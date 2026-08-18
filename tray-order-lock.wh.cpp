// ==WindhawkMod==
// @id              tray-order-lock
// @name            Tray Order Lock
// @description     Controls Windows 11 notification-area icon reordering.
// @version         0.2.0
// @author          Yusseter
// @github          https://github.com/Yusseter
// @homepage        https://github.com/Yusseter/tray-order-lock
// @license         MIT
// @include         explorer.exe
// @architecture    x86-64
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# Tray Order Lock

Controls reordering of Windows 11 notification-area icons.

The 0.2.0 development line starts by preserving the existing
"lock all reordering" behavior while moving taskbar initialization to the
Explorer-restart-safe bootstrap validated by the tray-order research tools.

At this stage:

- Manual tray icon move requests are still blocked.
- Existing tray order is not modified.
- No UIOrderList registry values are written.
- Application icon creation and removal are not changed.
- Taskbar hooks initialize correctly whether Shell_TrayWnd already exists or
  is created after the mod is injected into Explorer.

The later 0.2.0 implementation will build the persistent order-preservation
behavior on top of this initialization path.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <windhawk_utils.h>

#include <atomic>

namespace {

using TaskbarModel_MoveNotificationAreaIcon_t =
    int(__cdecl*)(
        void* pThis,
        void* notificationAreaIconAbi,
        int location,
        unsigned int index
    );

using CreateWindowExW_t =
    decltype(&CreateWindowExW);

TaskbarModel_MoveNotificationAreaIcon_t
    TaskbarModel_MoveNotificationAreaIcon_Original =
        nullptr;

CreateWindowExW_t
    CreateWindowExW_Original =
        nullptr;

std::atomic<bool> g_taskbarHooksInitializing =
    false;

std::atomic<bool> g_taskbarHooksInitialized =
    false;

std::atomic<unsigned long long> g_blockedMoveCount =
    0;

int __cdecl
TaskbarModel_MoveNotificationAreaIcon_Hook(
    void* pThis,
    void* notificationAreaIconAbi,
    int location,
    unsigned int index
) {
    static_cast<void>(pThis);

    const unsigned long long moveNumber =
        g_blockedMoveCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    Wh_Log(
        L"TRAY_ORDER_LOCK_MOVE_BLOCKED "
        L"move=%llu "
        L"iconAbi=%p "
        L"location=%d "
        L"index=%u",
        moveNumber,
        notificationAreaIconAbi,
        location,
        index
    );

    return
        static_cast<int>(
            S_OK
        );
}

void LogTaskbarModuleInformation(
    HMODULE module
) {
    wchar_t modulePath[
        32768
    ]{};

    const DWORD length =
        GetModuleFileNameW(
            module,
            modulePath,
            ARRAYSIZE(
                modulePath
            )
        );

    if (
        length == 0 ||
        length >=
            ARRAYSIZE(
                modulePath
            )
    ) {
        Wh_Log(
            L"TRAY_ORDER_LOCK_TASKBAR_MODULE "
            L"address=%p "
            L"path=\"<unavailable>\"",
            module
        );

        return;
    }

    Wh_Log(
        L"TRAY_ORDER_LOCK_TASKBAR_MODULE "
        L"address=%p "
        L"path=\"%s\"",
        module,
        modulePath
    );
}

bool HookTaskbarSymbols(
    HMODULE taskbarModule
) {
    WindhawkUtils::SYMBOL_HOOK
        symbolHooks[] = {
            {
                {
                    LR"(public: virtual int __cdecl winrt::impl::produce<struct winrt::WindowsUdk::UI::Shell::implementation::TaskbarModel,struct winrt::WindowsUdk::UI::Shell::ITaskbarModel5>::MoveNotificationAreaIcon(void *,int,unsigned int))"
                },
                &TaskbarModel_MoveNotificationAreaIcon_Original,
                TaskbarModel_MoveNotificationAreaIcon_Hook,
            },
        };

    if (
        !WindhawkUtils::HookSymbols(
            taskbarModule,
            symbolHooks,
            ARRAYSIZE(
                symbolHooks
            )
        )
    ) {
        Wh_Log(
            L"TRAY_ORDER_LOCK_TASKBAR_HOOK_REGISTRATION_FAILED"
        );

        return false;
    }

    LogTaskbarModuleInformation(
        taskbarModule
    );

    return true;
}

BOOL CALLBACK
EnumCurrentProcessTaskbarWindowProc(
    HWND hWnd,
    LPARAM lParam
) {
    DWORD processId =
        0;

    if (
        !GetWindowThreadProcessId(
            hWnd,
            &processId
        ) ||
        processId !=
            GetCurrentProcessId()
    ) {
        return TRUE;
    }

    wchar_t className[
        64
    ]{};

    if (
        GetClassNameW(
            hWnd,
            className,
            ARRAYSIZE(
                className
            )
        ) ==
        0
    ) {
        return TRUE;
    }

    if (
        _wcsicmp(
            className,
            L"Shell_TrayWnd"
        ) !=
        0
    ) {
        return TRUE;
    }

    *reinterpret_cast<HWND*>(
        lParam
    ) =
        hWnd;

    return FALSE;
}

HWND FindCurrentProcessTaskbarWindow() {
    HWND result =
        nullptr;

    EnumWindows(
        EnumCurrentProcessTaskbarWindowProc,
        reinterpret_cast<LPARAM>(
            &result
        )
    );

    return result;
}

void LogReady() {
    Wh_Log(
        L"TRAY_ORDER_LOCK_READY "
        L"processId=%lu "
        L"taskbarHooksInitialized=%d "
        L"blockedMoves=%llu",
        GetCurrentProcessId(),
        g_taskbarHooksInitialized.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_blockedMoveCount.load(
            std::memory_order_acquire
        )
    );
}

bool TryInitializeTaskbarHooks(
    bool applyImmediately
) {
    if (
        g_taskbarHooksInitialized.load(
            std::memory_order_acquire
        )
    ) {
        return true;
    }

    bool expected =
        false;

    if (
        !g_taskbarHooksInitializing
             .compare_exchange_strong(
                 expected,
                 true,
                 std::memory_order_acq_rel
             )
    ) {
        return false;
    }

    HMODULE taskbarModule =
        GetModuleHandleW(
            L"taskbar.dll"
        );

    if (!taskbarModule) {
        Wh_Log(
            L"TRAY_ORDER_LOCK_TASKBAR_DLL_NOT_READY "
            L"processId=%lu",
            GetCurrentProcessId()
        );

        g_taskbarHooksInitializing.store(
            false,
            std::memory_order_release
        );

        return false;
    }

    if (
        !HookTaskbarSymbols(
            taskbarModule
        )
    ) {
        g_taskbarHooksInitializing.store(
            false,
            std::memory_order_release
        );

        return false;
    }

    if (applyImmediately) {
        if (
            !Wh_ApplyHookOperations()
        ) {
            Wh_Log(
                L"TRAY_ORDER_LOCK_TASKBAR_HOOK_APPLY_FAILED "
                L"processId=%lu",
                GetCurrentProcessId()
            );

            g_taskbarHooksInitializing.store(
                false,
                std::memory_order_release
            );

            return false;
        }
    }

    g_taskbarHooksInitialized.store(
        true,
        std::memory_order_release
    );

    g_taskbarHooksInitializing.store(
        false,
        std::memory_order_release
    );

    if (applyImmediately) {
        Wh_Log(
            L"TRAY_ORDER_LOCK_TASKBAR_HOOKS_READY "
            L"processId=%lu "
            L"applyImmediately=1",
            GetCurrentProcessId()
        );
    } else {
        Wh_Log(
            L"TRAY_ORDER_LOCK_TASKBAR_HOOKS_REGISTERED "
            L"processId=%lu "
            L"applyImmediately=0",
            GetCurrentProcessId()
        );
    }

    return true;
}

HWND WINAPI CreateWindowExW_Hook(
    DWORD dwExStyle,
    LPCWSTR lpClassName,
    LPCWSTR lpWindowName,
    DWORD dwStyle,
    int X,
    int Y,
    int nWidth,
    int nHeight,
    HWND hWndParent,
    HMENU hMenu,
    HINSTANCE hInstance,
    LPVOID lpParam
) {
    HWND hWnd =
        CreateWindowExW_Original(
            dwExStyle,
            lpClassName,
            lpWindowName,
            dwStyle,
            X,
            Y,
            nWidth,
            nHeight,
            hWndParent,
            hMenu,
            hInstance,
            lpParam
        );

    if (
        !hWnd ||
        !lpClassName ||
        IS_INTRESOURCE(
            lpClassName
        ) ||
        _wcsicmp(
            lpClassName,
            L"Shell_TrayWnd"
        ) !=
            0
    ) {
        return hWnd;
    }

    DWORD processId =
        0;

    GetWindowThreadProcessId(
        hWnd,
        &processId
    );

    if (
        processId !=
        GetCurrentProcessId()
    ) {
        return hWnd;
    }

    Wh_Log(
        L"TRAY_ORDER_LOCK_SHELL_WINDOW_CREATED "
        L"processId=%lu "
        L"hWnd=%p",
        processId,
        hWnd
    );

    if (
        !g_taskbarHooksInitialized.load(
            std::memory_order_acquire
        )
    ) {
        if (
            TryInitializeTaskbarHooks(
                true
            )
        ) {
            LogReady();
        }
    }

    return hWnd;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Order Lock 0.2.0 initializing "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    g_taskbarHooksInitializing.store(
        false,
        std::memory_order_release
    );

    g_taskbarHooksInitialized.store(
        false,
        std::memory_order_release
    );

    g_blockedMoveCount.store(
        0,
        std::memory_order_release
    );

    if (
        !WindhawkUtils::SetFunctionHook(
            CreateWindowExW,
            CreateWindowExW_Hook,
            &CreateWindowExW_Original
        )
    ) {
        Wh_Log(
            L"TRAY_ORDER_LOCK_CREATEWINDOW_HOOK_FAILED "
            L"processId=%lu",
            GetCurrentProcessId()
        );

        return FALSE;
    }

    HWND existingTaskbarWindow =
        FindCurrentProcessTaskbarWindow();

    if (existingTaskbarWindow) {
        Wh_Log(
            L"TRAY_ORDER_LOCK_EXISTING_PRIMARY_SHELL "
            L"processId=%lu "
            L"hWnd=%p",
            GetCurrentProcessId(),
            existingTaskbarWindow
        );

        if (
            !TryInitializeTaskbarHooks(
                false
            )
        ) {
            return FALSE;
        }
    } else {
        Wh_Log(
            L"TRAY_ORDER_LOCK_TASKBAR_HOOKS_DEFERRED "
            L"processId=%lu "
            L"reason=\"Shell_TrayWnd-not-created-yet\"",
            GetCurrentProcessId()
        );
    }

    Wh_Log(
        L"TRAY_ORDER_LOCK_BOOTSTRAP_READY "
        L"processId=%lu "
        L"taskbarHooksInitialized=%d",
        GetCurrentProcessId(),
        g_taskbarHooksInitialized.load(
            std::memory_order_acquire
        )
            ? 1
            : 0
    );

    return TRUE;
}

void Wh_ModAfterInit() {
    if (
        !g_taskbarHooksInitialized.load(
            std::memory_order_acquire
        )
    ) {
        HWND taskbarWindow =
            FindCurrentProcessTaskbarWindow();

        if (taskbarWindow) {
            TryInitializeTaskbarHooks(
                true
            );
        }
    }

    if (
        g_taskbarHooksInitialized.load(
            std::memory_order_acquire
        )
    ) {
        LogReady();
    }
}

void Wh_ModUninit() {
    Wh_Log(
        L"Tray Order Lock stopped; "
        L"processId=%lu "
        L"blockedMoves=%llu "
        L"taskbarHooksInitialized=%d",
        GetCurrentProcessId(),
        g_blockedMoveCount.load(
            std::memory_order_relaxed
        ),
        g_taskbarHooksInitialized.load(
            std::memory_order_relaxed
        )
            ? 1
            : 0
    );
}
