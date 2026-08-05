// ==WindhawkMod==
// @id              tray-order-lock
// @name            Tray Order Lock
// @description     Prevents manual reordering of Windows 11 notification-area icons while enabled.
// @version         0.1.0
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

Prevents manual reordering of Windows 11 notification-area icons while the mod
is enabled.

Arrange the tray icons in the desired order before enabling the mod. Dragging an
icon to another position will then be rejected without changing the live order
or its persistent `UIOrderList` registry data.

Disabling the mod immediately restores normal tray icon dragging.

## Scope

Version 0.1.0:

- Blocks manual tray icon move requests.
- Does not modify or replace the existing saved tray order.
- Does not write to the registry.
- Does not interfere with applications adding or removing their tray icons.
- Targets 64-bit Windows 11 Explorer.

The implementation hooks the verified
`ITaskbarModel5::MoveNotificationAreaIcon` ABI boundary in `taskbar.dll` and
returns `S_OK` without forwarding move requests to the original function.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <windhawk_utils.h>

#include <atomic>

namespace {

std::atomic<bool> g_taskbarModuleHooked =
    false;

std::atomic<unsigned long long> g_blockedMoveCount =
    0;

using TaskbarModel_MoveNotificationAreaIcon_t =
    int(__cdecl*)(
        void* pThis,
        void* notificationAreaIconAbi,
        int location,
        unsigned int index
    );

TaskbarModel_MoveNotificationAreaIcon_t
    TaskbarModel_MoveNotificationAreaIcon_Original =
        nullptr;

int __cdecl
TaskbarModel_MoveNotificationAreaIcon_Hook(
    void* pThis,
    void* notificationAreaIconAbi,
    int location,
    unsigned int index
) {
    static_cast<void>(
        pThis
    );

    static_cast<void>(
        notificationAreaIconAbi
    );

    static_cast<void>(
        location
    );

    static_cast<void>(
        index
    );

    g_blockedMoveCount.fetch_add(
        1,
        std::memory_order_relaxed
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
        MAX_PATH
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
            L"taskbar.dll module=%p; "
            L"path unavailable",
            module
        );

        return;
    }

    Wh_Log(
        L"taskbar.dll module=%p; "
        L"path=\"%s\"",
        module,
        modulePath
    );
}

bool HookTaskbarSymbols(
    HMODULE module
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
            module,
            symbolHooks,
            ARRAYSIZE(
                symbolHooks
            )
        )
    ) {
        Wh_Log(
            L"Failed to locate or hook "
            L"ITaskbarModel5::"
            L"MoveNotificationAreaIcon"
        );

        return false;
    }

    LogTaskbarModuleInformation(
        module
    );

    Wh_Log(
        L"Tray icon move lock installed"
    );

    return true;
}

HMODULE GetTaskbarModuleHandle() {
    return
        GetModuleHandleW(
            L"taskbar.dll"
        );
}

bool TryHookTaskbarModule(
    HMODULE module,
    bool applyHookOperations
) {
    if (
        !module
    ) {
        return false;
    }

    if (
        g_taskbarModuleHooked.load(
            std::memory_order_acquire
        )
    ) {
        return true;
    }

    bool expected =
        false;

    if (
        !g_taskbarModuleHooked
             .compare_exchange_strong(
                 expected,
                 true,
                 std::memory_order_acq_rel
             )
    ) {
        return true;
    }

    if (
        !HookTaskbarSymbols(
            module
        )
    ) {
        g_taskbarModuleHooked.store(
            false,
            std::memory_order_release
        );

        return false;
    }

    if (
        applyHookOperations
    ) {
        Wh_ApplyHookOperations();
    }

    return true;
}

void HandleLoadedModule(
    HMODULE module,
    LPCWSTR requestedPath
) {
    if (
        !module ||
        g_taskbarModuleHooked.load(
            std::memory_order_acquire
        )
    ) {
        return;
    }

    HMODULE taskbarModule =
        GetTaskbarModuleHandle();

    if (
        !taskbarModule ||
        taskbarModule !=
            module
    ) {
        return;
    }

    Wh_Log(
        L"Detected taskbar.dll load; "
        L"requestedPath=\"%s\"",
        requestedPath
            ? requestedPath
            : L"<null>"
    );

    TryHookTaskbarModule(
        module,
        true
    );
}

using LoadLibraryExW_t =
    decltype(
        &LoadLibraryExW
    );

LoadLibraryExW_t LoadLibraryExW_Original =
    nullptr;

HMODULE WINAPI LoadLibraryExW_Hook(
    LPCWSTR libraryPath,
    HANDLE file,
    DWORD flags
) {
    HMODULE module =
        LoadLibraryExW_Original(
            libraryPath,
            file,
            flags
        );

    if (
        module
    ) {
        HandleLoadedModule(
            module,
            libraryPath
        );
    }

    return module;
}

bool HookModuleLoader() {
    HMODULE kernelBase =
        GetModuleHandleW(
            L"kernelbase.dll"
        );

    if (
        !kernelBase
    ) {
        Wh_Log(
            L"kernelbase.dll is unavailable"
        );

        return false;
    }

    auto loadLibraryExW =
        reinterpret_cast<
            LoadLibraryExW_t
        >(
            GetProcAddress(
                kernelBase,
                "LoadLibraryExW"
            )
        );

    if (
        !loadLibraryExW
    ) {
        Wh_Log(
            L"LoadLibraryExW is unavailable"
        );

        return false;
    }

    if (
        !WindhawkUtils::
            Wh_SetFunctionHookT(
                loadLibraryExW,
                LoadLibraryExW_Hook,
                &LoadLibraryExW_Original
            )
    ) {
        Wh_Log(
            L"Failed to hook LoadLibraryExW"
        );

        return false;
    }

    Wh_Log(
        L"taskbar.dll is not loaded yet; "
        L"waiting for module load"
    );

    return true;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Order Lock 0.1.0 initializing"
    );

    g_taskbarModuleHooked.store(
        false,
        std::memory_order_release
    );

    g_blockedMoveCount.store(
        0,
        std::memory_order_release
    );

    HMODULE taskbarModule =
        GetTaskbarModuleHandle();

    if (
        taskbarModule
    ) {
        return
            TryHookTaskbarModule(
                taskbarModule,
                false
            )
                ? TRUE
                : FALSE;
    }

    return
        HookModuleLoader()
            ? TRUE
            : FALSE;
}

void Wh_ModAfterInit() {
    if (
        g_taskbarModuleHooked.load(
            std::memory_order_acquire
        )
    ) {
        return;
    }

    HMODULE taskbarModule =
        GetTaskbarModuleHandle();

    if (
        taskbarModule
    ) {
        TryHookTaskbarModule(
            taskbarModule,
            true
        );
    }
}

void Wh_ModUninit() {
    Wh_Log(
        L"Tray Order Lock stopped; "
        L"blockedMoves=%llu",
        g_blockedMoveCount.load(
            std::memory_order_relaxed
        )
    );
}
