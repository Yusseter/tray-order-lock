// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Records a move-path experiment whose alternate-path premise was later found to be invalid.
// @version         0.30.0
// @author          Yusseter
// @github          https://github.com/Yusseter
// @homepage        https://github.com/Yusseter/tray-order-lock
// @license         MIT
// @include         explorer.exe
// @architecture    x86-64
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# Tray Add Path Analyzer

Version 0.30.0 preserves a move-path experiment which was started from an
incorrect interpretation of the manual test procedure.

The original research question assumed that there was a distinct tray
"context-menu Move icon" operation which might bypass
ITaskbarModel5::MoveNotificationAreaIcon and call
NotificationAreaIconManager2::MoveIcon through another path.

That premise was incorrect.

During the actual runtime test, the user right-clicked the Discord tray icon
and then manually dragged it one position to the left. The only real move was
therefore an ordinary tray drag.

The observed call chain was:

    ITaskbarModel5::MoveNotificationAreaIcon
        -> NotificationAreaIconManager2::MoveIcon

The manager call had:

    parentTaskbarMove=1

and the final counters were:

    taskbarMoveCalls=1
    managerMoveCalls=1
    managerMovesWithoutTaskbarParent=0

This result reconfirms the already-known normal drag path. It does NOT prove
that a separate alternate move path exists, nor does it prove that one does
not exist.

The version is retained intentionally as a research-history checkpoint so that
the invalid alternate-path premise and its correction remain documented.

The analyzer:

- Does not block any move.
- Calls all original functions normally.
- Does not create or remove tray icons.
- Does not write to the registry itself.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <windhawk_utils.h>

#include <atomic>
#include <cstdint>

namespace {

using TaskbarModel_MoveNotificationAreaIcon_t =
    int(__cdecl*)(
        void* pThis,
        void* notificationAreaIconAbi,
        int location,
        unsigned int index
    );

using NotificationAreaIconManager_MoveIcon_t =
    void(__cdecl*)(
        void* pThis,
        void* iconArgumentStorage,
        int location,
        unsigned int index
    );

TaskbarModel_MoveNotificationAreaIcon_t
    TaskbarModel_MoveNotificationAreaIcon_Original =
        nullptr;

NotificationAreaIconManager_MoveIcon_t
    NotificationAreaIconManager_MoveIcon_Original =
        nullptr;

std::atomic<unsigned long long> g_taskbarMoveCalls =
    0;

std::atomic<unsigned long long> g_managerMoveCalls =
    0;

std::atomic<unsigned long long> g_managerMovesWithoutTaskbarParent =
    0;

thread_local unsigned long long g_activeTaskbarMoveCall =
    0;

void LogModuleInformation(
    const wchar_t* prefix,
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
            L"%s address=%p path=\"<unavailable>\"",
            prefix,
            module
        );

        return;
    }

    Wh_Log(
        L"%s address=%p path=\"%s\"",
        prefix,
        module,
        modulePath
    );
}

void LogStackFrame(
    unsigned long long managerMoveCall,
    unsigned int frameNumber,
    void* address
) {
    HMODULE module =
        nullptr;

    if (
        !GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(
                address
            ),
            &module
        ) ||
        !module
    ) {
        Wh_Log(
            L"ALTERNATE_MOVE_STACK "
            L"managerMove=%llu "
            L"frame=%u "
            L"address=%p "
            L"module=\"<unknown>\" "
            L"offset=0",
            managerMoveCall,
            frameNumber,
            address
        );

        return;
    }

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

    const std::uintptr_t addressValue =
        reinterpret_cast<std::uintptr_t>(
            address
        );

    const std::uintptr_t moduleValue =
        reinterpret_cast<std::uintptr_t>(
            module
        );

    const unsigned long long offset =
        addressValue >= moduleValue
            ? static_cast<unsigned long long>(
                  addressValue -
                  moduleValue
              )
            : 0;

    Wh_Log(
        L"ALTERNATE_MOVE_STACK "
        L"managerMove=%llu "
        L"frame=%u "
        L"address=%p "
        L"moduleBase=%p "
        L"offset=0x%llX "
        L"module=\"%s\"",
        managerMoveCall,
        frameNumber,
        address,
        module,
        offset,
        (
            length != 0 &&
            length <
                ARRAYSIZE(
                    modulePath
                )
        )
            ? modulePath
            : L"<unavailable>"
    );
}

void LogAlternateMoveStack(
    unsigned long long managerMoveCall
) {
    constexpr ULONG kMaximumFrames =
        16;

    void* frames[
        kMaximumFrames
    ]{};

    const USHORT captured =
        CaptureStackBackTrace(
            1,
            kMaximumFrames,
            frames,
            nullptr
        );

    Wh_Log(
        L"ALTERNATE_MOVE_STACK_BEGIN "
        L"managerMove=%llu "
        L"capturedFrames=%u",
        managerMoveCall,
        static_cast<unsigned int>(
            captured
        )
    );

    for (
        USHORT index = 0;
        index < captured;
        index++
    ) {
        LogStackFrame(
            managerMoveCall,
            static_cast<unsigned int>(
                index
            ),
            frames[index]
        );
    }

    Wh_Log(
        L"ALTERNATE_MOVE_STACK_END "
        L"managerMove=%llu",
        managerMoveCall
    );
}

int __cdecl
TaskbarModel_MoveNotificationAreaIcon_Hook(
    void* pThis,
    void* notificationAreaIconAbi,
    int location,
    unsigned int index
) {
    const unsigned long long callNumber =
        g_taskbarMoveCalls.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    const unsigned long long previousParent =
        g_activeTaskbarMoveCall;

    g_activeTaskbarMoveCall =
        callNumber;

    Wh_Log(
        L"MOVE_PATH_TASKBAR_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"taskbarModel=%p "
        L"iconAbi=%p "
        L"location=%d "
        L"index=%u",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        notificationAreaIconAbi,
        location,
        index
    );

    const int result =
        TaskbarModel_MoveNotificationAreaIcon_Original(
            pThis,
            notificationAreaIconAbi,
            location,
            index
        );

    Wh_Log(
        L"MOVE_PATH_TASKBAR_END "
        L"call=%llu "
        L"thread=%lu "
        L"result=0x%08X",
        callNumber,
        GetCurrentThreadId(),
        static_cast<unsigned int>(
            result
        )
    );

    g_activeTaskbarMoveCall =
        previousParent;

    return result;
}

void __cdecl
NotificationAreaIconManager_MoveIcon_Hook(
    void* pThis,
    void* iconArgumentStorage,
    int location,
    unsigned int index
) {
    const unsigned long long callNumber =
        g_managerMoveCalls.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    void* containedPointer =
        nullptr;

    if (iconArgumentStorage) {
        containedPointer =
            *reinterpret_cast<void**>(
                iconArgumentStorage
            );
    }

    const unsigned long long parentTaskbarMove =
        g_activeTaskbarMoveCall;

    Wh_Log(
        L"MOVE_PATH_MANAGER_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"iconArgumentStorage=%p "
        L"containedPointer=%p "
        L"location=%d "
        L"index=%u "
        L"parentTaskbarMove=%llu",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        iconArgumentStorage,
        containedPointer,
        location,
        index,
        parentTaskbarMove
    );

    if (parentTaskbarMove == 0) {
        const unsigned long long alternateNumber =
            g_managerMovesWithoutTaskbarParent.fetch_add(
                1,
                std::memory_order_relaxed
            ) +
            1;

        Wh_Log(
            L"ALTERNATE_MOVE_PATH_OBSERVED "
            L"alternate=%llu "
            L"managerMove=%llu "
            L"thread=%lu "
            L"location=%d "
            L"index=%u",
            alternateNumber,
            callNumber,
            GetCurrentThreadId(),
            location,
            index
        );

        LogAlternateMoveStack(
            callNumber
        );
    }

    NotificationAreaIconManager_MoveIcon_Original(
        pThis,
        iconArgumentStorage,
        location,
        index
    );

    Wh_Log(
        L"MOVE_PATH_MANAGER_END "
        L"call=%llu "
        L"thread=%lu "
        L"parentTaskbarMove=%llu",
        callNumber,
        GetCurrentThreadId(),
        parentTaskbarMove
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
            {
                {
                    LR"(public: void __cdecl NotificationAreaIconManager2::MoveIcon(struct winrt::WindowsUdk::UI::Shell::NotificationAreaIcon,enum winrt::WindowsUdk::UI::Shell::NotificationAreaIconLocation,unsigned int))"
                },
                &NotificationAreaIconManager_MoveIcon_Original,
                NotificationAreaIconManager_MoveIcon_Hook,
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
            L"MOVE_PATH_HOOK_REGISTRATION_FAILED"
        );

        return false;
    }

    Wh_Log(
        L"MOVE_PATH_HOOKS_REGISTERED "
        L"taskbarModule=%p",
        taskbarModule
    );

    return true;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Add Path Analyzer 0.30.0 initializing "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    HMODULE taskbarModule =
        GetModuleHandleW(
            L"taskbar.dll"
        );

    if (!taskbarModule) {
        Wh_Log(
            L"MOVE_PATH_TASKBAR_DLL_NOT_READY "
            L"processId=%lu",
            GetCurrentProcessId()
        );

        return FALSE;
    }

    LogModuleInformation(
        L"MOVE_PATH_TASKBAR_MODULE",
        taskbarModule
    );

    return
        HookTaskbarSymbols(
            taskbarModule
        )
            ? TRUE
            : FALSE;
}

void Wh_ModUninit() {
    Wh_Log(
        L"Tray Add Path Analyzer stopped; "
        L"processId=%lu "
        L"taskbarMoveCalls=%llu "
        L"managerMoveCalls=%llu "
        L"managerMovesWithoutTaskbarParent=%llu",
        GetCurrentProcessId(),
        g_taskbarMoveCalls.load(
            std::memory_order_relaxed
        ),
        g_managerMoveCalls.load(
            std::memory_order_relaxed
        ),
        g_managerMovesWithoutTaskbarParent.load(
            std::memory_order_relaxed
        )
    );
}
