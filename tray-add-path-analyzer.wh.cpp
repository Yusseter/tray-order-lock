// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Correlates newly added tray icon objects with manual move arguments.
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
# Tray Add Path Analyzer

A temporary diagnostic mod.

Version 0.2.0 correlates:

- `NotificationAreaIconManager2::AddIcon`
- `NotificationAreaIconManager2::AddIconToVisibleCollection`
- ABI-facing `ITaskbarModel5::MoveNotificationAreaIcon`
- `NotificationAreaIconManager2::MoveIcon`

The goal is to determine how the live `NotificationAreaIcon2` implementation
pointer relates to the ABI/projected icon value used by the normal move path.

All original functions are called normally. The mod does not block, create,
remove or move tray icons and does not write to the registry.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <windhawk_utils.h>

#include <atomic>
#include <cstring>

namespace {

using NotificationAreaIconManager_AddIcon_t =
    void(__cdecl*)(
        void* pThis,
        void* trayNotifyData
    );

using NotificationAreaIconManager_AddVisible_t =
    void(__cdecl*)(
        void* pThis,
        void* iconImplementation
    );

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

NotificationAreaIconManager_AddIcon_t
    NotificationAreaIconManager_AddIcon_Original =
        nullptr;

NotificationAreaIconManager_AddVisible_t
    NotificationAreaIconManager_AddVisible_Original =
        nullptr;

TaskbarModel_MoveNotificationAreaIcon_t
    TaskbarModel_MoveNotificationAreaIcon_Original =
        nullptr;

NotificationAreaIconManager_MoveIcon_t
    NotificationAreaIconManager_MoveIcon_Original =
        nullptr;

std::atomic<unsigned long long> g_addIconCalls =
    0;

std::atomic<unsigned long long> g_visibleAddCalls =
    0;

std::atomic<unsigned long long> g_taskbarMoveCalls =
    0;

std::atomic<unsigned long long> g_managerMoveCalls =
    0;

thread_local unsigned int g_addIconDepth =
    0;

thread_local unsigned long long g_activeAddIconCall =
    0;

thread_local unsigned long long g_activeTaskbarMoveCall =
    0;

std::atomic<void*> g_latestVisibleImplementation =
    nullptr;

std::atomic<unsigned long long> g_latestVisibleCall =
    0;

void* ReadFirstPointer(
    void* address
) {
    if (!address) {
        return nullptr;
    }

    void* value =
        nullptr;

    std::memcpy(
        &value,
        address,
        sizeof(value)
    );

    return value;
}

void __cdecl NotificationAreaIconManager_AddIcon_Hook(
    void* pThis,
    void* trayNotifyData
) {
    const unsigned long long callNumber =
        g_addIconCalls.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    const unsigned long long previousActiveCall =
        g_activeAddIconCall;

    g_activeAddIconCall =
        callNumber;

    g_addIconDepth++;

    Wh_Log(
        L"ADD_ICON_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"trayNotifyData=%p "
        L"depth=%u",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        trayNotifyData,
        g_addIconDepth
    );

    NotificationAreaIconManager_AddIcon_Original(
        pThis,
        trayNotifyData
    );

    Wh_Log(
        L"ADD_ICON_END "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"depth=%u",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        g_addIconDepth
    );

    g_addIconDepth--;

    g_activeAddIconCall =
        previousActiveCall;
}

void __cdecl
NotificationAreaIconManager_AddVisible_Hook(
    void* pThis,
    void* iconImplementation
) {
    const unsigned long long callNumber =
        g_visibleAddCalls.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    const void* firstPointer =
        ReadFirstPointer(
            iconImplementation
        );

    Wh_Log(
        L"VISIBLE_ADD_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"implementation=%p "
        L"implementationFirstPointer=%p "
        L"duringAddIcon=%d "
        L"parentAddCall=%llu",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        iconImplementation,
        firstPointer,
        g_addIconDepth != 0
            ? 1
            : 0,
        g_activeAddIconCall
    );

    NotificationAreaIconManager_AddVisible_Original(
        pThis,
        iconImplementation
    );

    g_latestVisibleImplementation.store(
        iconImplementation,
        std::memory_order_release
    );

    g_latestVisibleCall.store(
        callNumber,
        std::memory_order_release
    );

    Wh_Log(
        L"VISIBLE_ADD_END "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"implementation=%p "
        L"parentAddCall=%llu",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        iconImplementation,
        g_activeAddIconCall
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

    const unsigned long long previousActiveCall =
        g_activeTaskbarMoveCall;

    g_activeTaskbarMoveCall =
        callNumber;

    const void* abiFirstPointer =
        ReadFirstPointer(
            notificationAreaIconAbi
        );

    Wh_Log(
        L"TASKBAR_MOVE_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"taskbarModel=%p "
        L"iconAbi=%p "
        L"iconAbiFirstPointer=%p "
        L"location=%d "
        L"index=%u "
        L"latestImplementation=%p "
        L"latestVisibleCall=%llu",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        notificationAreaIconAbi,
        abiFirstPointer,
        location,
        index,
        g_latestVisibleImplementation.load(
            std::memory_order_acquire
        ),
        g_latestVisibleCall.load(
            std::memory_order_acquire
        )
    );

    const int result =
        TaskbarModel_MoveNotificationAreaIcon_Original(
            pThis,
            notificationAreaIconAbi,
            location,
            index
        );

    Wh_Log(
        L"TASKBAR_MOVE_END "
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
        previousActiveCall;

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

    const void* containedPointer =
        ReadFirstPointer(
            iconArgumentStorage
        );

    Wh_Log(
        L"MANAGER_MOVE_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"iconArgumentStorage=%p "
        L"containedPointer=%p "
        L"location=%d "
        L"index=%u "
        L"parentTaskbarMove=%llu "
        L"latestImplementation=%p "
        L"latestVisibleCall=%llu",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        iconArgumentStorage,
        containedPointer,
        location,
        index,
        g_activeTaskbarMoveCall,
        g_latestVisibleImplementation.load(
            std::memory_order_acquire
        ),
        g_latestVisibleCall.load(
            std::memory_order_acquire
        )
    );

    NotificationAreaIconManager_MoveIcon_Original(
        pThis,
        iconArgumentStorage,
        location,
        index
    );

    Wh_Log(
        L"MANAGER_MOVE_END "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"parentTaskbarMove=%llu",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        g_activeTaskbarMoveCall
    );
}

bool HookTaskbarSymbols(
    HMODULE module
) {
    WindhawkUtils::SYMBOL_HOOK symbolHooks[] = {
        {
            {
                LR"(private: void __cdecl NotificationAreaIconManager2::AddIcon(struct _TRAYNOTIFYDATAW * const))"
            },
            &NotificationAreaIconManager_AddIcon_Original,
            NotificationAreaIconManager_AddIcon_Hook,
        },
        {
            {
                LR"(private: void __cdecl NotificationAreaIconManager2::AddIconToVisibleCollection(struct winrt::WindowsUdk::UI::Shell::implementation::NotificationAreaIcon2 *))"
            },
            &NotificationAreaIconManager_AddVisible_Original,
            NotificationAreaIconManager_AddVisible_Hook,
        },
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
            module,
            symbolHooks,
            ARRAYSIZE(
                symbolHooks
            )
        )
    ) {
        Wh_Log(
            L"Failed to hook one or more taskbar.dll symbols"
        );

        return false;
    }

    Wh_Log(
        L"Tray add/move correlation hooks installed"
    );

    return true;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Add Path Analyzer "
        L"0.2.0 initializing"
    );

    HMODULE taskbarModule =
        GetModuleHandleW(
            L"taskbar.dll"
        );

    if (!taskbarModule) {
        Wh_Log(
            L"taskbar.dll is not loaded"
        );

        return FALSE;
    }

    wchar_t modulePath[
        32768
    ]{};

    GetModuleFileNameW(
        taskbarModule,
        modulePath,
        ARRAYSIZE(
            modulePath
        )
    );

    Wh_Log(
        L"TASKBAR_MODULE "
        L"address=%p "
        L"path=\"%s\"",
        taskbarModule,
        modulePath
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
        L"addIconCalls=%llu "
        L"visibleAddCalls=%llu "
        L"taskbarMoveCalls=%llu "
        L"managerMoveCalls=%llu",
        g_addIconCalls.load(
            std::memory_order_relaxed
        ),
        g_visibleAddCalls.load(
            std::memory_order_relaxed
        ),
        g_taskbarMoveCalls.load(
            std::memory_order_relaxed
        ),
        g_managerMoveCalls.load(
            std::memory_order_relaxed
        )
    );
}
