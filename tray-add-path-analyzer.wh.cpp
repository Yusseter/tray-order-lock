// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Validates safe conversion from live tray icon objects to ABI icon pointers.
// @version         0.3.0
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

Version 0.3.0 validates a safe conversion from a live
`NotificationAreaIcon2` implementation object to the
`INotificationAreaIcon` ABI pointer used by
`ITaskbarModel5::MoveNotificationAreaIcon`.

The mod resolves these public Microsoft symbols:

- The internal `root_implements::query_interface` method for
  `NotificationAreaIcon2`
- The IID data symbol for `INotificationAreaIcon`

It compares the queried ABI pointer with the pointer received by the normal
manual move path.

All original functions are called normally. The mod does not create, remove,
block or move tray icons and does not write to the registry.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <unknwn.h>
#include <windhawk_utils.h>

#include <atomic>
#include <cwchar>

namespace {

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

using NotificationAreaIcon_QueryInterface_t =
    int(__cdecl*)(
        void* iconImplementation,
        const GUID& interfaceId,
        void** result
    );

NotificationAreaIconManager_AddVisible_t
    NotificationAreaIconManager_AddVisible_Original =
        nullptr;

TaskbarModel_MoveNotificationAreaIcon_t
    TaskbarModel_MoveNotificationAreaIcon_Original =
        nullptr;

NotificationAreaIcon_QueryInterface_t
    NotificationAreaIcon_QueryInterface =
        nullptr;

const GUID* g_notificationAreaIconInterfaceId =
    nullptr;

std::atomic<unsigned long long> g_visibleAddCallCount =
    0;

std::atomic<unsigned long long> g_moveCallCount =
    0;

std::atomic<unsigned long long> g_queryCallCount =
    0;

std::atomic<void*> g_latestImplementation =
    nullptr;

std::atomic<void*> g_latestQueriedAbi =
    nullptr;

std::atomic<unsigned long long> g_latestQueryCall =
    0;

bool ContainsText(
    const wchar_t* text,
    const wchar_t* expected
) {
    return
        text &&
        expected &&
        std::wcsstr(
            text,
            expected
        ) !=
        nullptr;
}

bool IsNotificationAreaIconQueryInterfaceSymbol(
    const wchar_t* symbol
) {
    return
        ContainsText(
            symbol,
            L"root_implements<"
        ) &&
        ContainsText(
            symbol,
            L"NotificationAreaIcon2"
        ) &&
        ContainsText(
            symbol,
            L">::query_interface("
        ) &&
        ContainsText(
            symbol,
            L"winrt::guid const &"
        ) &&
        ContainsText(
            symbol,
            L"void * *"
        ) &&
        !ContainsText(
            symbol,
            L"query_interface_common"
        ) &&
        !ContainsText(
            symbol,
            L"query_interface_tearoff"
        );
}

bool IsNotificationAreaIconIidSymbol(
    const wchar_t* symbol
) {
    constexpr wchar_t kExpectedSymbol[] =
        L"struct guid::guid const "
        L"winrt::impl::guid_v<struct "
        L"winrt::WindowsUdk::UI::Shell::"
        L"INotificationAreaIcon>";

    return
        symbol &&
        std::wcscmp(
            symbol,
            kExpectedSymbol
        ) ==
        0;
}

bool ResolveQueryInterfaceSymbols(
    HMODULE taskbarModule
) {
    WH_FIND_SYMBOL_OPTIONS options{};

    options.optionsSize =
        sizeof(options);

    options.symbolServer =
        nullptr;

    options.noUndecoratedSymbols =
        FALSE;

    WH_FIND_SYMBOL symbol{};

    HANDLE symbolSearch =
        Wh_FindFirstSymbol(
            taskbarModule,
            &options,
            &symbol
        );

    if (!symbolSearch) {
        Wh_Log(
            L"Wh_FindFirstSymbol failed"
        );

        return false;
    }

    do {
        if (
            !NotificationAreaIcon_QueryInterface &&
            IsNotificationAreaIconQueryInterfaceSymbol(
                symbol.symbol
            )
        ) {
            NotificationAreaIcon_QueryInterface =
                reinterpret_cast<
                    NotificationAreaIcon_QueryInterface_t
                >(
                    symbol.address
                );

            Wh_Log(
                L"QUERY_INTERFACE_SYMBOL "
                L"address=%p "
                L"symbol=\"%s\"",
                symbol.address,
                symbol.symbol
            );
        }

        if (
            !g_notificationAreaIconInterfaceId &&
            IsNotificationAreaIconIidSymbol(
                symbol.symbol
            )
        ) {
            g_notificationAreaIconInterfaceId =
                reinterpret_cast<
                    const GUID*
                >(
                    symbol.address
                );

            Wh_Log(
                L"INTERFACE_ID_SYMBOL "
                L"address=%p "
                L"symbol=\"%s\"",
                symbol.address,
                symbol.symbol
            );
        }

        if (
            NotificationAreaIcon_QueryInterface &&
            g_notificationAreaIconInterfaceId
        ) {
            break;
        }
    } while (
        Wh_FindNextSymbol(
            symbolSearch,
            &symbol
        )
    );

    Wh_FindCloseSymbol(
        symbolSearch
    );

    if (!NotificationAreaIcon_QueryInterface) {
        Wh_Log(
            L"NotificationAreaIcon2 "
            L"query_interface symbol not found"
        );

        return false;
    }

    if (!g_notificationAreaIconInterfaceId) {
        Wh_Log(
            L"INotificationAreaIcon IID symbol not found"
        );

        return false;
    }

    Wh_Log(
        L"QUERY_INTERFACE_SUPPORT_READY "
        L"queryFunction=%p "
        L"interfaceId=%p "
        L"iid={%08lX-%04hX-%04hX-"
        L"%02hhX%"
        L"%02hhX%02hhX-"
        L"%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
        NotificationAreaIcon_QueryInterface,
        g_notificationAreaIconInterfaceId,
        g_notificationAreaIconInterfaceId->Data1,
        g_notificationAreaIconInterfaceId->Data2,
        g_notificationAreaIconInterfaceId->Data3,
        g_notificationAreaIconInterfaceId->Data4[0],
        g_notificationAreaIconInterfaceId->Data4[1],
        g_notificationAreaIconInterfaceId->Data4[2],
        g_notificationAreaIconInterfaceId->Data4[3],
        g_notificationAreaIconInterfaceId->Data4[4],
        g_notificationAreaIconInterfaceId->Data4[5],
        g_notificationAreaIconInterfaceId->Data4[6],
        g_notificationAreaIconInterfaceId->Data4[7]
    );

    return true;
}

void QueryAndLogAbiPointer(
    void* iconImplementation,
    unsigned long long visibleAddCall
) {
    const unsigned long long queryCall =
        g_queryCallCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    void* queriedAbi =
        nullptr;

    const int result =
        NotificationAreaIcon_QueryInterface(
            iconImplementation,
            *g_notificationAreaIconInterfaceId,
            &queriedAbi
        );

    void* observedOffsetAbi =
        iconImplementation
            ? static_cast<void*>(
                  static_cast<BYTE*>(
                      iconImplementation
                  ) +
                  0x10
              )
            : nullptr;

    const bool matchesObservedOffset =
        queriedAbi &&
        queriedAbi ==
            observedOffsetAbi;

    Wh_Log(
        L"QUERY_INTERFACE_RESULT "
        L"call=%llu "
        L"visibleAddCall=%llu "
        L"thread=%lu "
        L"implementation=%p "
        L"result=0x%08X "
        L"queriedAbi=%p "
        L"observedOffsetAbi=%p "
        L"matchesObservedOffset=%d",
        queryCall,
        visibleAddCall,
        GetCurrentThreadId(),
        iconImplementation,
        static_cast<unsigned int>(
            result
        ),
        queriedAbi,
        observedOffsetAbi,
        matchesObservedOffset
            ? 1
            : 0
    );

    if (
        SUCCEEDED(result) &&
        queriedAbi
    ) {
        g_latestImplementation.store(
            iconImplementation,
            std::memory_order_release
        );

        g_latestQueriedAbi.store(
            queriedAbi,
            std::memory_order_release
        );

        g_latestQueryCall.store(
            queryCall,
            std::memory_order_release
        );

        reinterpret_cast<IUnknown*>(
            queriedAbi
        )->Release();
    }
}

void __cdecl
NotificationAreaIconManager_AddVisible_Hook(
    void* pThis,
    void* iconImplementation
) {
    const unsigned long long callNumber =
        g_visibleAddCallCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    Wh_Log(
        L"VISIBLE_ADD_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"implementation=%p",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        iconImplementation
    );

    NotificationAreaIconManager_AddVisible_Original(
        pThis,
        iconImplementation
    );

    QueryAndLogAbiPointer(
        iconImplementation,
        callNumber
    );

    Wh_Log(
        L"VISIBLE_ADD_END "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"implementation=%p",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        iconImplementation
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
        g_moveCallCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    void* latestImplementation =
        g_latestImplementation.load(
            std::memory_order_acquire
        );

    void* latestQueriedAbi =
        g_latestQueriedAbi.load(
            std::memory_order_acquire
        );

    const unsigned long long latestQueryCall =
        g_latestQueryCall.load(
            std::memory_order_acquire
        );

    const bool matchesQueriedAbi =
        latestQueriedAbi &&
        notificationAreaIconAbi ==
            latestQueriedAbi;

    void* observedOffsetAbi =
        latestImplementation
            ? static_cast<void*>(
                  static_cast<BYTE*>(
                      latestImplementation
                  ) +
                  0x10
              )
            : nullptr;

    const bool matchesObservedOffset =
        observedOffsetAbi &&
        notificationAreaIconAbi ==
            observedOffsetAbi;

    Wh_Log(
        L"TASKBAR_MOVE_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"taskbarModel=%p "
        L"iconAbi=%p "
        L"location=%d "
        L"index=%u "
        L"latestImplementation=%p "
        L"latestQueriedAbi=%p "
        L"latestQueryCall=%llu "
        L"matchesQueriedAbi=%d "
        L"matchesObservedOffset=%d",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        notificationAreaIconAbi,
        location,
        index,
        latestImplementation,
        latestQueriedAbi,
        latestQueryCall,
        matchesQueriedAbi
            ? 1
            : 0,
        matchesObservedOffset
            ? 1
            : 0
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

    return result;
}

bool HookTaskbarSymbols(
    HMODULE taskbarModule
) {
    WindhawkUtils::SYMBOL_HOOK symbolHooks[] = {
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
            L"Failed to hook taskbar.dll symbols"
        );

        return false;
    }

    Wh_Log(
        L"Tray ABI validation hooks installed"
    );

    return true;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Add Path Analyzer "
        L"0.3.0 initializing"
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

    if (
        !ResolveQueryInterfaceSymbols(
            taskbarModule
        )
    ) {
        return FALSE;
    }

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
        L"visibleAddCalls=%llu "
        L"queryCalls=%llu "
        L"moveCalls=%llu",
        g_visibleAddCallCount.load(
            std::memory_order_relaxed
        ),
        g_queryCallCount.load(
            std::memory_order_relaxed
        ),
        g_moveCallCount.load(
            std::memory_order_relaxed
        )
    );
}
