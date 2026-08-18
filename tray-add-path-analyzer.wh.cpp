// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Correlates live tray ABI pointers with the 64-bit NotifyIconSettings identity.
// @version         0.34.0
// @author          Yusseter
// @github          https://github.com/Yusseter
// @homepage        https://github.com/Yusseter/tray-order-lock
// @license         MIT
// @include         explorer.exe
// @architecture    x86-64
// @compilerOptions -ladvapi32
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# Tray Add Path Analyzer

Version 0.34.0 validates the final live identity bridge required by the
production Tray Order Lock.

Earlier analyzers established:

- NotificationAreaIcon2 implementation objects can be converted safely to the
  INotificationAreaIcon ABI pointer through QueryInterface.
- NotificationAreaIcon2 is constructed with a settings pair containing an
  unsigned 64-bit value and a shared registry HKEY.
- The same NotifyIconSettingsDatabase uses unsigned 64-bit identities for
  GetUIOrderForIcon and MoveIcon.

This version performs a controlled runtime correlation.

For each NotificationAreaIcon2 constructed after the analyzer is enabled it:

- Reads the first unsigned 64-bit member of the settings pair.
- Calls the already validated QueryInterface path after construction.
- Records the resulting INotificationAreaIcon ABI pointer.
- Checks whether the 64-bit value is present in UIOrderList.

When a normal tray drag occurs it:

- Looks up the MoveNotificationAreaIcon ABI pointer in the live map.
- Records the associated 64-bit settings identity.
- Observes NotifyIconSettingsDatabase::MoveIcon during the same call.
- Checks whether either database identity argument matches the live mapped
  identity.

The test is observational only. All original functions are called normally.

This version:

- Does not create tray icons.
- Does not perform automatic moves.
- Does not block manual moves.
- Does not write registry values.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <unknwn.h>
#include <windhawk_utils.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <mutex>
#include <vector>

namespace {

constexpr wchar_t kNotifyIconSettingsPath[] =
    L"Control Panel\\NotifyIconSettings";

constexpr wchar_t kUIOrderListValueName[] =
    L"UIOrderList";

using NotificationAreaIcon2_Constructor_t =
    void(__cdecl*)(
        void* pThis,
        void* identityRvalueReference,
        void* settingsPairReference
    );

using NotificationAreaIcon_QueryInterface_t =
    int(__cdecl*)(
        void* iconImplementation,
        const GUID& interfaceId,
        void** result
    );

using TaskbarModel_MoveNotificationAreaIcon_t =
    int(__cdecl*)(
        void* pThis,
        void* notificationAreaIconAbi,
        int location,
        unsigned int index
    );

using NotifyIconSettingsDatabase_MoveIcon_t =
    void(__cdecl*)(
        void* pThis,
        std::uint64_t firstIdentity,
        std::uint64_t secondIdentity,
        int relativePosition
    );

NotificationAreaIcon2_Constructor_t
    NotificationAreaIcon2_Constructor_Target =
        nullptr;

NotificationAreaIcon2_Constructor_t
    NotificationAreaIcon2_Constructor_Original =
        nullptr;

NotificationAreaIcon_QueryInterface_t
    NotificationAreaIcon_QueryInterface =
        nullptr;

TaskbarModel_MoveNotificationAreaIcon_t
    TaskbarModel_MoveNotificationAreaIcon_Original =
        nullptr;

NotifyIconSettingsDatabase_MoveIcon_t
    NotifyIconSettingsDatabase_MoveIcon_Original =
        nullptr;

const GUID* g_notificationAreaIconInterfaceId =
    nullptr;

std::atomic<unsigned long long>
    g_constructorCalls =
        0;

std::atomic<unsigned long long>
    g_mappedIconCount =
        0;

std::atomic<unsigned long long>
    g_taskbarMoveCalls =
        0;

std::atomic<unsigned long long>
    g_databaseMoveCalls =
        0;

struct LiveIdentityMapping {
    void* implementation =
        nullptr;

    void* abi =
        nullptr;

    std::uint64_t settingsIdentity =
        0;

    bool inUIOrderList =
        false;

    unsigned long long uiOrderPosition =
        0;
};

std::mutex g_mappingMutex;

std::vector<LiveIdentityMapping>
    g_liveMappings;

thread_local unsigned long long
    g_activeTaskbarMoveCall =
        0;

thread_local std::uint64_t
    g_activeTaskbarSettingsIdentity =
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

bool IsNotificationAreaIconConstructorSymbol(
    const wchar_t* symbol
) {
    return
        symbol &&
        ContainsText(
            symbol,
            L"public: __cdecl "
        ) &&
        ContainsText(
            symbol,
            L"NotificationAreaIcon2::NotificationAreaIcon2("
        ) &&
        ContainsText(
            symbol,
            L"NotificationAreaIconIdentity &&"
        ) &&
        ContainsText(
            symbol,
            L"pair<unsigned __int64"
        ) &&
        ContainsText(
            symbol,
            L"HKEY__"
        );
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
    constexpr wchar_t expected[] =
        L"struct guid::guid const "
        L"winrt::impl::guid_v<struct "
        L"winrt::WindowsUdk::UI::Shell::"
        L"INotificationAreaIcon>";

    return
        symbol &&
        std::wcscmp(
            symbol,
            expected
        ) ==
        0;
}

bool ResolveRequiredSymbols(
    HMODULE taskbarModule
) {
    WH_FIND_SYMBOL_OPTIONS options{};

    options.optionsSize =
        sizeof(
            options
        );

    options.symbolServer =
        nullptr;

    options.noUndecoratedSymbols =
        FALSE;

    WH_FIND_SYMBOL symbol{};

    HANDLE search =
        Wh_FindFirstSymbol(
            taskbarModule,
            &options,
            &symbol
        );

    if (!search) {
        Wh_Log(
            L"LIVE_IDENTITY_SYMBOL_ENUMERATION_FAILED "
            L"lastError=%lu",
            GetLastError()
        );

        return false;
    }

    unsigned int constructorMatches =
        0;

    unsigned int queryInterfaceMatches =
        0;

    unsigned int iidMatches =
        0;

    do {
        if (
            IsNotificationAreaIconConstructorSymbol(
                symbol.symbol
            )
        ) {
            constructorMatches++;

            if (
                !NotificationAreaIcon2_Constructor_Target
            ) {
                NotificationAreaIcon2_Constructor_Target =
                    reinterpret_cast<
                        NotificationAreaIcon2_Constructor_t
                    >(
                        symbol.address
                    );

                Wh_Log(
                    L"LIVE_IDENTITY_CONSTRUCTOR_SYMBOL "
                    L"address=%p",
                    symbol.address
                );
            }
        }

        if (
            IsNotificationAreaIconQueryInterfaceSymbol(
                symbol.symbol
            )
        ) {
            queryInterfaceMatches++;

            if (
                !NotificationAreaIcon_QueryInterface
            ) {
                NotificationAreaIcon_QueryInterface =
                    reinterpret_cast<
                        NotificationAreaIcon_QueryInterface_t
                    >(
                        symbol.address
                    );

                Wh_Log(
                    L"LIVE_IDENTITY_QUERY_INTERFACE_SYMBOL "
                    L"address=%p",
                    symbol.address
                );
            }
        }

        if (
            IsNotificationAreaIconIidSymbol(
                symbol.symbol
            )
        ) {
            iidMatches++;

            if (
                !g_notificationAreaIconInterfaceId
            ) {
                g_notificationAreaIconInterfaceId =
                    reinterpret_cast<const GUID*>(
                        symbol.address
                    );

                Wh_Log(
                    L"LIVE_IDENTITY_INTERFACE_ID_SYMBOL "
                    L"address=%p",
                    symbol.address
                );
            }
        }
    } while (
        Wh_FindNextSymbol(
            search,
            &symbol
        )
    );

    Wh_FindCloseSymbol(
        search
    );

    Wh_Log(
        L"LIVE_IDENTITY_SYMBOL_SUMMARY "
        L"constructorMatches=%u "
        L"queryInterfaceMatches=%u "
        L"iidMatches=%u",
        constructorMatches,
        queryInterfaceMatches,
        iidMatches
    );

    if (
        constructorMatches !=
            1 ||
        !NotificationAreaIcon2_Constructor_Target ||
        !NotificationAreaIcon_QueryInterface ||
        !g_notificationAreaIconInterfaceId
    ) {
        Wh_Log(
            L"LIVE_IDENTITY_REQUIRED_SYMBOL_MISSING_OR_AMBIGUOUS"
        );

        return false;
    }

    return true;
}

bool FindUIOrderIdentity(
    std::uint64_t identity,
    unsigned long long* position,
    unsigned long long* count
) {
    if (position) {
        *position =
            0;
    }

    if (count) {
        *count =
            0;
    }

    DWORD registryType =
        REG_NONE;

    DWORD requiredBytes =
        0;

    LONG status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            kNotifyIconSettingsPath,
            kUIOrderListValueName,
            RRF_RT_REG_BINARY,
            &registryType,
            nullptr,
            &requiredBytes
        );

    if (
        status !=
            ERROR_SUCCESS ||
        requiredBytes %
                sizeof(
                    std::uint64_t
                ) !=
            0
    ) {
        return false;
    }

    std::vector<BYTE> data(
        requiredBytes
    );

    DWORD actualBytes =
        requiredBytes;

    status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            kNotifyIconSettingsPath,
            kUIOrderListValueName,
            RRF_RT_REG_BINARY,
            &registryType,
            data.empty()
                ? nullptr
                : data.data(),
            &actualBytes
        );

    if (
        status !=
            ERROR_SUCCESS ||
        actualBytes %
                sizeof(
                    std::uint64_t
                ) !=
            0
    ) {
        return false;
    }

    const std::size_t entryCount =
        actualBytes /
        sizeof(
            std::uint64_t
        );

    if (count) {
        *count =
            static_cast<unsigned long long>(
                entryCount
            );
    }

    for (
        std::size_t index = 0;
        index <
            entryCount;
        index++
    ) {
        std::uint64_t current =
            0;

        std::memcpy(
            &current,
            data.data() +
                index *
                    sizeof(
                        std::uint64_t
                    ),
            sizeof(
                current
            )
        );

        if (
            current ==
            identity
        ) {
            if (position) {
                *position =
                    static_cast<unsigned long long>(
                        index +
                        1
                    );
            }

            return true;
        }
    }

    return false;
}

void StoreLiveMapping(
    const LiveIdentityMapping& mapping
) {
    std::lock_guard<std::mutex> lock(
        g_mappingMutex
    );

    for (
        LiveIdentityMapping& existing :
        g_liveMappings
    ) {
        if (
            existing.abi ==
                mapping.abi ||
            existing.implementation ==
                mapping.implementation
        ) {
            existing =
                mapping;

            return;
        }
    }

    g_liveMappings.push_back(
        mapping
    );
}

bool LookupLiveMapping(
    void* abi,
    LiveIdentityMapping* mapping
) {
    if (
        !abi ||
        !mapping
    ) {
        return false;
    }

    std::lock_guard<std::mutex> lock(
        g_mappingMutex
    );

    for (
        const LiveIdentityMapping& candidate :
        g_liveMappings
    ) {
        if (
            candidate.abi ==
            abi
        ) {
            *mapping =
                candidate;

            return true;
        }
    }

    return false;
}

void __cdecl
NotificationAreaIcon2_Constructor_Hook(
    void* pThis,
    void* identityRvalueReference,
    void* settingsPairReference
) {
    const unsigned long long callNumber =
        g_constructorCalls.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    std::uint64_t settingsIdentity =
        0;

    if (
        settingsPairReference
    ) {
        std::memcpy(
            &settingsIdentity,
            settingsPairReference,
            sizeof(
                settingsIdentity
            )
        );
    }

    NotificationAreaIcon2_Constructor_Original(
        pThis,
        identityRvalueReference,
        settingsPairReference
    );

    void* queriedAbi =
        nullptr;

    HRESULT queryResult =
        E_FAIL;

    if (
        NotificationAreaIcon_QueryInterface &&
        g_notificationAreaIconInterfaceId
    ) {
        queryResult =
            static_cast<HRESULT>(
                NotificationAreaIcon_QueryInterface(
                    pThis,
                    *g_notificationAreaIconInterfaceId,
                    &queriedAbi
                )
            );
    }

    unsigned long long position =
        0;

    unsigned long long orderCount =
        0;

    const bool inUIOrderList =
        settingsIdentity !=
            0 &&
        FindUIOrderIdentity(
            settingsIdentity,
            &position,
            &orderCount
        );

    Wh_Log(
        L"LIVE_IDENTITY_CONSTRUCTED "
        L"call=%llu "
        L"implementation=%p "
        L"settingsPair=%p "
        L"settingsIdentity=%llu "
        L"queryResult=0x%08X "
        L"queriedAbi=%p "
        L"inUIOrderList=%d "
        L"uiOrderPosition=%llu "
        L"uiOrderCount=%llu",
        callNumber,
        pThis,
        settingsPairReference,
        static_cast<unsigned long long>(
            settingsIdentity
        ),
        static_cast<unsigned int>(
            queryResult
        ),
        queriedAbi,
        inUIOrderList
            ? 1
            : 0,
        position,
        orderCount
    );

    if (
        SUCCEEDED(
            queryResult
        ) &&
        queriedAbi &&
        settingsIdentity !=
            0
    ) {
        LiveIdentityMapping mapping;

        mapping.implementation =
            pThis;

        mapping.abi =
            queriedAbi;

        mapping.settingsIdentity =
            settingsIdentity;

        mapping.inUIOrderList =
            inUIOrderList;

        mapping.uiOrderPosition =
            position;

        StoreLiveMapping(
            mapping
        );

        const unsigned long long mapped =
            g_mappedIconCount.fetch_add(
                1,
                std::memory_order_relaxed
            ) +
            1;

        Wh_Log(
            L"LIVE_IDENTITY_MAP "
            L"mapped=%llu "
            L"implementation=%p "
            L"abi=%p "
            L"settingsIdentity=%llu "
            L"inUIOrderList=%d "
            L"uiOrderPosition=%llu",
            mapped,
            pThis,
            queriedAbi,
            static_cast<unsigned long long>(
                settingsIdentity
            ),
            inUIOrderList
                ? 1
                : 0,
            position
        );
    }

    if (
        queriedAbi
    ) {
        reinterpret_cast<IUnknown*>(
            queriedAbi
        )->Release();
    }
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

    LiveIdentityMapping mapping;

    const bool mapped =
        LookupLiveMapping(
            notificationAreaIconAbi,
            &mapping
        );

    unsigned long long currentPosition =
        0;

    unsigned long long currentCount =
        0;

    const bool currentIdentityPresent =
        mapped &&
        FindUIOrderIdentity(
            mapping.settingsIdentity,
            &currentPosition,
            &currentCount
        );

    Wh_Log(
        L"LIVE_IDENTITY_TASKBAR_MOVE_BEGIN "
        L"call=%llu "
        L"iconAbi=%p "
        L"mapped=%d "
        L"settingsIdentity=%llu "
        L"identityPresent=%d "
        L"uiOrderPosition=%llu "
        L"uiOrderCount=%llu "
        L"location=%d "
        L"index=%u",
        callNumber,
        notificationAreaIconAbi,
        mapped
            ? 1
            : 0,
        static_cast<unsigned long long>(
            mapped
                ? mapping.settingsIdentity
                : 0
        ),
        currentIdentityPresent
            ? 1
            : 0,
        currentPosition,
        currentCount,
        location,
        index
    );

    const unsigned long long previousCall =
        g_activeTaskbarMoveCall;

    const std::uint64_t previousIdentity =
        g_activeTaskbarSettingsIdentity;

    g_activeTaskbarMoveCall =
        callNumber;

    g_activeTaskbarSettingsIdentity =
        mapped
            ? mapping.settingsIdentity
            : 0;

    const int result =
        TaskbarModel_MoveNotificationAreaIcon_Original(
            pThis,
            notificationAreaIconAbi,
            location,
            index
        );

    Wh_Log(
        L"LIVE_IDENTITY_TASKBAR_MOVE_END "
        L"call=%llu "
        L"result=0x%08X "
        L"mapped=%d "
        L"settingsIdentity=%llu",
        callNumber,
        static_cast<unsigned int>(
            result
        ),
        mapped
            ? 1
            : 0,
        static_cast<unsigned long long>(
            mapped
                ? mapping.settingsIdentity
                : 0
        )
    );

    g_activeTaskbarMoveCall =
        previousCall;

    g_activeTaskbarSettingsIdentity =
        previousIdentity;

    return result;
}

void __cdecl
NotifyIconSettingsDatabase_MoveIcon_Hook(
    void* pThis,
    std::uint64_t firstIdentity,
    std::uint64_t secondIdentity,
    int relativePosition
) {
    const unsigned long long callNumber =
        g_databaseMoveCalls.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    const std::uint64_t activeIdentity =
        g_activeTaskbarSettingsIdentity;

    unsigned long long firstPosition =
        0;

    unsigned long long firstCount =
        0;

    unsigned long long secondPosition =
        0;

    unsigned long long secondCount =
        0;

    const bool firstPresent =
        FindUIOrderIdentity(
            firstIdentity,
            &firstPosition,
            &firstCount
        );

    const bool secondPresent =
        FindUIOrderIdentity(
            secondIdentity,
            &secondPosition,
            &secondCount
        );

    Wh_Log(
        L"LIVE_IDENTITY_DATABASE_MOVE "
        L"call=%llu "
        L"database=%p "
        L"activeTaskbarMove=%llu "
        L"activeSettingsIdentity=%llu "
        L"firstIdentity=%llu "
        L"secondIdentity=%llu "
        L"firstMatchesActive=%d "
        L"secondMatchesActive=%d "
        L"firstPresent=%d "
        L"secondPresent=%d "
        L"firstPosition=%llu "
        L"secondPosition=%llu "
        L"relativePosition=%d",
        callNumber,
        pThis,
        g_activeTaskbarMoveCall,
        static_cast<unsigned long long>(
            activeIdentity
        ),
        static_cast<unsigned long long>(
            firstIdentity
        ),
        static_cast<unsigned long long>(
            secondIdentity
        ),
        (
            activeIdentity !=
                0 &&
            firstIdentity ==
                activeIdentity
        )
            ? 1
            : 0,
        (
            activeIdentity !=
                0 &&
            secondIdentity ==
                activeIdentity
        )
            ? 1
            : 0,
        firstPresent
            ? 1
            : 0,
        secondPresent
            ? 1
            : 0,
        firstPosition,
        secondPosition,
        relativePosition
    );

    NotifyIconSettingsDatabase_MoveIcon_Original(
        pThis,
        firstIdentity,
        secondIdentity,
        relativePosition
    );
}

bool HookRequiredFunctions(
    HMODULE taskbarModule
) {
    if (
        !WindhawkUtils::SetFunctionHook(
            NotificationAreaIcon2_Constructor_Target,
            NotificationAreaIcon2_Constructor_Hook,
            &NotificationAreaIcon2_Constructor_Original
        )
    ) {
        Wh_Log(
            L"LIVE_IDENTITY_CONSTRUCTOR_HOOK_FAILED"
        );

        return false;
    }

    WindhawkUtils::SYMBOL_HOOK hooks[] = {
        {
            {
                LR"(public: virtual int __cdecl winrt::impl::produce<struct winrt::WindowsUdk::UI::Shell::implementation::TaskbarModel,struct winrt::WindowsUdk::UI::Shell::ITaskbarModel5>::MoveNotificationAreaIcon(void *,int,unsigned int))"
            },
            &TaskbarModel_MoveNotificationAreaIcon_Original,
            TaskbarModel_MoveNotificationAreaIcon_Hook,
        },
        {
            {
                LR"(public: void __cdecl NotifyIconSettingsDatabase::MoveIcon(unsigned __int64,unsigned __int64,enum OrderListRelativePosition))"
            },
            &NotifyIconSettingsDatabase_MoveIcon_Original,
            NotifyIconSettingsDatabase_MoveIcon_Hook,
        },
    };

    if (
        !WindhawkUtils::HookSymbols(
            taskbarModule,
            hooks,
            ARRAYSIZE(
                hooks
            )
        )
    ) {
        Wh_Log(
            L"LIVE_IDENTITY_TASKBAR_HOOKS_FAILED"
        );

        return false;
    }

    Wh_Log(
        L"LIVE_IDENTITY_HOOKS_REGISTERED "
        L"constructor=%p "
        L"queryInterface=%p "
        L"interfaceId=%p",
        NotificationAreaIcon2_Constructor_Target,
        NotificationAreaIcon_QueryInterface,
        g_notificationAreaIconInterfaceId
    );

    return true;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Add Path Analyzer 0.34.0 initializing "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    HMODULE taskbarModule =
        GetModuleHandleW(
            L"taskbar.dll"
        );

    if (!taskbarModule) {
        Wh_Log(
            L"LIVE_IDENTITY_TASKBAR_NOT_READY"
        );

        return FALSE;
    }

    if (
        !ResolveRequiredSymbols(
            taskbarModule
        )
    ) {
        return FALSE;
    }

    if (
        !HookRequiredFunctions(
            taskbarModule
        )
    ) {
        return FALSE;
    }

    Wh_Log(
        L"LIVE_IDENTITY_TEST_READY "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    return TRUE;
}

void Wh_ModUninit() {
    std::size_t liveMappings =
        0;

    {
        std::lock_guard<std::mutex> lock(
            g_mappingMutex
        );

        liveMappings =
            g_liveMappings.size();
    }

    Wh_Log(
        L"Tray Add Path Analyzer 0.34.0 stopped "
        L"processId=%lu "
        L"constructorCalls=%llu "
        L"mappedIcons=%llu "
        L"liveMappings=%llu "
        L"taskbarMoveCalls=%llu "
        L"databaseMoveCalls=%llu",
        GetCurrentProcessId(),
        g_constructorCalls.load(
            std::memory_order_relaxed
        ),
        g_mappedIconCount.load(
            std::memory_order_relaxed
        ),
        static_cast<unsigned long long>(
            liveMappings
        ),
        g_taskbarMoveCalls.load(
            std::memory_order_relaxed
        ),
        g_databaseMoveCalls.load(
            std::memory_order_relaxed
        )
    );
}
