// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Tests UID-based tray identity behavior across executable path changes.
// @version         0.10.0
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

A temporary read-only diagnostic mod.

Version 0.10.0 runs the same UID-based tray application binary from two
different directories.

Both copies use:

- The same executable file name.
- The same fixed notification icon UID.
- No notification icon GUID.

The analyzer:

- Captures UIOrderList before and after every AddIcon call.
- Detects the registry identity created for the first executable path.
- Checks whether the second executable path reuses the first identity or
  creates another identity.
- Records GetUIOrderForIcon calls for the involved registry identities.
- Performs no MoveIcon operation and does not intentionally modify tray order.

The dedicated test executable is:

TrayUidIdentityProbeV100.exe
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <windhawk_utils.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr wchar_t kNotifyIconSettingsPath[] =
    L"Control Panel\\NotifyIconSettings";

constexpr wchar_t kUIOrderListValueName[] =
    L"UIOrderList";

constexpr wchar_t kTargetExecutableName[] =
    L"trayuididentityprobev100.exe";

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

using NotifyIconSettingsDatabase_GetUIOrderForIcon_t =
    unsigned int(__cdecl*)(
        void* pThis,
        std::uint64_t identity
    );

NotificationAreaIconManager_AddIcon_t
    NotificationAreaIconManager_AddIcon_Original =
        nullptr;

NotificationAreaIconManager_AddVisible_t
    NotificationAreaIconManager_AddVisible_Original =
        nullptr;

NotifyIconSettingsDatabase_GetUIOrderForIcon_t
    NotifyIconSettingsDatabase_GetUIOrderForIcon_Original =
        nullptr;

std::atomic<unsigned long long> g_addIconCalls =
    0;

std::atomic<unsigned long long> g_visibleAddCalls =
    0;

std::atomic<unsigned long long> g_orderQueries =
    0;

std::atomic<unsigned long long> g_targetResults =
    0;

std::atomic<std::uint64_t> g_firstTargetIdentity =
    0;

struct UIOrderSnapshot {
    bool valid =
        false;

    LONG status =
        ERROR_SUCCESS;

    std::vector<std::uint64_t> entries;
};

struct OrderQueryObservation {
    std::uint64_t identity =
        0;

    unsigned int returnedOrder =
        0;
};

struct AddIconContext {
    bool active =
        false;

    unsigned long long callNumber =
        0;

    void* manager =
        nullptr;

    void* trayNotifyData =
        nullptr;

    UIOrderSnapshot before;

    std::vector<OrderQueryObservation> orderQueries;

    std::vector<void*> visibleImplementations;
};

thread_local AddIconContext g_addIconContext;

UIOrderSnapshot CaptureUIOrderSnapshot() {
    UIOrderSnapshot snapshot;

    for (
        int attempt = 0;
        attempt < 3;
        attempt++
    ) {
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

        snapshot.status =
            status;

        if (status != ERROR_SUCCESS) {
            return snapshot;
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

        if (status == ERROR_MORE_DATA) {
            continue;
        }

        snapshot.status =
            status;

        if (status != ERROR_SUCCESS) {
            return snapshot;
        }

        if (
            actualBytes %
                sizeof(std::uint64_t) !=
            0
        ) {
            snapshot.status =
                ERROR_INVALID_DATA;

            return snapshot;
        }

        snapshot.entries.resize(
            actualBytes /
            sizeof(std::uint64_t)
        );

        if (actualBytes != 0) {
            std::memcpy(
                snapshot.entries.data(),
                data.data(),
                actualBytes
            );
        }

        snapshot.valid =
            true;

        return snapshot;
    }

    snapshot.status =
        ERROR_MORE_DATA;

    return snapshot;
}

std::wstring MakeTrayEntrySubkey(
    std::uint64_t identity
) {
    return
        std::wstring(
            kNotifyIconSettingsPath
        ) +
        L"\\" +
        std::to_wstring(
            identity
        );
}

std::wstring QueryStringValue(
    const std::wstring& subkey,
    const wchar_t* valueName
) {
    DWORD registryType =
        REG_NONE;

    DWORD requiredBytes =
        0;

    LONG status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            valueName,
            RRF_RT_REG_SZ |
                RRF_RT_REG_EXPAND_SZ,
            &registryType,
            nullptr,
            &requiredBytes
        );

    if (
        status != ERROR_SUCCESS ||
        requiredBytes == 0
    ) {
        return L"";
    }

    std::vector<wchar_t> buffer(
        requiredBytes /
            sizeof(wchar_t) +
        1
    );

    DWORD actualBytes =
        requiredBytes;

    status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            valueName,
            RRF_RT_REG_SZ |
                RRF_RT_REG_EXPAND_SZ,
            &registryType,
            buffer.data(),
            &actualBytes
        );

    if (status != ERROR_SUCCESS) {
        return L"";
    }

    buffer.back() =
        L'\0';

    return
        std::wstring(
            buffer.data()
        );
}

bool EndsWithOrdinalIgnoreCase(
    const std::wstring& value,
    const std::wstring& suffix
) {
    if (
        value.size() <
        suffix.size()
    ) {
        return false;
    }

    const std::size_t offset =
        value.size() -
        suffix.size();

    for (
        std::size_t index = 0;
        index < suffix.size();
        index++
    ) {
        const wchar_t left =
            static_cast<wchar_t>(
                std::towlower(
                    value[
                        offset +
                        index
                    ]
                )
            );

        const wchar_t right =
            static_cast<wchar_t>(
                std::towlower(
                    suffix[index]
                )
            );

        if (left != right) {
            return false;
        }
    }

    return true;
}

std::vector<std::uint64_t> FindAddedIdentities(
    const UIOrderSnapshot& before,
    const UIOrderSnapshot& after
) {
    std::vector<std::uint64_t> added;

    if (
        !before.valid ||
        !after.valid
    ) {
        return added;
    }

    for (
        std::uint64_t identity :
        after.entries
    ) {
        if (
            std::find(
                before.entries.begin(),
                before.entries.end(),
                identity
            ) ==
            before.entries.end()
        ) {
            added.push_back(
                identity
            );
        }
    }

    return added;
}

std::vector<std::uint64_t> FindTargetIdentities(
    const UIOrderSnapshot& snapshot
) {
    std::vector<std::uint64_t> matches;

    if (!snapshot.valid) {
        return matches;
    }

    for (
        std::uint64_t identity :
        snapshot.entries
    ) {
        const std::wstring executablePath =
            QueryStringValue(
                MakeTrayEntrySubkey(
                    identity
                ),
                L"ExecutablePath"
            );

        if (
            EndsWithOrdinalIgnoreCase(
                executablePath,
                kTargetExecutableName
            )
        ) {
            matches.push_back(
                identity
            );
        }
    }

    return matches;
}

bool ContainsIdentity(
    const std::vector<std::uint64_t>& identities,
    std::uint64_t identity
) {
    return
        std::find(
            identities.begin(),
            identities.end(),
            identity
        ) !=
        identities.end();
}

unsigned long long FindOneBasedPosition(
    const UIOrderSnapshot& snapshot,
    std::uint64_t identity
) {
    const auto iterator =
        std::find(
            snapshot.entries.begin(),
            snapshot.entries.end(),
            identity
        );

    if (
        iterator ==
        snapshot.entries.end()
    ) {
        return 0;
    }

    return
        static_cast<unsigned long long>(
            std::distance(
                snapshot.entries.begin(),
                iterator
            )
        ) +
        1;
}

unsigned int CountObservedIdentity(
    const std::vector<OrderQueryObservation>& observations,
    std::uint64_t identity
) {
    unsigned int count =
        0;

    for (
        const OrderQueryObservation& observation :
        observations
    ) {
        if (
            observation.identity ==
            identity
        ) {
            count++;
        }
    }

    return count;
}

void LogIdentitySet(
    const wchar_t* label,
    unsigned long long addCall,
    const std::vector<std::uint64_t>& identities,
    const UIOrderSnapshot& snapshot
) {
    Wh_Log(
        L"%s "
        L"addCall=%llu "
        L"count=%llu",
        label,
        addCall,
        static_cast<unsigned long long>(
            identities.size()
        )
    );

    for (
        std::size_t index = 0;
        index < identities.size();
        index++
    ) {
        const std::uint64_t identity =
            identities[index];

        const std::wstring executablePath =
            QueryStringValue(
                MakeTrayEntrySubkey(
                    identity
                ),
                L"ExecutablePath"
            );

        Wh_Log(
            L"%s_ITEM "
            L"addCall=%llu "
            L"item=%llu "
            L"id=%llu "
            L"position=%llu "
            L"path=\"%s\"",
            label,
            addCall,
            static_cast<unsigned long long>(
                index +
                1
            ),
            static_cast<unsigned long long>(
                identity
            ),
            snapshot.valid
                ? FindOneBasedPosition(
                      snapshot,
                      identity
                  )
                : 0,
            executablePath.c_str()
        );
    }
}

void AnalyzeCompletedAddIcon(
    const AddIconContext& context,
    const UIOrderSnapshot& after
) {
    const std::vector<std::uint64_t> addedIdentities =
        FindAddedIdentities(
            context.before,
            after
        );

    const std::vector<std::uint64_t> targetBefore =
        FindTargetIdentities(
            context.before
        );

    const std::vector<std::uint64_t> targetAfter =
        FindTargetIdentities(
            after
        );

    std::vector<std::uint64_t> targetAdded;

    for (
        std::uint64_t identity :
        addedIdentities
    ) {
        if (
            ContainsIdentity(
                targetAfter,
                identity
            )
        ) {
            targetAdded.push_back(
                identity
            );
        }
    }

    LogIdentitySet(
        L"ADDED_IDENTITIES",
        context.callNumber,
        addedIdentities,
        after
    );

    LogIdentitySet(
        L"TARGET_BEFORE",
        context.callNumber,
        targetBefore,
        context.before
    );

    LogIdentitySet(
        L"TARGET_AFTER",
        context.callNumber,
        targetAfter,
        after
    );

    LogIdentitySet(
        L"TARGET_ADDED",
        context.callNumber,
        targetAdded,
        after
    );

    std::uint64_t selectedIdentity =
        0;

    const wchar_t* resultKind =
        L"unrelated";

    if (
        targetBefore.empty() &&
        targetAdded.size() ==
            1
    ) {
        selectedIdentity =
            targetAdded.front();

        resultKind =
            L"first-path-new-identity";

        std::uint64_t expected =
            0;

        g_firstTargetIdentity.compare_exchange_strong(
            expected,
            selectedIdentity,
            std::memory_order_acq_rel
        );
    } else if (
        !targetBefore.empty() &&
        targetAdded.size() ==
            1
    ) {
        selectedIdentity =
            targetAdded.front();

        resultKind =
            L"changed-path-created-new-identity";
    } else if (
        targetAdded.empty() &&
        targetBefore.size() ==
            1 &&
        targetAfter.size() ==
            1 &&
        targetBefore.front() ==
            targetAfter.front()
    ) {
        selectedIdentity =
            targetAfter.front();

        resultKind =
            L"changed-path-reused-identity";
    } else if (
        !targetBefore.empty() ||
        !targetAfter.empty() ||
        !targetAdded.empty()
    ) {
        resultKind =
            L"ambiguous";
    }

    const std::uint64_t firstTargetIdentity =
        g_firstTargetIdentity.load(
            std::memory_order_acquire
        );

    const bool matchesFirstIdentity =
        selectedIdentity != 0 &&
        firstTargetIdentity != 0 &&
        selectedIdentity ==
            firstTargetIdentity;

    const bool firstIdentityStillPresent =
        firstTargetIdentity != 0 &&
        ContainsIdentity(
            targetAfter,
            firstTargetIdentity
        );

    unsigned int matchingOrderQueries =
        0;

    if (selectedIdentity != 0) {
        matchingOrderQueries =
            CountObservedIdentity(
                context.orderQueries,
                selectedIdentity
            );
    }

    const unsigned long long resultNumber =
        g_targetResults.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    Wh_Log(
        L"UID_PATH_RESULT "
        L"result=%llu "
        L"addCall=%llu "
        L"kind=\"%s\" "
        L"selectedIdentity=%llu "
        L"firstTargetIdentity=%llu "
        L"matchesFirstIdentity=%d "
        L"firstIdentityStillPresent=%d "
        L"matchingOrderQueries=%u "
        L"totalOrderQueries=%llu "
        L"visibleImplementations=%llu "
        L"targetBeforeCount=%llu "
        L"targetAfterCount=%llu "
        L"targetAddedCount=%llu "
        L"beforeCount=%llu "
        L"afterCount=%llu "
        L"beforePosition=%llu "
        L"afterPosition=%llu",
        resultNumber,
        context.callNumber,
        resultKind,
        static_cast<unsigned long long>(
            selectedIdentity
        ),
        static_cast<unsigned long long>(
            firstTargetIdentity
        ),
        matchesFirstIdentity
            ? 1
            : 0,
        firstIdentityStillPresent
            ? 1
            : 0,
        matchingOrderQueries,
        static_cast<unsigned long long>(
            context.orderQueries.size()
        ),
        static_cast<unsigned long long>(
            context.visibleImplementations.size()
        ),
        static_cast<unsigned long long>(
            targetBefore.size()
        ),
        static_cast<unsigned long long>(
            targetAfter.size()
        ),
        static_cast<unsigned long long>(
            targetAdded.size()
        ),
        static_cast<unsigned long long>(
            context.before.entries.size()
        ),
        static_cast<unsigned long long>(
            after.entries.size()
        ),
        selectedIdentity != 0
            ? FindOneBasedPosition(
                  context.before,
                  selectedIdentity
              )
            : 0,
        selectedIdentity != 0
            ? FindOneBasedPosition(
                  after,
                  selectedIdentity
              )
            : 0
    );
}

unsigned int __cdecl
NotifyIconSettingsDatabase_GetUIOrderForIcon_Hook(
    void* pThis,
    std::uint64_t identity
) {
    const unsigned long long queryNumber =
        g_orderQueries.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    const unsigned int returnedOrder =
        NotifyIconSettingsDatabase_GetUIOrderForIcon_Original(
            pThis,
            identity
        );

    if (g_addIconContext.active) {
        g_addIconContext.orderQueries.push_back(
            {
                identity,
                returnedOrder
            }
        );
    }

    Wh_Log(
        L"UI_ORDER_QUERY "
        L"query=%llu "
        L"thread=%lu "
        L"database=%p "
        L"id=%llu "
        L"returnedOrder=%u "
        L"duringAddIcon=%d "
        L"parentAddCall=%llu",
        queryNumber,
        GetCurrentThreadId(),
        pThis,
        static_cast<unsigned long long>(
            identity
        ),
        returnedOrder,
        g_addIconContext.active
            ? 1
            : 0,
        g_addIconContext.active
            ? g_addIconContext.callNumber
            : 0
    );

    return returnedOrder;
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

    Wh_Log(
        L"VISIBLE_ADD_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"implementation=%p "
        L"duringAddIcon=%d "
        L"parentAddCall=%llu",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        iconImplementation,
        g_addIconContext.active
            ? 1
            : 0,
        g_addIconContext.active
            ? g_addIconContext.callNumber
            : 0
    );

    NotificationAreaIconManager_AddVisible_Original(
        pThis,
        iconImplementation
    );

    if (g_addIconContext.active) {
        g_addIconContext.visibleImplementations.push_back(
            iconImplementation
        );
    }

    Wh_Log(
        L"VISIBLE_ADD_END "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"implementation=%p "
        L"duringAddIcon=%d "
        L"parentAddCall=%llu",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        iconImplementation,
        g_addIconContext.active
            ? 1
            : 0,
        g_addIconContext.active
            ? g_addIconContext.callNumber
            : 0
    );
}

void __cdecl
NotificationAreaIconManager_AddIcon_Hook(
    void* pThis,
    void* trayNotifyData
) {
    const unsigned long long callNumber =
        g_addIconCalls.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    AddIconContext previousContext =
        std::move(
            g_addIconContext
        );

    g_addIconContext =
        {};

    g_addIconContext.active =
        true;

    g_addIconContext.callNumber =
        callNumber;

    g_addIconContext.manager =
        pThis;

    g_addIconContext.trayNotifyData =
        trayNotifyData;

    g_addIconContext.before =
        CaptureUIOrderSnapshot();

    const std::vector<std::uint64_t> targetBefore =
        FindTargetIdentities(
            g_addIconContext.before
        );

    Wh_Log(
        L"ADD_ICON_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"trayNotifyData=%p "
        L"beforeValid=%d "
        L"beforeStatus=%ld "
        L"beforeCount=%llu "
        L"targetBeforeCount=%llu",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        trayNotifyData,
        g_addIconContext.before.valid
            ? 1
            : 0,
        g_addIconContext.before.status,
        static_cast<unsigned long long>(
            g_addIconContext.before.entries.size()
        ),
        static_cast<unsigned long long>(
            targetBefore.size()
        )
    );

    NotificationAreaIconManager_AddIcon_Original(
        pThis,
        trayNotifyData
    );

    const UIOrderSnapshot after =
        CaptureUIOrderSnapshot();

    Wh_Log(
        L"ADD_ICON_ORIGINAL_RETURNED "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"afterValid=%d "
        L"afterStatus=%ld "
        L"afterCount=%llu "
        L"orderQueries=%llu "
        L"visibleImplementations=%llu",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        after.valid
            ? 1
            : 0,
        after.status,
        static_cast<unsigned long long>(
            after.entries.size()
        ),
        static_cast<unsigned long long>(
            g_addIconContext.orderQueries.size()
        ),
        static_cast<unsigned long long>(
            g_addIconContext.visibleImplementations.size()
        )
    );

    AnalyzeCompletedAddIcon(
        g_addIconContext,
        after
    );

    Wh_Log(
        L"ADD_ICON_END "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p",
        callNumber,
        GetCurrentThreadId(),
        pThis
    );

    g_addIconContext =
        std::move(
            previousContext
        );
}

bool HookTaskbarSymbols(
    HMODULE taskbarModule
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
                LR"(public: unsigned int __cdecl NotifyIconSettingsDatabase::GetUIOrderForIcon(unsigned __int64))"
            },
            &NotifyIconSettingsDatabase_GetUIOrderForIcon_Original,
            NotifyIconSettingsDatabase_GetUIOrderForIcon_Hook,
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
            L"Failed to hook one or more "
            L"taskbar.dll symbols"
        );

        return false;
    }

    Wh_Log(
        L"UID path identity hooks installed"
    );

    return true;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Add Path Analyzer "
        L"0.10.0 initializing"
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
        L"orderQueries=%llu "
        L"targetResults=%llu "
        L"firstTargetIdentity=%llu",
        g_addIconCalls.load(
            std::memory_order_relaxed
        ),
        g_visibleAddCalls.load(
            std::memory_order_relaxed
        ),
        g_orderQueries.load(
            std::memory_order_relaxed
        ),
        g_targetResults.load(
            std::memory_order_relaxed
        ),
        static_cast<unsigned long long>(
            g_firstTargetIdentity.load(
                std::memory_order_relaxed
            )
        )
    );
}
