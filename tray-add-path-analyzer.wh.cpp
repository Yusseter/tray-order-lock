// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Observes tray icon creation and visible-collection insertion without modifying behavior.
// @version         0.1.0
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

It hooks:

- `NotificationAreaIconManager2::AddIcon`
- `NotificationAreaIconManager2::AddIconToVisibleCollection`

For every call, it records the `UIOrderList` state before and after the original
function, reports newly added or removed registry identities, and records the
live `NotificationAreaIcon2` implementation pointer.

The mod does not alter function arguments, return behavior, tray collections or
registry values.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <windhawk_utils.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

constexpr wchar_t kNotifyIconSettingsPath[] =
    L"Control Panel\\NotifyIconSettings";

constexpr wchar_t kUIOrderListValueName[] =
    L"UIOrderList";

constexpr std::uint64_t kFnv1aOffsetBasis =
    14695981039346656037ULL;

constexpr std::uint64_t kFnv1aPrime =
    1099511628211ULL;

using NotificationAreaIconManager_AddIcon_t =
    void(__cdecl*)(
        void* pThis,
        void* trayNotifyData
    );

using NotificationAreaIconManager_AddIconToVisibleCollection_t =
    void(__cdecl*)(
        void* pThis,
        void* iconImplementation
    );

NotificationAreaIconManager_AddIcon_t
    NotificationAreaIconManager_AddIcon_Original =
        nullptr;

NotificationAreaIconManager_AddIconToVisibleCollection_t
    NotificationAreaIconManager_AddIconToVisibleCollection_Original =
        nullptr;

std::atomic<unsigned long long> g_addIconCallCount =
    0;

std::atomic<unsigned long long> g_visibleAddCallCount =
    0;

thread_local unsigned int g_addIconDepth =
    0;

thread_local unsigned long long g_activeAddIconCall =
    0;

struct UIOrderSnapshot {
    LONG status =
        ERROR_SUCCESS;

    DWORD registryType =
        REG_NONE;

    std::vector<std::uint64_t> entries;

    std::uint64_t hash =
        0;

    bool valid =
        false;
};

std::uint64_t CalculateFnv1aHash(
    const BYTE* data,
    DWORD length
) {
    std::uint64_t hash =
        kFnv1aOffsetBasis;

    for (
        DWORD index = 0;
        index < length;
        index++
    ) {
        hash ^=
            data[index];

        hash *=
            kFnv1aPrime;
    }

    return hash;
}

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

        if (
            status != ERROR_SUCCESS
        ) {
            snapshot.status =
                status;

            snapshot.registryType =
                registryType;

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

        if (
            status == ERROR_MORE_DATA
        ) {
            continue;
        }

        snapshot.status =
            status;

        snapshot.registryType =
            registryType;

        if (
            status != ERROR_SUCCESS
        ) {
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

        data.resize(
            actualBytes
        );

        snapshot.entries.resize(
            actualBytes /
            sizeof(std::uint64_t)
        );

        if (
            actualBytes != 0
        ) {
            std::memcpy(
                snapshot.entries.data(),
                data.data(),
                actualBytes
            );
        }

        snapshot.hash =
            CalculateFnv1aHash(
                data.empty()
                    ? nullptr
                    : data.data(),
                actualBytes
            );

        snapshot.valid =
            true;

        return snapshot;
    }

    snapshot.status =
        ERROR_MORE_DATA;

    return snapshot;
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

    if (
        status != ERROR_SUCCESS
    ) {
        return L"";
    }

    buffer.back() =
        L'\0';

    std::wstring result(
        buffer.data()
    );

    for (
        wchar_t& character :
        result
    ) {
        if (
            character == L'\r' ||
            character == L'\n' ||
            character == L'\t'
        ) {
            character =
                L' ';
        } else if (
            character == L'"'
        ) {
            character =
                L'\'';
        }
    }

    return result;
}

bool QueryDwordValue(
    const std::wstring& subkey,
    const wchar_t* valueName,
    DWORD& value
) {
    value =
        0;

    DWORD registryType =
        REG_NONE;

    DWORD valueSize =
        sizeof(value);

    const LONG status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            valueName,
            RRF_RT_REG_DWORD,
            &registryType,
            &value,
            &valueSize
        );

    return
        status ==
        ERROR_SUCCESS;
}

void LogTrayEntry(
    const wchar_t* change,
    const wchar_t* source,
    unsigned long long sourceCall,
    std::uint64_t identity,
    unsigned long long position
) {
    const std::wstring subkey =
        MakeTrayEntrySubkey(
            identity
        );

    const std::wstring executablePath =
        QueryStringValue(
            subkey,
            L"ExecutablePath"
        );

    const std::wstring iconGuid =
        QueryStringValue(
            subkey,
            L"IconGuid"
        );

    DWORD uid =
        0;

    const bool uidPresent =
        QueryDwordValue(
            subkey,
            L"UID",
            uid
        );

    DWORD isPromoted =
        0;

    const bool isPromotedPresent =
        QueryDwordValue(
            subkey,
            L"IsPromoted",
            isPromoted
        );

    Wh_Log(
        L"TRAY_ENTRY "
        L"change=%s "
        L"source=%s "
        L"sourceCall=%llu "
        L"id=%llu "
        L"position=%llu "
        L"path=\"%s\" "
        L"uidPresent=%d "
        L"uid=%lu "
        L"guid=\"%s\" "
        L"isPromotedPresent=%d "
        L"isPromoted=%lu",
        change,
        source,
        sourceCall,
        static_cast<unsigned long long>(
            identity
        ),
        position,
        executablePath.c_str(),
        uidPresent
            ? 1
            : 0,
        uid,
        iconGuid.c_str(),
        isPromotedPresent
            ? 1
            : 0,
        isPromoted
    );
}

void LogSnapshot(
    const wchar_t* phase,
    const wchar_t* source,
    unsigned long long sourceCall,
    const UIOrderSnapshot& snapshot
) {
    const unsigned long long firstIdentity =
        snapshot.entries.empty()
            ? 0
            : static_cast<unsigned long long>(
                  snapshot.entries.front()
              );

    const unsigned long long lastIdentity =
        snapshot.entries.empty()
            ? 0
            : static_cast<unsigned long long>(
                  snapshot.entries.back()
              );

    Wh_Log(
        L"UIORDER_SNAPSHOT "
        L"phase=%s "
        L"source=%s "
        L"sourceCall=%llu "
        L"valid=%d "
        L"status=%ld "
        L"type=%lu "
        L"count=%llu "
        L"hash=0x%016llX "
        L"first=%llu "
        L"last=%llu",
        phase,
        source,
        sourceCall,
        snapshot.valid
            ? 1
            : 0,
        snapshot.status,
        snapshot.registryType,
        static_cast<unsigned long long>(
            snapshot.entries.size()
        ),
        static_cast<unsigned long long>(
            snapshot.hash
        ),
        firstIdentity,
        lastIdentity
    );
}

void LogOrderDelta(
    const wchar_t* source,
    unsigned long long sourceCall,
    const UIOrderSnapshot& before,
    const UIOrderSnapshot& after
) {
    if (
        !before.valid ||
        !after.valid
    ) {
        Wh_Log(
            L"ORDER_DELTA "
            L"source=%s "
            L"sourceCall=%llu "
            L"valid=0 "
            L"beforeStatus=%ld "
            L"afterStatus=%ld",
            source,
            sourceCall,
            before.status,
            after.status
        );

        return;
    }

    const std::unordered_set<std::uint64_t>
        beforeSet(
            before.entries.begin(),
            before.entries.end()
        );

    const std::unordered_set<std::uint64_t>
        afterSet(
            after.entries.begin(),
            after.entries.end()
        );

    std::vector<std::uint64_t> addedEntries;
    std::vector<std::uint64_t> removedEntries;

    for (
        const std::uint64_t identity :
        after.entries
    ) {
        if (
            beforeSet.find(
                identity
            ) ==
            beforeSet.end()
        ) {
            addedEntries.push_back(
                identity
            );
        }
    }

    for (
        const std::uint64_t identity :
        before.entries
    ) {
        if (
            afterSet.find(
                identity
            ) ==
            afterSet.end()
        ) {
            removedEntries.push_back(
                identity
            );
        }
    }

    long long firstDifference =
        -1;

    const std::size_t commonCount =
        std::min(
            before.entries.size(),
            after.entries.size()
        );

    for (
        std::size_t index = 0;
        index < commonCount;
        index++
    ) {
        if (
            before.entries[index] !=
            after.entries[index]
        ) {
            firstDifference =
                static_cast<long long>(
                    index
                );

            break;
        }
    }

    if (
        firstDifference < 0 &&
        before.entries.size() !=
            after.entries.size()
    ) {
        firstDifference =
            static_cast<long long>(
                commonCount
            );
    }

    const bool changed =
        before.entries !=
        after.entries;

    Wh_Log(
        L"ORDER_DELTA "
        L"source=%s "
        L"sourceCall=%llu "
        L"valid=1 "
        L"changed=%d "
        L"beforeCount=%llu "
        L"afterCount=%llu "
        L"added=%llu "
        L"removed=%llu "
        L"firstDifferenceZeroBased=%lld",
        source,
        sourceCall,
        changed
            ? 1
            : 0,
        static_cast<unsigned long long>(
            before.entries.size()
        ),
        static_cast<unsigned long long>(
            after.entries.size()
        ),
        static_cast<unsigned long long>(
            addedEntries.size()
        ),
        static_cast<unsigned long long>(
            removedEntries.size()
        ),
        firstDifference
    );

    for (
        const std::uint64_t identity :
        addedEntries
    ) {
        LogTrayEntry(
            L"added",
            source,
            sourceCall,
            identity,
            FindOneBasedPosition(
                after,
                identity
            )
        );
    }

    for (
        const std::uint64_t identity :
        removedEntries
    ) {
        LogTrayEntry(
            L"removed",
            source,
            sourceCall,
            identity,
            FindOneBasedPosition(
                before,
                identity
            )
        );
    }
}

void __cdecl NotificationAreaIconManager_AddIcon_Hook(
    void* pThis,
    void* trayNotifyData
) {
    const unsigned long long callNumber =
        g_addIconCallCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    const DWORD threadId =
        GetCurrentThreadId();

    const UIOrderSnapshot before =
        CaptureUIOrderSnapshot();

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
        threadId,
        pThis,
        trayNotifyData,
        g_addIconDepth
    );

    LogSnapshot(
        L"before",
        L"AddIcon",
        callNumber,
        before
    );

    NotificationAreaIconManager_AddIcon_Original(
        pThis,
        trayNotifyData
    );

    const UIOrderSnapshot after =
        CaptureUIOrderSnapshot();

    LogSnapshot(
        L"after",
        L"AddIcon",
        callNumber,
        after
    );

    LogOrderDelta(
        L"AddIcon",
        callNumber,
        before,
        after
    );

    Wh_Log(
        L"ADD_ICON_END "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"depth=%u",
        callNumber,
        threadId,
        pThis,
        g_addIconDepth
    );

    g_addIconDepth--;

    g_activeAddIconCall =
        previousActiveCall;
}

void __cdecl
NotificationAreaIconManager_AddIconToVisibleCollection_Hook(
    void* pThis,
    void* iconImplementation
) {
    const unsigned long long callNumber =
        g_visibleAddCallCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    const DWORD threadId =
        GetCurrentThreadId();

    const bool duringAddIcon =
        g_addIconDepth !=
        0;

    const unsigned long long parentAddCall =
        g_activeAddIconCall;

    const UIOrderSnapshot before =
        CaptureUIOrderSnapshot();

    Wh_Log(
        L"VISIBLE_ADD_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"iconImplementation=%p "
        L"duringAddIcon=%d "
        L"parentAddCall=%llu",
        callNumber,
        threadId,
        pThis,
        iconImplementation,
        duringAddIcon
            ? 1
            : 0,
        parentAddCall
    );

    LogSnapshot(
        L"before",
        L"AddIconToVisibleCollection",
        callNumber,
        before
    );

    NotificationAreaIconManager_AddIconToVisibleCollection_Original(
        pThis,
        iconImplementation
    );

    const UIOrderSnapshot after =
        CaptureUIOrderSnapshot();

    LogSnapshot(
        L"after",
        L"AddIconToVisibleCollection",
        callNumber,
        after
    );

    LogOrderDelta(
        L"AddIconToVisibleCollection",
        callNumber,
        before,
        after
    );

    Wh_Log(
        L"VISIBLE_ADD_END "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"iconImplementation=%p "
        L"duringAddIcon=%d "
        L"parentAddCall=%llu",
        callNumber,
        threadId,
        pThis,
        iconImplementation,
        duringAddIcon
            ? 1
            : 0,
        parentAddCall
    );
}

bool LogModuleInformation(
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
            L"TASKBAR_MODULE "
            L"address=%p "
            L"path=\"<unavailable>\"",
            module
        );

        return false;
    }

    Wh_Log(
        L"TASKBAR_MODULE "
        L"address=%p "
        L"path=\"%s\"",
        module,
        modulePath
    );

    return true;
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
            &NotificationAreaIconManager_AddIconToVisibleCollection_Original,
            NotificationAreaIconManager_AddIconToVisibleCollection_Hook,
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
            L"Failed to hook taskbar.dll symbols"
        );

        return false;
    }

    Wh_Log(
        L"Tray add-path hooks installed"
    );

    return true;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Add Path Analyzer "
        L"0.1.0 initializing"
    );

    HMODULE taskbarModule =
        GetModuleHandleW(
            L"taskbar.dll"
        );

    if (
        !taskbarModule
    ) {
        Wh_Log(
            L"taskbar.dll is not loaded"
        );

        return FALSE;
    }

    LogModuleInformation(
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
        L"addIconCalls=%llu "
        L"visibleAddCalls=%llu",
        g_addIconCallCount.load(
            std::memory_order_relaxed
        ),
        g_visibleAddCallCount.load(
            std::memory_order_relaxed
        )
    );
}
