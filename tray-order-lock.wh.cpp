// ==WindhawkMod==
// @id              tray-order-lock
// @name            Tray Order Lock
// @description     Preserves Windows 11 notification-area icon ordering while allowing configurable manual reordering.
// @version         0.2.0
// @author          Yusseter
// @github          https://github.com/Yusseter
// @homepage        https://github.com/Yusseter/tray-order-lock
// @license         MIT
// @include         explorer.exe
// @architecture    x86-64
// @compilerOptions -ladvapi32 -lole32
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# Tray Order Lock

Controls Windows 11 notification-area icon ordering.

Version 0.2.0 is currently under development.

This checkpoint provides two ordering behaviors:

- Lock all reordering:
  preserves the 0.1.0 behavior and blocks tray move requests.
- Preserve order, allow manual changes:
  allows Windows to perform the user's tray move, detects the Windows identity
  which actually moved, converts it to a logical tray identity, updates the
  canonical relation and persists the result in Windhawk local storage.

Logical identity currently uses:

- IconGuid when available.
- Otherwise, version-normalized executable path plus UID.

Ambiguous or unsupported identities are not learned automatically.

The persisted canonical order survives a complete Explorer process restart.

Automatic restoration of replacement identities is intentionally not enabled
in this development checkpoint. It will be added after the production
canonical-state path is validated.
*/
// ==/WindhawkModReadme==

// ==WindhawkModSettings==
/*
- orderingBehavior: lockAll
  $name: Ordering behavior
  $options:
    - lockAll: Lock all reordering
    - preserveManual: Preserve order, allow manual changes
*/
// ==/WindhawkModSettings==

#include <windows.h>
#include <objbase.h>
#include <windhawk_utils.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr wchar_t kNotifyIconSettingsPath[] =
    L"Control Panel\\NotifyIconSettings";

constexpr wchar_t kUIOrderListValueName[] =
    L"UIOrderList";

constexpr wchar_t kCanonicalOrderValueName[] =
    L"CanonicalOrderV200";

constexpr wchar_t kCanonicalStorageHeader[] =
    L"TRAY_ORDER_LOCK_V200";

constexpr std::size_t kMaximumStoredOrderChars =
    262144;

enum class OrderingBehavior {
    LockAll = 0,
    PreserveManual = 1,
};

struct UIOrderSnapshot {
    bool valid = false;
    LONG status = ERROR_SUCCESS;

    std::vector<std::uint64_t> entries;
};

struct LogicalSnapshotEntry {
    std::uint64_t identity = 0;

    std::wstring key;

    bool unique =
        false;
};

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

std::atomic<int> g_orderingBehavior =
    static_cast<int>(
        OrderingBehavior::LockAll
    );

std::atomic<unsigned long long> g_blockedMoveCount =
    0;

std::atomic<unsigned long long> g_allowedMoveCount =
    0;

std::atomic<unsigned long long> g_learnedMoveCount =
    0;

std::atomic<unsigned long long> g_skippedLearningCount =
    0;

std::mutex g_canonicalMutex;

std::vector<std::wstring> g_canonicalOrder;

bool g_canonicalLoadedFromStorage =
    false;

std::wstring ToLower(
    std::wstring value
) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](
            wchar_t character
        ) {
            return
                static_cast<wchar_t>(
                    std::towlower(
                        character
                    )
                );
        }
    );

    return value;
}

std::wstring NormalizeSlashes(
    std::wstring path
) {
    std::replace(
        path.begin(),
        path.end(),
        L'/',
        L'\\'
    );

    return path;
}

bool StartsWithOrdinalIgnoreCase(
    const std::wstring& value,
    const std::wstring& prefix
) {
    if (
        value.size() <
        prefix.size()
    ) {
        return false;
    }

    for (
        std::size_t index = 0;
        index <
            prefix.size();
        index++
    ) {
        if (
            std::towlower(
                value[index]
            ) !=
            std::towlower(
                prefix[index]
            )
        ) {
            return false;
        }
    }

    return true;
}

bool IsNumericDottedVersionCore(
    const std::wstring& value
) {
    if (
        value.empty()
    ) {
        return false;
    }

    bool digitSeen =
        false;

    bool dotSeen =
        false;

    for (
        wchar_t character :
        value
    ) {
        if (
            character >=
                L'0' &&
            character <=
                L'9'
        ) {
            digitSeen =
                true;

            continue;
        }

        if (
            character ==
            L'.'
        ) {
            dotSeen =
                true;

            continue;
        }

        return false;
    }

    return
        digitSeen &&
        dotSeen;
}

bool LooksLikeVersionDirectory(
    std::wstring candidate
) {
    candidate =
        ToLower(
            candidate
        );

    if (
        StartsWithOrdinalIgnoreCase(
            candidate,
            L"app-"
        )
    ) {
        candidate.erase(
            0,
            4
        );
    } else if (
        StartsWithOrdinalIgnoreCase(
            candidate,
            L"version-"
        )
    ) {
        candidate.erase(
            0,
            8
        );
    } else if (
        candidate.size() >=
            2 &&
        candidate[0] ==
            L'v' &&
        candidate[1] >=
            L'0' &&
        candidate[1] <=
            L'9'
    ) {
        candidate.erase(
            0,
            1
        );
    }

    return
        IsNumericDottedVersionCore(
            candidate
        );
}

std::wstring BuildVersionNormalizedPath(
    const std::wstring& executablePath
) {
    const std::wstring path =
        ToLower(
            NormalizeSlashes(
                executablePath
            )
        );

    if (
        path.empty()
    ) {
        return path;
    }

    std::wstring result;

    std::size_t segmentStart =
        0;

    bool firstSegment =
        true;

    while (
        segmentStart <=
        path.size()
    ) {
        const std::size_t separator =
            path.find(
                L'\\',
                segmentStart
            );

        const std::size_t segmentEnd =
            separator ==
                    std::wstring::npos
                ? path.size()
                : separator;

        const std::wstring segment =
            path.substr(
                segmentStart,
                segmentEnd -
                    segmentStart
            );

        if (
            !firstSegment
        ) {
            result +=
                L'\\';
        }

        const bool isLastSegment =
            separator ==
            std::wstring::npos;

        if (
            !isLastSegment &&
            LooksLikeVersionDirectory(
                segment
            )
        ) {
            result +=
                L"<version>";
        } else {
            result +=
                segment;
        }

        firstSegment =
            false;

        if (
            separator ==
            std::wstring::npos
        ) {
            break;
        }

        segmentStart =
            separator +
            1;
    }

    return result;
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
        status !=
            ERROR_SUCCESS ||
        requiredBytes ==
            0
    ) {
        return L"";
    }

    std::vector<wchar_t> buffer(
        requiredBytes /
                sizeof(
                    wchar_t
                ) +
            1,
        L'\0'
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
        status !=
        ERROR_SUCCESS
    ) {
        return L"";
    }

    buffer.back() =
        L'\0';

    return
        std::wstring(
            buffer.data()
        );
}

bool QueryDwordValue(
    const std::wstring& subkey,
    const wchar_t* valueName,
    DWORD* value
) {
    if (
        !value
    ) {
        return false;
    }

    DWORD registryType =
        REG_NONE;

    DWORD result =
        0;

    DWORD resultBytes =
        sizeof(
            result
        );

    const LONG status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            valueName,
            RRF_RT_REG_DWORD,
            &registryType,
            &result,
            &resultBytes
        );

    if (
        status !=
            ERROR_SUCCESS ||
        registryType !=
            REG_DWORD ||
        resultBytes !=
            sizeof(
                result
            )
    ) {
        return false;
    }

    *value =
        result;

    return true;
}

bool QueryIconGuid(
    const std::wstring& subkey,
    std::wstring* guidText
) {
    if (
        !guidText
    ) {
        return false;
    }

    guidText->clear();

    DWORD registryType =
        REG_NONE;

    DWORD requiredBytes =
        0;

    LONG status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            L"IconGuid",
            RRF_RT_ANY,
            &registryType,
            nullptr,
            &requiredBytes
        );

    if (
        status !=
            ERROR_SUCCESS ||
        requiredBytes ==
            0
    ) {
        return false;
    }

    if (
        registryType ==
            REG_SZ ||
        registryType ==
            REG_EXPAND_SZ
    ) {
        *guidText =
            QueryStringValue(
                subkey,
                L"IconGuid"
            );

        if (
            guidText->empty()
        ) {
            return false;
        }

        *guidText =
            ToLower(
                *guidText
            );

        return true;
    }

    if (
        registryType !=
            REG_BINARY ||
        requiredBytes !=
            sizeof(
                GUID
            )
    ) {
        return false;
    }

    GUID guid{};

    DWORD actualBytes =
        sizeof(
            guid
        );

    status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            L"IconGuid",
            RRF_RT_REG_BINARY,
            &registryType,
            &guid,
            &actualBytes
        );

    if (
        status !=
            ERROR_SUCCESS ||
        actualBytes !=
            sizeof(
                guid
            )
    ) {
        return false;
    }

    wchar_t buffer[
        64
    ]{};

    if (
        StringFromGUID2(
            guid,
            buffer,
            ARRAYSIZE(
                buffer
            )
        ) ==
        0
    ) {
        return false;
    }

    *guidText =
        ToLower(
            buffer
        );

    return true;
}

std::wstring BuildLogicalKey(
    std::uint64_t identity
) {
    const std::wstring subkey =
        MakeTrayEntrySubkey(
            identity
        );

    std::wstring iconGuid;

    if (
        QueryIconGuid(
            subkey,
            &iconGuid
        )
    ) {
        return
            L"guid:" +
            iconGuid;
    }

    const std::wstring executablePath =
        QueryStringValue(
            subkey,
            L"ExecutablePath"
        );

    if (
        executablePath.empty()
    ) {
        return L"";
    }

    DWORD uid =
        0;

    if (
        !QueryDwordValue(
            subkey,
            L"UID",
            &uid
        )
    ) {
        return L"";
    }

    const std::wstring normalizedPath =
        BuildVersionNormalizedPath(
            executablePath
        );

    if (
        normalizedPath.empty()
    ) {
        return L"";
    }

    return
        L"uid:" +
        std::to_wstring(
            static_cast<unsigned long long>(
                uid
            )
        ) +
        L"|path:" +
        normalizedPath;
}

UIOrderSnapshot CaptureUIOrderSnapshot() {
    UIOrderSnapshot snapshot;

    for (
        int attempt = 0;
        attempt <
            3;
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

        if (
            status !=
            ERROR_SUCCESS
        ) {
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
            status ==
            ERROR_MORE_DATA
        ) {
            continue;
        }

        snapshot.status =
            status;

        if (
            status !=
            ERROR_SUCCESS
        ) {
            return snapshot;
        }

        if (
            actualBytes %
                sizeof(
                    std::uint64_t
                ) !=
            0
        ) {
            snapshot.status =
                ERROR_INVALID_DATA;

            return snapshot;
        }

        snapshot.entries.resize(
            actualBytes /
            sizeof(
                std::uint64_t
            )
        );

        if (
            actualBytes !=
            0
        ) {
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

std::vector<LogicalSnapshotEntry>
BuildLogicalSnapshot(
    const UIOrderSnapshot& snapshot
) {
    std::vector<LogicalSnapshotEntry>
        result;

    if (
        !snapshot.valid
    ) {
        return result;
    }

    result.reserve(
        snapshot.entries.size()
    );

    for (
        std::uint64_t identity :
        snapshot.entries
    ) {
        LogicalSnapshotEntry entry;

        entry.identity =
            identity;

        entry.key =
            BuildLogicalKey(
                identity
            );

        result.push_back(
            std::move(
                entry
            )
        );
    }

    for (
        std::size_t index = 0;
        index <
            result.size();
        index++
    ) {
        if (
            result[index].key.empty()
        ) {
            continue;
        }

        unsigned int occurrences =
            0;

        for (
            const LogicalSnapshotEntry& candidate :
            result
        ) {
            if (
                candidate.key ==
                result[index].key
            ) {
                occurrences++;
            }
        }

        result[index].unique =
            occurrences ==
            1;
    }

    return result;
}

bool ContainsCanonicalKeyLocked(
    const std::wstring& key
) {
    return
        std::find(
            g_canonicalOrder.begin(),
            g_canonicalOrder.end(),
            key
        ) !=
        g_canonicalOrder.end();
}

std::wstring SerializeCanonicalOrderLocked() {
    std::wstring serialized =
        kCanonicalStorageHeader;

    serialized +=
        L'\n';

    for (
        const std::wstring& key :
        g_canonicalOrder
    ) {
        serialized +=
            key;

        serialized +=
            L'\n';
    }

    return serialized;
}

bool PersistCanonicalOrderLocked() {
    const std::wstring serialized =
        SerializeCanonicalOrderLocked();

    const BOOL succeeded =
        Wh_SetStringValue(
            kCanonicalOrderValueName,
            serialized.c_str()
        );

    Wh_Log(
        L"TRAY_ORDER_LOCK_CANONICAL_WRITE "
        L"succeeded=%d "
        L"entries=%llu "
        L"chars=%llu",
        succeeded
            ? 1
            : 0,
        static_cast<unsigned long long>(
            g_canonicalOrder.size()
        ),
        static_cast<unsigned long long>(
            serialized.size()
        )
    );

    return
        succeeded !=
        FALSE;
}

bool LoadCanonicalOrderLocked() {
    std::vector<wchar_t> buffer(
        kMaximumStoredOrderChars,
        L'\0'
    );

    const std::size_t length =
        Wh_GetStringValue(
            kCanonicalOrderValueName,
            buffer.data(),
            buffer.size()
        );

    if (
        length ==
        0
    ) {
        return false;
    }

    const std::wstring serialized(
        buffer.data(),
        length
    );

    const std::wstring expectedPrefix =
        std::wstring(
            kCanonicalStorageHeader
        ) +
        L'\n';

    if (
        serialized.size() <
            expectedPrefix.size() ||
        serialized.compare(
            0,
            expectedPrefix.size(),
            expectedPrefix
        ) !=
            0
    ) {
        return false;
    }

    std::vector<std::wstring> loaded;

    std::size_t lineStart =
        expectedPrefix.size();

    while (
        lineStart <
        serialized.size()
    ) {
        const std::size_t lineEnd =
            serialized.find(
                L'\n',
                lineStart
            );

        const std::size_t end =
            lineEnd ==
                    std::wstring::npos
                ? serialized.size()
                : lineEnd;

        const std::wstring key =
            serialized.substr(
                lineStart,
                end -
                    lineStart
            );

        if (
            !key.empty() &&
            std::find(
                loaded.begin(),
                loaded.end(),
                key
            ) ==
                loaded.end()
        ) {
            loaded.push_back(
                key
            );
        }

        if (
            lineEnd ==
            std::wstring::npos
        ) {
            break;
        }

        lineStart =
            lineEnd +
            1;
    }

    if (
        loaded.empty()
    ) {
        return false;
    }

    g_canonicalOrder =
        std::move(
            loaded
        );

    return true;
}

unsigned int MergeLiveKeysLocked(
    const std::vector<LogicalSnapshotEntry>& logicalSnapshot
) {
    unsigned int added =
        0;

    for (
        const LogicalSnapshotEntry& entry :
        logicalSnapshot
    ) {
        if (
            !entry.unique ||
            entry.key.empty()
        ) {
            continue;
        }

        if (
            ContainsCanonicalKeyLocked(
                entry.key
            )
        ) {
            continue;
        }

        g_canonicalOrder.push_back(
            entry.key
        );

        added++;
    }

    return added;
}

void InitializeCanonicalState() {
    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    if (
        !snapshot.valid
    ) {
        Wh_Log(
            L"TRAY_ORDER_LOCK_CANONICAL_INIT_SKIPPED "
            L"reason=\"invalid-ui-order\" "
            L"status=%ld",
            snapshot.status
        );

        return;
    }

    const std::vector<LogicalSnapshotEntry>
        logicalSnapshot =
            BuildLogicalSnapshot(
                snapshot
            );

    std::lock_guard<std::mutex> lock(
        g_canonicalMutex
    );

    const bool loaded =
        LoadCanonicalOrderLocked();

    g_canonicalLoadedFromStorage =
        loaded;

    if (
        !loaded
    ) {
        g_canonicalOrder.clear();

        MergeLiveKeysLocked(
            logicalSnapshot
        );

        const bool persisted =
            !g_canonicalOrder.empty() &&
            PersistCanonicalOrderLocked();

        Wh_Log(
            L"TRAY_ORDER_LOCK_CANONICAL_INIT "
            L"loaded=0 "
            L"uiOrderEntries=%llu "
            L"canonicalEntries=%llu "
            L"persisted=%d",
            static_cast<unsigned long long>(
                snapshot.entries.size()
            ),
            static_cast<unsigned long long>(
                g_canonicalOrder.size()
            ),
            persisted
                ? 1
                : 0
        );

        return;
    }

    const unsigned int merged =
        MergeLiveKeysLocked(
            logicalSnapshot
        );

    bool persisted =
        true;

    if (
        merged !=
        0
    ) {
        persisted =
            PersistCanonicalOrderLocked();
    }

    Wh_Log(
        L"TRAY_ORDER_LOCK_CANONICAL_LOAD "
        L"loaded=1 "
        L"uiOrderEntries=%llu "
        L"canonicalEntries=%llu "
        L"newLiveKeys=%u "
        L"persisted=%d",
        static_cast<unsigned long long>(
            snapshot.entries.size()
        ),
        static_cast<unsigned long long>(
            g_canonicalOrder.size()
        ),
        merged,
        persisted
            ? 1
            : 0
    );
}

std::vector<std::uint64_t>
WithoutIdentity(
    const std::vector<std::uint64_t>& values,
    std::uint64_t identity
) {
    std::vector<std::uint64_t> result;

    result.reserve(
        values.size()
    );

    for (
        std::uint64_t value :
        values
    ) {
        if (
            value !=
            identity
        ) {
            result.push_back(
                value
            );
        }
    }

    return result;
}

std::uint64_t FindSingleMovedIdentity(
    const UIOrderSnapshot& before,
    const UIOrderSnapshot& after
) {
    if (
        !before.valid ||
        !after.valid ||
        before.entries.size() !=
            after.entries.size() ||
        before.entries ==
            after.entries
    ) {
        return 0;
    }

    std::uint64_t selected =
        0;

    unsigned int matches =
        0;

    for (
        std::uint64_t candidate :
        before.entries
    ) {
        const auto beforePosition =
            std::find(
                before.entries.begin(),
                before.entries.end(),
                candidate
            );

        const auto afterPosition =
            std::find(
                after.entries.begin(),
                after.entries.end(),
                candidate
            );

        if (
            afterPosition ==
            after.entries.end()
        ) {
            return 0;
        }

        if (
            std::distance(
                before.entries.begin(),
                beforePosition
            ) ==
            std::distance(
                after.entries.begin(),
                afterPosition
            )
        ) {
            continue;
        }

        const std::vector<std::uint64_t>
            beforeWithout =
                WithoutIdentity(
                    before.entries,
                    candidate
                );

        const std::vector<std::uint64_t>
            afterWithout =
                WithoutIdentity(
                    after.entries,
                    candidate
                );

        if (
            beforeWithout ==
            afterWithout
        ) {
            selected =
                candidate;

            matches++;
        }
    }

    return
        matches ==
                1
            ? selected
            : 0;
}

const LogicalSnapshotEntry*
FindLogicalEntry(
    const std::vector<LogicalSnapshotEntry>& entries,
    std::uint64_t identity
) {
    for (
        const LogicalSnapshotEntry& entry :
        entries
    ) {
        if (
            entry.identity ==
            identity
        ) {
            return
                &entry;
        }
    }

    return nullptr;
}

void LearnManualMove(
    const UIOrderSnapshot& before,
    const UIOrderSnapshot& after,
    int location,
    unsigned int requestedIndex
) {
    const std::uint64_t movedIdentity =
        FindSingleMovedIdentity(
            before,
            after
        );

    if (
        movedIdentity ==
        0
    ) {
        const unsigned long long skipped =
            g_skippedLearningCount.fetch_add(
                1,
                std::memory_order_relaxed
            ) +
            1;

        Wh_Log(
            L"TRAY_ORDER_LOCK_MANUAL_LEARN_SKIPPED "
            L"skip=%llu "
            L"reason=\"single-moved-identity-not-resolved\" "
            L"location=%d "
            L"requestedIndex=%u",
            skipped,
            location,
            requestedIndex
        );

        return;
    }

    const std::vector<LogicalSnapshotEntry>
        logicalAfter =
            BuildLogicalSnapshot(
                after
            );

    const LogicalSnapshotEntry* movedEntry =
        FindLogicalEntry(
            logicalAfter,
            movedIdentity
        );

    if (
        !movedEntry ||
        !movedEntry->unique ||
        movedEntry->key.empty()
    ) {
        const unsigned long long skipped =
            g_skippedLearningCount.fetch_add(
                1,
                std::memory_order_relaxed
            ) +
            1;

        Wh_Log(
            L"TRAY_ORDER_LOCK_MANUAL_LEARN_SKIPPED "
            L"skip=%llu "
            L"reason=\"logical-identity-not-unique\" "
            L"identity=%llu",
            skipped,
            static_cast<unsigned long long>(
                movedIdentity
            )
        );

        return;
    }

    std::size_t movedIndex =
        logicalAfter.size();

    for (
        std::size_t index = 0;
        index <
            logicalAfter.size();
        index++
    ) {
        if (
            logicalAfter[index].identity ==
            movedIdentity
        ) {
            movedIndex =
                index;

            break;
        }
    }

    if (
        movedIndex ==
        logicalAfter.size()
    ) {
        return;
    }

    std::wstring precedingKey;
    std::wstring followingKey;

    for (
        std::size_t index = movedIndex;
        index >
            0;
        index--
    ) {
        const LogicalSnapshotEntry& candidate =
            logicalAfter[
                index -
                1
            ];

        if (
            candidate.unique &&
            !candidate.key.empty()
        ) {
            precedingKey =
                candidate.key;

            break;
        }
    }

    for (
        std::size_t index =
            movedIndex +
            1;
        index <
            logicalAfter.size();
        index++
    ) {
        const LogicalSnapshotEntry& candidate =
            logicalAfter[index];

        if (
            candidate.unique &&
            !candidate.key.empty()
        ) {
            followingKey =
                candidate.key;

            break;
        }
    }

    if (
        precedingKey.empty() &&
        followingKey.empty()
    ) {
        const unsigned long long skipped =
            g_skippedLearningCount.fetch_add(
                1,
                std::memory_order_relaxed
            ) +
            1;

        Wh_Log(
            L"TRAY_ORDER_LOCK_MANUAL_LEARN_SKIPPED "
            L"skip=%llu "
            L"reason=\"no-reliable-logical-neighbor\" "
            L"identity=%llu",
            skipped,
            static_cast<unsigned long long>(
                movedIdentity
            )
        );

        return;
    }

    std::lock_guard<std::mutex> lock(
        g_canonicalMutex
    );

    MergeLiveKeysLocked(
        logicalAfter
    );

    auto movedIterator =
        std::find(
            g_canonicalOrder.begin(),
            g_canonicalOrder.end(),
            movedEntry->key
        );

    if (
        movedIterator !=
        g_canonicalOrder.end()
    ) {
        g_canonicalOrder.erase(
            movedIterator
        );
    }

    bool relationApplied =
        false;

    if (
        !precedingKey.empty()
    ) {
        auto precedingIterator =
            std::find(
                g_canonicalOrder.begin(),
                g_canonicalOrder.end(),
                precedingKey
            );

        if (
            precedingIterator !=
            g_canonicalOrder.end()
        ) {
            g_canonicalOrder.insert(
                std::next(
                    precedingIterator
                ),
                movedEntry->key
            );

            relationApplied =
                true;
        }
    }

    if (
        !relationApplied &&
        !followingKey.empty()
    ) {
        auto followingIterator =
            std::find(
                g_canonicalOrder.begin(),
                g_canonicalOrder.end(),
                followingKey
            );

        if (
            followingIterator !=
            g_canonicalOrder.end()
        ) {
            g_canonicalOrder.insert(
                followingIterator,
                movedEntry->key
            );

            relationApplied =
                true;
        }
    }

    if (
        !relationApplied
    ) {
        const unsigned long long skipped =
            g_skippedLearningCount.fetch_add(
                1,
                std::memory_order_relaxed
            ) +
            1;

        Wh_Log(
            L"TRAY_ORDER_LOCK_MANUAL_LEARN_SKIPPED "
            L"skip=%llu "
            L"reason=\"canonical-neighbor-not-found\" "
            L"identity=%llu",
            skipped,
            static_cast<unsigned long long>(
                movedIdentity
            )
        );

        return;
    }

    const bool persisted =
        PersistCanonicalOrderLocked();

    const unsigned long long learned =
        g_learnedMoveCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    Wh_Log(
        L"TRAY_ORDER_LOCK_MANUAL_MOVE_LEARNED "
        L"learned=%llu "
        L"identity=%llu "
        L"precedingFound=%d "
        L"followingFound=%d "
        L"canonicalEntries=%llu "
        L"persisted=%d "
        L"location=%d "
        L"requestedIndex=%u",
        learned,
        static_cast<unsigned long long>(
            movedIdentity
        ),
        precedingKey.empty()
            ? 0
            : 1,
        followingKey.empty()
            ? 0
            : 1,
        static_cast<unsigned long long>(
            g_canonicalOrder.size()
        ),
        persisted
            ? 1
            : 0,
        location,
        requestedIndex
    );
}

OrderingBehavior GetOrderingBehavior() {
    return
        static_cast<OrderingBehavior>(
            g_orderingBehavior.load(
                std::memory_order_acquire
            )
        );
}

void LoadSettings() {
    PCWSTR setting =
        Wh_GetStringSetting(
            L"orderingBehavior"
        );

    OrderingBehavior behavior =
        OrderingBehavior::LockAll;

    if (
        setting &&
        _wcsicmp(
            setting,
            L"preserveManual"
        ) ==
            0
    ) {
        behavior =
            OrderingBehavior::PreserveManual;
    }

    Wh_FreeStringSetting(
        setting
    );

    g_orderingBehavior.store(
        static_cast<int>(
            behavior
        ),
        std::memory_order_release
    );

    Wh_Log(
        L"TRAY_ORDER_LOCK_SETTINGS "
        L"orderingBehavior=%s",
        behavior ==
                OrderingBehavior::PreserveManual
            ? L"preserveManual"
            : L"lockAll"
    );
}

int __cdecl
TaskbarModel_MoveNotificationAreaIcon_Hook(
    void* pThis,
    void* notificationAreaIconAbi,
    int location,
    unsigned int index
) {
    if (
        GetOrderingBehavior() ==
        OrderingBehavior::LockAll
    ) {
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

    const UIOrderSnapshot before =
        CaptureUIOrderSnapshot();

    const unsigned long long moveNumber =
        g_allowedMoveCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    Wh_Log(
        L"TRAY_ORDER_LOCK_MOVE_ALLOWED "
        L"move=%llu "
        L"iconAbi=%p "
        L"location=%d "
        L"index=%u "
        L"beforeValid=%d "
        L"beforeEntries=%llu",
        moveNumber,
        notificationAreaIconAbi,
        location,
        index,
        before.valid
            ? 1
            : 0,
        static_cast<unsigned long long>(
            before.entries.size()
        )
    );

    const int result =
        TaskbarModel_MoveNotificationAreaIcon_Original(
            pThis,
            notificationAreaIconAbi,
            location,
            index
        );

    const UIOrderSnapshot after =
        CaptureUIOrderSnapshot();

    Wh_Log(
        L"TRAY_ORDER_LOCK_MOVE_ALLOWED_COMPLETE "
        L"move=%llu "
        L"result=0x%08X "
        L"afterValid=%d "
        L"afterEntries=%llu "
        L"orderChanged=%d",
        moveNumber,
        static_cast<unsigned int>(
            result
        ),
        after.valid
            ? 1
            : 0,
        static_cast<unsigned long long>(
            after.entries.size()
        ),
        before.valid &&
                after.valid &&
                before.entries !=
                    after.entries
            ? 1
            : 0
    );

    if (
        SUCCEEDED(
            static_cast<HRESULT>(
                result
            )
        ) &&
        before.valid &&
        after.valid &&
        before.entries !=
            after.entries
    ) {
        LearnManualMove(
            before,
            after,
            location,
            index
        );
    }

    return result;
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
    std::size_t canonicalEntries =
        0;

    bool loadedFromStorage =
        false;

    {
        std::lock_guard<std::mutex> lock(
            g_canonicalMutex
        );

        canonicalEntries =
            g_canonicalOrder.size();

        loadedFromStorage =
            g_canonicalLoadedFromStorage;
    }

    Wh_Log(
        L"TRAY_ORDER_LOCK_READY "
        L"processId=%lu "
        L"taskbarHooksInitialized=%d "
        L"orderingBehavior=%s "
        L"canonicalEntries=%llu "
        L"canonicalLoadedFromStorage=%d",
        GetCurrentProcessId(),
        g_taskbarHooksInitialized.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        GetOrderingBehavior() ==
                OrderingBehavior::PreserveManual
            ? L"preserveManual"
            : L"lockAll",
        static_cast<unsigned long long>(
            canonicalEntries
        ),
        loadedFromStorage
            ? 1
            : 0
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

    if (
        !taskbarModule
    ) {
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

    if (
        applyImmediately
    ) {
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

    if (
        applyImmediately
    ) {
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

    g_allowedMoveCount.store(
        0,
        std::memory_order_release
    );

    g_learnedMoveCount.store(
        0,
        std::memory_order_release
    );

    g_skippedLearningCount.store(
        0,
        std::memory_order_release
    );

    LoadSettings();

    InitializeCanonicalState();

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

    if (
        existingTaskbarWindow
    ) {
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

        if (
            taskbarWindow
        ) {
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

void Wh_ModSettingsChanged() {
    LoadSettings();

    InitializeCanonicalState();

    LogReady();
}

void Wh_ModUninit() {
    std::size_t canonicalEntries =
        0;

    {
        std::lock_guard<std::mutex> lock(
            g_canonicalMutex
        );

        canonicalEntries =
            g_canonicalOrder.size();
    }

    Wh_Log(
        L"Tray Order Lock stopped; "
        L"processId=%lu "
        L"blockedMoves=%llu "
        L"allowedMoves=%llu "
        L"learnedMoves=%llu "
        L"skippedLearning=%llu "
        L"canonicalEntries=%llu "
        L"taskbarHooksInitialized=%d",
        GetCurrentProcessId(),
        g_blockedMoveCount.load(
            std::memory_order_relaxed
        ),
        g_allowedMoveCount.load(
            std::memory_order_relaxed
        ),
        g_learnedMoveCount.load(
            std::memory_order_relaxed
        ),
        g_skippedLearningCount.load(
            std::memory_order_relaxed
        ),
        static_cast<unsigned long long>(
            canonicalEntries
        ),
        g_taskbarHooksInitialized.load(
            std::memory_order_relaxed
        )
            ? 1
            : 0
    );
}
