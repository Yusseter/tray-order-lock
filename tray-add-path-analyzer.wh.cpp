// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Tests stable UID fallback chains for multiple tray icons across version-directory changes.
// @version         0.15.0
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

Version 0.15.0 analyzes a dedicated synthetic test application which creates
two UID-based tray icons from two version directories.

The test application uses:

- UID 101
- UID 202

The first executable runs from Version-1.0.0.
 first executable runs from Version-1.0.0.
The second executable runs from Version-2.0.0.

After the first run, the Version-1.0.0 directory is removed before the second
run. This leaves two stale registry identities from the first version and two
current identities from the second version.

The analyzer verifies whether:

- Version-normalized executable path alone combines both tray icons into one
  ambiguous group.
- Stable UID separates that group into two independent historical chains.
- Each UID chain contains one stale old-version record and one current
  new-version record.

This version:

- Installs no taskbar hooks.
- Calls no MoveIcon function.
- Writes nothing to the registry.
- Does not change tray order.
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
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr wchar_t kNotifyIconSettingsPath[] =
    L"Control Panel\\NotifyIconSettings";

constexpr wchar_t kUIOrderListValueName[] =
    L"UIOrderList";

constexpr wchar_t kTargetExecutableName[] =
    L"traydualuidversionprobev150.exe";

std::atomic<bool> g_auditCompleted =
    false;

struct UIOrderSnapshot {
    bool valid =
        false;

    LONG status =
        ERROR_SUCCESS;

    std::vector<std::uint64_t> entries;
};

struct RegistryRecord {
    std::uint64_t identity =
        0;

    unsigned long long oneBasedPosition =
        0;

    std::wstring executablePath;
    std::wstring normalizedExecutablePath;
    std::wstring initialTooltip;

    bool uidValid =
        false;

    DWORD uid =
        0;

    bool executableExists =
        false;

    bool hasVersionDirectory =
        false;
};

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

    constexpr wchar_t kExtendedPrefix[] =
        L"\\\\?\\";

    if (
        path.size() >=
            4 &&
        path.compare(
            0,
            4,
            kExtendedPrefix
        ) ==
            0
    ) {
        path.erase(
            0,
            4
        );
    }

    return path;
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
            sizeof(wchar_t) +
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
    if (!value) {
        return false;
    }

    DWORD registryType =
        REG_NONE;

    DWORD result =
        0;

    DWORD resultBytes =
        sizeof(result);

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
            sizeof(result)
    ) {
        return false;
    }

    *value =
        result;

    return true;
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

bool StartsWith(
    const std::wstring& value,
    const wchar_t* prefix
) {
    if (!prefix) {
        return false;
    }

    const std::size_t prefixLength =
        std::wcslen(
            prefix
        );

    return
        value.size() >=
            prefixLength &&
        value.compare(
            0,
            prefixLength,
            prefix
        ) ==
            0;
}

bool IsNumericDottedVersionCore(
    const std::wstring& value
) {
    if (value.empty()) {
        return false;
    }

    if (
        value.front() ==
            L'.' ||
        value.back() ==
            L'.'
    ) {
        return false;
    }

    unsigned int digitCount =
        0;

    unsigned int dotCount =
        0;

    bool previousWasDot =
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
            digitCount++;

            previousWasDot =
                false;

            continue;
        }

        if (
            character ==
            L'.'
        ) {
            if (
                previousWasDot
            ) {
                return false;
            }

            dotCount++;

            previousWasDot =
                true;

            continue;
        }

        return false;
    }

    return
        digitCount >
            0 &&
        dotCount >=
            1;
}

bool LooksLikeVersionDirectory(
    const std::wstring& directoryName
) {
    if (
        directoryName.empty()
    ) {
        return false;
    }

    std::wstring candidate =
        ToLower(
            directoryName
        );

    if (
        StartsWith(
            candidate,
            L"app-"
        )
    ) {
        candidate.erase(
            0,
            4
        );
    } else if (
        StartsWith(
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
    const std::wstring& executablePath,
    bool* foundVersionDirectory
) {
    if (
        foundVersionDirectory
    ) {
        *foundVersionDirectory =
            false;
    }

    const std::wstring path =
        ToLower(
            NormalizeSlashes(
                executablePath
            )
        );

    if (path.empty()) {
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

        if (!firstSegment) {
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

            if (
                foundVersionDirectory
            ) {
                *foundVersionDirectory =
                    true;
            }
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
        index <
            suffix.size();
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
                    suffix[
                        index
                    ]
                )
            );

        if (
            left !=
            right
        ) {
            return false;
        }
    }

    return true;
}

bool ExecutableExists(
    const std::wstring& executablePath
) {
    if (
        executablePath.empty()
    ) {
        return false;
    }

    const std::wstring normalizedPath =
        NormalizeSlashes(
            executablePath
        );

    const DWORD attributes =
        GetFileAttributesW(
            normalizedPath.c_str()
        );

    if (
        attributes ==
        INVALID_FILE_ATTRIBUTES
    ) {
        return false;
    }

    return
        (
            attributes &
            FILE_ATTRIBUTE_DIRECTORY
        ) ==
        0;
}

RegistryRecord ReadRegistryRecord(
    std::uint64_t identity,
    unsigned long long oneBasedPosition
) {
    RegistryRecord record;

    record.identity =
        identity;

    record.oneBasedPosition =
        oneBasedPosition;

    const std::wstring subkey =
        MakeTrayEntrySubkey(
            identity
        );

    record.executablePath =
        QueryStringValue(
            subkey,
            L"ExecutablePath"
        );

    record.initialTooltip =
        QueryStringValue(
            subkey,
            L"InitialTooltip"
        );

    record.uidValid =
        QueryDwordValue(
            subkey,
            L"UID",
            &record.uid
        );

    record.normalizedExecutablePath =
        BuildVersionNormalizedPath(
            record.executablePath,
            &record.hasVersionDirectory
        );

    record.executableExists =
        ExecutableExists(
            record.executablePath
        );

    return record;
}

bool IsTargetRecord(
    const RegistryRecord& record
) {
    if (
        record.executablePath.empty() ||
        !record.hasVersionDirectory
    ) {
        return false;
    }

    return
        EndsWithOrdinalIgnoreCase(
            record.executablePath,
            kTargetExecutableName
        );
}

bool IsPrimaryShellProcess() {
    const HWND shellWindow =
        GetShellWindow();

    if (!shellWindow) {
        return false;
    }

    DWORD shellProcessId =
        0;

    GetWindowThreadProcessId(
        shellWindow,
        &shellProcessId
    );

    return
        shellProcessId ==
        GetCurrentProcessId();
}

void RunDualUidAudit() {
    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    if (!snapshot.valid) {
        Wh_Log(
            L"DUAL_UID_AUDIT_FAILED "
            L"registryStatus=%ld",
            snapshot.status
        );

        return;
    }

    std::map<
        std::wstring,
        std::vector<RegistryRecord>
    > pathGroups;

    unsigned long long targetRecords =
        0;

    unsigned long long targetUidRecords =
        0;

    unsigned long long targetMissingUidRecords =
        0;

    for (
        std::size_t index = 0;
        index <
            snapshot.entries.size();
        index++
    ) {
        RegistryRecord record =
            ReadRegistryRecord(
                snapshot.entries[
                    index
                ],
                static_cast<
                    unsigned long long
                >(
                    index +
                    1
                )
            );

        if (
            !IsTargetRecord(
                record
            )
        ) {
            continue;
        }

        targetRecords++;

        if (
            record.uidValid
        ) {
            targetUidRecords++;
        } else {
            targetMissingUidRecords++;
        }

        pathGroups[
            record.normalizedExecutablePath
        ].push_back(
            std::move(
                record
            )
        );
    }

    unsigned long long normalizedPathGroups =
        0;

    unsigned long long multiRecordPathGroups =
        0;

    unsigned long long pathOnlyAmbiguousGroups =
        0;

    unsigned long long uidChains =
        0;

    unsigned long long uidHistoricalChainCandidates =
        0;

    unsigned long long uidAmbiguousChains =
        0;

    unsigned long long expectedDualUidGroups =
        0;

    for (
        const auto& pathGroup :
        pathGroups
    ) {
        normalizedPathGroups++;

        const std::wstring& normalizedPath =
            pathGroup.first;

        const std::vector<RegistryRecord>& members =
            pathGroup.second;

        if (
            members.size() >
            1
        ) {
            multiRecordPathGroups++;
        }

        std::set<std::wstring>
            exactPaths;

        std::set<DWORD>
            uniqueUids;

        std::set<std::wstring>
            existingPaths;

        std::map<
            std::wstring,
            unsigned long long
        > exactPathCounts;

        std::map<
            DWORD,
            std::vector<
                const RegistryRecord*
            >
        > uidGroups;

        unsigned long long existingRecords =
            0;

        for (
            const RegistryRecord& member :
            members
        ) {
            const std::wstring exactPath =
                ToLower(
                    NormalizeSlashes(
                        member.executablePath
                    )
                );

            exactPaths.insert(
                exactPath
            );

            exactPathCounts[
                exactPath
            ]++;

            if (
                member.executableExists
            ) {
                existingRecords++;

                existingPaths.insert(
                    exactPath
                );
            }

            if (
                member.uidValid
            ) {
                uniqueUids.insert(
                    member.uid
                );

                uidGroups[
                    member.uid
                ].push_back(
                    &member
                );
            }
        }

        bool sameExactPathDuplicate =
            false;

        for (
            const auto& count :
            exactPathCounts
        ) {
            if (
                count.second >
                1
            ) {
                sameExactPathDuplicate =
                    true;

                break;
            }
        }

        const bool pathOnlyAmbiguous =
            uniqueUids.size() >
                1 &&
            existingPaths.size() ==
                1 &&
            existingRecords >
                1;

        if (
            pathOnlyAmbiguous
        ) {
            pathOnlyAmbiguousGroups++;
        }

        const bool expectedDualUidGroup =
            members.size() ==
                4 &&
            exactPaths.size() ==
                2 &&
            uniqueUids.size() ==
                2 &&
            existingRecords ==
                2 &&
            existingPaths.size() ==
                1 &&
            sameExactPathDuplicate &&
            pathOnlyAmbiguous;

        if (
            expectedDualUidGroup
        ) {
            expectedDualUidGroups++;
        }

        Wh_Log(
            L"DUAL_UID_PATH_GROUP "
            L"group=%llu "
            L"memberCount=%llu "
            L"uniqueExactPaths=%llu "
            L"uniqueUids=%llu "
            L"existingRecords=%llu "
            L"uniqueExistingPaths=%llu "
            L"sameExactPathDuplicate=%d "
            L"pathOnlyAmbiguous=%d "
            L"expectedDualUidShape=%d "
            L"normalizedPath=\"%s\"",
            normalizedPathGroups,
            static_cast<
                unsigned long long
            >(
                members.size()
            ),
            static_cast<
                unsigned long long
            >(
                exactPaths.size()
            ),
            static_cast<
                unsigned long long
            >(
                uniqueUids.size()
            ),
            existingRecords,
            static_cast<
                unsigned long long
            >(
                existingPaths.size()
            ),
            sameExactPathDuplicate
                ? 1
                : 0,
            pathOnlyAmbiguous
                ? 1
                : 0,
            expectedDualUidGroup
                ? 1
                : 0,
            normalizedPath.c_str()
        );

        for (
            std::size_t memberIndex = 0;
            memberIndex <
                members.size();
            memberIndex++
        ) {
            const RegistryRecord& member =
                members[
                    memberIndex
                ];

            Wh_Log(
                L"DUAL_UID_PATH_GROUP_MEMBER "
                L"group=%llu "
                L"member=%llu "
                L"id=%llu "
                L"position=%llu "
                L"uidValid=%d "
                L"uid=%u "
                L"exists=%d "
                L"tooltip=\"%s\" "
                L"path=\"%s\"",
                normalizedPathGroups,
                static_cast<
                    unsigned long long
                >(
                    memberIndex +
                    1
                ),
                static_cast<
                    unsigned long long
                >(
                    member.identity
                ),
                member.oneBasedPosition,
                member.uidValid
                    ? 1
                    : 0,
                member.uid,
                member.executableExists
                    ? 1
                    : 0,
                member.initialTooltip.c_str(),
                member.executablePath.c_str()
            );
        }

        for (
            const auto& uidGroup :
            uidGroups
        ) {
            uidChains++;

            const DWORD uid =
                uidGroup.first;

            const std::vector<
                const RegistryRecord*
            >& uidMembers =
                uidGroup.second;

            std::set<std::wstring>
                uidExactPaths;

            std::set<std::wstring>
                uidExistingPaths;

            unsigned long long uidExistingRecords =
                0;

            for (
                const RegistryRecord* member :
                uidMembers
            ) {
                const std::wstring exactPath =
                    ToLower(
                        NormalizeSlashes(
                            member->executablePath
                        )
                    );

                uidExactPaths.insert(
                    exactPath
                );

                if (
                    member->executableExists
                ) {
                    uidExistingRecords++;

                    uidExistingPaths.insert(
                        exactPath
                    );
                }
            }

            const bool historicalPaths =
                uidExactPaths.size() >
                1;

            const bool singleCurrentRecord =
                uidExistingRecords ==
                1;

            const bool singleCurrentPath =
                uidExistingPaths.size() ==
                1;

            const bool uidAmbiguous =
                uidExistingRecords >
                    1 ||
                uidExistingPaths.size() >
                    1;

            const bool historicalChainCandidate =
                uidMembers.size() ==
                    2 &&
                uidExactPaths.size() ==
                    2 &&
                historicalPaths &&
                singleCurrentRecord &&
                singleCurrentPath &&
                !uidAmbiguous;

            if (
                historicalChainCandidate
            ) {
                uidHistoricalChainCandidates++;
            }

            if (
                uidAmbiguous
            ) {
                uidAmbiguousChains++;
            }

            Wh_Log(
                L"DUAL_UID_CHAIN "
                L"pathGroup=%llu "
                L"uid=%u "
                L"memberCount=%llu "
                L"uniqueExactPaths=%llu "
                L"existingRecords=%llu "
                L"uniqueExistingPaths=%llu "
                L"historicalPaths=%d "
                L"singleCurrentRecord=%d "
                L"singleCurrentPath=%d "
                L"ambiguous=%d "
                L"historicalChainCandidate=%d",
                normalizedPathGroups,
                uid,
                static_cast<
                    unsigned long long
                >(
                    uidMembers.size()
                ),
                static_cast<
                    unsigned long long
                >(
                    uidExactPaths.size()
                ),
                uidExistingRecords,
                static_cast<
                    unsigned long long
                >(
                    uidExistingPaths.size()
                ),
                historicalPaths
                    ? 1
                    : 0,
                singleCurrentRecord
                    ? 1
                    : 0,
                singleCurrentPath
                    ? 1
                    : 0,
                uidAmbiguous
                    ? 1
                    : 0,
                historicalChainCandidate
                    ? 1
                    : 0
            );
        }
    }

    const bool dualUidSeparationValidated =
        expectedDualUidGroups ==
            1 &&
        uidChains ==
            2 &&
        uidHistoricalChainCandidates ==
            2 &&
        uidAmbiguousChains ==
            0 &&
        targetMissingUidRecords ==
            0;

    Wh_Log(
        L"DUAL_UID_AUDIT_SUMMARY "
        L"uiOrderEntries=%llu "
        L"targetRecords=%llu "
        L"targetUidRecords=%llu "
        L"targetMissingUidRecords=%llu "
        L"normalizedPathGroups=%llu "
        L"multiRecordPathGroups=%llu "
        L"pathOnlyAmbiguousGroups=%llu "
        L"uidChains=%llu "
        L"uidHistoricalChainCandidates=%llu "
        L"uidAmbiguousChains=%llu "
        L"expectedDualUidGroups=%llu "
        L"dualUidSeparationValidated=%d",
        static_cast<
            unsigned long long
        >(
            snapshot.entries.size()
        ),
        targetRecords,
        targetUidRecords,
        targetMissingUidRecords,
        normalizedPathGroups,
        multiRecordPathGroups,
        pathOnlyAmbiguousGroups,
        uidChains,
        uidHistoricalChainCandidates,
        uidAmbiguousChains,
        expectedDualUidGroups,
        dualUidSeparationValidated
            ? 1
            : 0
    );

    g_auditCompleted.store(
        true,
        std::memory_order_release
    );
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Add Path Analyzer "
        L"0.15.0 initializing"
    );

    if (
        !IsPrimaryShellProcess()
    ) {
        Wh_Log(
            L"DUAL_UID_AUDIT_SKIPPED "
            L"reason=\"non-primary Explorer process\" "
            L"processId=%lu",
            GetCurrentProcessId()
        );

        return TRUE;
    }

    Wh_Log(
        L"DUAL_UID_AUDIT_BEGIN "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    RunDualUidAudit();

    return TRUE;
}

void Wh_ModUninit() {
    Wh_Log(
        L"Tray Add Path Analyzer stopped; "
        L"auditCompleted=%d",
        g_auditCompleted.load(
            std::memory_order_acquire
        )
            ? 1
            : 0
    );
}
