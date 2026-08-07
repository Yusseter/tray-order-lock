// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Compares stable and rotating GUID tray identities across version-directory changes.
// @version         0.16.0
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

Version 0.16.0 analyzes a dedicated synthetic application which creates two
GUID-based tray icons across two executable version directories.

The first icon keeps the same GUID in both versions.

The second icon uses one GUID in Version-1.0.0 and a different GUID in
Version-2.0.0.

After the first run, Version-1.0.0 is removed before the second run.

The analyzer verifies whether:

- The stable GUID is represented by one current registry identity.
- The rotating GUID produces one stale old-version identity and one current
  new-version identity.
- Both current tray icons share the same executable path.
- Executable-path-only matching is therefore ambiguous.
- Exact GUID matching remains safe for the stable icon.
- A GUID-changing icon cannot be paired across versions from path alone when
  another current GUID-based icon shares the same executable.

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
    L"trayguidfallbackprobev160.exe";

constexpr wchar_t kStableGuid[] =
    L"{0f29c634-2a3b-4a77-9d15-8bf6dd6a1601}";

constexpr wchar_t kRotatingGuidV1[] =
    L"{1a3bd745-3b4c-5b88-ae26-9cf7ee7b1602}";

constexpr wchar_t kRotatingGuidV2[] =
    L"{2b4ce856-4c5d-6c99-bf37-ad08ff8c1603}";

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
    std::wstring iconGuid;

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
        status != ERROR_SUCCESS ||
        requiredBytes == 0
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

    record.iconGuid =
        ToLower(
            QueryStringValue(
                subkey,
                L"IconGuid"
            )
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

void RunGuidFallbackAudit() {
    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    if (!snapshot.valid) {
        Wh_Log(
            L"GUID_FALLBACK_AUDIT_FAILED "
            L"registryStatus=%ld",
            snapshot.status
        );

        return;
    }

    std::map<
        std::wstring,
        std::vector<RegistryRecord>
    > groups;

    unsigned long long targetRecords =
        0;

    unsigned long long targetGuidRecords =
        0;

    unsigned long long targetMissingGuidRecords =
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
            record.iconGuid.empty()
        ) {
            targetMissingGuidRecords++;
        } else {
            targetGuidRecords++;
        }

        groups[
            record.normalizedExecutablePath
        ].push_back(
            std::move(
                record
            )
        );
    }

    unsigned long long normalizedPathGroups =
        0;

    unsigned long long activeCandidateGroups =
        0;

    unsigned long long expectedMixedGroups =
        0;

    unsigned long long pathOnlyAmbiguousGroups =
        0;

    unsigned long long stableGuidCurrentRecords =
        0;

    unsigned long long stableGuidStaleRecords =
        0;

    unsigned long long rotatingV1CurrentRecords =
        0;

    unsigned long long rotatingV1StaleRecords =
        0;

    unsigned long long rotatingV2CurrentRecords =
        0;

    unsigned long long rotatingV2StaleRecords =
        0;

    for (
        const auto& groupPair :
        groups
    ) {
        normalizedPathGroups++;

        const std::wstring& normalizedPath =
            groupPair.first;

        const std::vector<RegistryRecord>& members =
            groupPair.second;

        std::set<std::wstring>
            exactPaths;

        std::set<std::wstring>
            allGuids;

        std::set<std::wstring>
            currentGuids;

        std::set<std::wstring>
            existingPaths;

        std::map<
            std::wstring,
            unsigned long long
        > exactPathCounts;

        unsigned long long existingRecords =
            0;

        unsigned long long stableRecords =
            0;

        unsigned long long stableCurrent =
            0;

        unsigned long long stableStale =
            0;

        unsigned long long rotatingV1Records =
            0;

        unsigned long long rotatingV1Current =
            0;

        unsigned long long rotatingV1Stale =
            0;

        unsigned long long rotatingV2Records =
            0;

        unsigned long long rotatingV2Current =
            0;

        unsigned long long rotatingV2Stale =
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
                !member.iconGuid.empty()
            ) {
                allGuids.insert(
                    member.iconGuid
                );
            }

            if (
                member.executableExists
            ) {
                existingRecords++;

                existingPaths.insert(
                    exactPath
                );

                if (
                    !member.iconGuid.empty()
                ) {
                    currentGuids.insert(
                        member.iconGuid
                    );
                }
            }

            if (
                member.iconGuid ==
                kStableGuid
            ) {
                stableRecords++;

                if (
                    member.executableExists
                ) {
                    stableCurrent++;
                } else {
                    stableStale++;
                }
            }

            if (
                member.iconGuid ==
                kRotatingGuidV1
            ) {
                rotatingV1Records++;

                if (
                    member.executableExists
                ) {
                    rotatingV1Current++;
                } else {
                    rotatingV1Stale++;
                }
            }

            if (
                member.iconGuid ==
                kRotatingGuidV2
            ) {
                rotatingV2Records++;

                if (
                    member.executableExists
                ) {
                    rotatingV2Current++;
                } else {
                    rotatingV2Stale++;
                }
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

        const bool hasCurrentRecords =
            existingRecords >
            0;

        if (
            hasCurrentRecords
        ) {
            activeCandidateGroups++;
        }

        const bool pathOnlyAmbiguous =
            existingRecords >
                1 &&
            currentGuids.size() >
                1;

        if (
            pathOnlyAmbiguous
        ) {
            pathOnlyAmbiguousGroups++;
        }

        const bool stableGuidExactMatchSafe =
            stableRecords ==
                1 &&
            stableCurrent ==
                1 &&
            stableStale ==
                0;

        const bool rotatingGuidChanged =
            rotatingV1Records ==
                1 &&
            rotatingV1Stale ==
                1 &&
            rotatingV1Current ==
                0 &&
            rotatingV2Records ==
                1 &&
            rotatingV2Current ==
                1 &&
            rotatingV2Stale ==
                0;

        const bool rotatingFallbackAmbiguous =
            rotatingGuidChanged &&
            pathOnlyAmbiguous;

        const bool expectedMixedShape =
            members.size() ==
                3 &&
            exactPaths.size() ==
                2 &&
            allGuids.size() ==
                3 &&
            currentGuids.size() ==
                2 &&
            existingRecords ==
                2 &&
            existingPaths.size() ==
                1 &&
            sameExactPathDuplicate &&
            stableGuidExactMatchSafe &&
            rotatingGuidChanged &&
            rotatingFallbackAmbiguous;

        if (
            expectedMixedShape
        ) {
            expectedMixedGroups++;
        }

        stableGuidCurrentRecords +=
            stableCurrent;

        stableGuidStaleRecords +=
            stableStale;

        rotatingV1CurrentRecords +=
            rotatingV1Current;

        rotatingV1StaleRecords +=
            rotatingV1Stale;

        rotatingV2CurrentRecords +=
            rotatingV2Current;

        rotatingV2StaleRecords +=
            rotatingV2Stale;

        Wh_Log(
            L"GUID_FALLBACK_GROUP "
            L"group=%llu "
            L"memberCount=%llu "
            L"uniqueExactPaths=%llu "
            L"uniqueGuids=%llu "
            L"existingRecords=%llu "
            L"uniqueExistingPaths=%llu "
            L"currentGuids=%llu "
            L"sameExactPathDuplicate=%d "
            L"pathOnlyAmbiguous=%d "
            L"stableGuidExactMatchSafe=%d "
            L"rotatingGuidChanged=%d "
            L"rotatingFallbackAmbiguous=%d "
            L"expectedMixedShape=%d "
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
                allGuids.size()
            ),
            existingRecords,
            static_cast<
                unsigned long long
            >(
                existingPaths.size()
            ),
            static_cast<
                unsigned long long
            >(
                currentGuids.size()
            ),
            sameExactPathDuplicate
                ? 1
                : 0,
            pathOnlyAmbiguous
                ? 1
                : 0,
            stableGuidExactMatchSafe
                ? 1
                : 0,
            rotatingGuidChanged
                ? 1
                : 0,
            rotatingFallbackAmbiguous
                ? 1
                : 0,
            expectedMixedShape
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
                L"GUID_FALLBACK_GROUP_MEMBER "
                L"group=%llu "
                L"member=%llu "
                L"id=%llu "
                L"position=%llu "
                L"exists=%d "
                L"guid=\"%s\" "
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
                member.executableExists
                    ? 1
                    : 0,
                member.iconGuid.c_str(),
                member.initialTooltip.c_str(),
                member.executablePath.c_str()
            );
        }
    }

    const bool mixedGuidBehaviorValidated =
        activeCandidateGroups ==
            1 &&
        expectedMixedGroups ==
            1 &&
        pathOnlyAmbiguousGroups ==
            1 &&
        stableGuidCurrentRecords ==
            1 &&
        stableGuidStaleRecords ==
            0 &&
        rotatingV1CurrentRecords ==
            0 &&
        rotatingV1StaleRecords ==
            1 &&
        rotatingV2CurrentRecords ==
            1 &&
        rotatingV2StaleRecords ==
            0 &&
        targetMissingGuidRecords ==
            0;

    Wh_Log(
        L"GUID_FALLBACK_AUDIT_SUMMARY "
        L"uiOrderEntries=%llu "
        L"targetRecords=%llu "
        L"targetGuidRecords=%llu "
        L"targetMissingGuidRecords=%llu "
        L"normalizedPathGroups=%llu "
        L"activeCandidateGroups=%llu "
        L"pathOnlyAmbiguousGroups=%llu "
        L"expectedMixedGroups=%llu "
        L"stableGuidCurrentRecords=%llu "
        L"stableGuidStaleRecords=%llu "
        L"rotatingV1CurrentRecords=%llu "
        L"rotatingV1StaleRecords=%llu "
        L"rotatingV2CurrentRecords=%llu "
        L"rotatingV2StaleRecords=%llu "
        L"mixedGuidBehaviorValidated=%d",
        static_cast<
            unsigned long long
        >(
            snapshot.entries.size()
        ),
        targetRecords,
        targetGuidRecords,
        targetMissingGuidRecords,
        normalizedPathGroups,
        activeCandidateGroups,
        pathOnlyAmbiguousGroups,
        expectedMixedGroups,
        stableGuidCurrentRecords,
        stableGuidStaleRecords,
        rotatingV1CurrentRecords,
        rotatingV1StaleRecords,
        rotatingV2CurrentRecords,
        rotatingV2StaleRecords,
        mixedGuidBehaviorValidated
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
        L"0.16.0 initializing"
    );

    if (
        !IsPrimaryShellProcess()
    ) {
        Wh_Log(
            L"GUID_FALLBACK_AUDIT_SKIPPED "
            L"reason=\"non-primary Explorer process\" "
            L"processId=%lu",
            GetCurrentProcessId()
        );

        return TRUE;
    }

    Wh_Log(
        L"GUID_FALLBACK_AUDIT_BEGIN "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    RunGuidFallbackAudit();

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
