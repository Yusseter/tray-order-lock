// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Audits version-directory fallback identities for non-packaged tray icons.
// @version         0.14.0
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

Version 0.14.0 audits notification-area registry records outside WindowsApps
whose executable paths contain a conservative version-like directory.

Examples include directory names such as:

- 1.2.3
- v1.2.3
- app-1.2.3
- version-1.2.3

The analyzer replaces only those directory segments with <version> and groups
records by the resulting normalized executable path.

For each multi-record group it reports:

- Exact executable paths.
- Whether each executable still exists.
- GUID or UID discriminator.
- Number of distinct historical paths.
- Whether more than one current executable exists.
- Whether multiple records share the same exact executable path.
- Whether the group resembles a safe single-app version-history chain.

The version-directory recognition is deliberately conservative. This version
is an audit and does not establish a production matching rule.

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

constexpr wchar_t kWindowsAppsMarker[] =
    L"\\windowsapps\\";

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
    std::wstring publisher;
    std::wstring initialTooltip;

    bool uidValid =
        false;

    DWORD uid =
        0;

    std::wstring iconGuidText;
    std::wstring discriminator;

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
        path.size() >= 4 &&
        path.compare(
            0,
            4,
            kExtendedPrefix
        ) == 0
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
        status != ERROR_SUCCESS ||
        registryType != REG_DWORD ||
        resultBytes != sizeof(result)
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
        value.size() >= prefixLength &&
        value.compare(
            0,
            prefixLength,
            prefix
        ) == 0;
}

bool IsNumericDottedVersionCore(
    const std::wstring& value
) {
    if (value.empty()) {
        return false;
    }

    if (
        value.front() == L'.' ||
        value.back() == L'.'
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
            character >= L'0' &&
            character <= L'9'
        ) {
            digitCount++;

            previousWasDot =
                false;

            continue;
        }

        if (character == L'.') {
            if (previousWasDot) {
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
        digitCount > 0 &&
        dotCount >= 1;
}

bool LooksLikeVersionDirectory(
    const std::wstring& directoryName
) {
    if (directoryName.empty()) {
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
        candidate.size() >= 2 &&
        candidate[0] == L'v' &&
        candidate[1] >= L'0' &&
        candidate[1] <= L'9'
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
    if (foundVersionDirectory) {
        *foundVersionDirectory =
            false;
    }

    std::wstring path =
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

            if (foundVersionDirectory) {
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

bool IsWindowsAppsPath(
    const std::wstring& executablePath
) {
    const std::wstring lowerPath =
        ToLower(
            NormalizeSlashes(
                executablePath
            )
        );

    return
        lowerPath.find(
            kWindowsAppsMarker
        ) !=
        std::wstring::npos;
}

bool ExecutableExists(
    const std::wstring& executablePath
) {
    if (executablePath.empty()) {
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
        ) == 0;
}

std::wstring BuildDiscriminator(
    const RegistryRecord& record
) {
    if (
        !record.iconGuidText.empty()
    ) {
        return
            L"guid:" +
            ToLower(
                record.iconGuidText
            );
    }

    if (record.uidValid) {
        return
            L"uid:" +
            std::to_wstring(
                record.uid
            );
    }

    return L"";
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

    record.publisher =
        QueryStringValue(
            subkey,
            L"Publisher"
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

    record.iconGuidText =
        QueryStringValue(
            subkey,
            L"IconGuid"
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

    record.discriminator =
        BuildDiscriminator(
            record
        );

    return record;
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

void RunVersionDirectoryAudit() {
    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    if (!snapshot.valid) {
        Wh_Log(
            L"NONPACKAGE_VERSION_AUDIT_FAILED "
            L"registryStatus=%ld",
            snapshot.status
        );

        return;
    }

    std::map<
        std::wstring,
        std::vector<RegistryRecord>
    > groups;

    unsigned long long nonPackagedEntries =
        0;

    unsigned long long versionPatternEntries =
        0;

    unsigned long long versionPatternExisting =
        0;

    unsigned long long versionPatternMissing =
        0;

    unsigned long long recordsWithoutDiscriminator =
        0;

    for (
        std::size_t index = 0;
        index < snapshot.entries.size();
        index++
    ) {
        const std::uint64_t identity =
            snapshot.entries[
                index
            ];

        RegistryRecord record =
            ReadRegistryRecord(
                identity,
                static_cast<unsigned long long>(
                    index +
                    1
                )
            );

        if (
            record.executablePath.empty() ||
            IsWindowsAppsPath(
                record.executablePath
            )
        ) {
            continue;
        }

        nonPackagedEntries++;

        if (
            !record.hasVersionDirectory
        ) {
            continue;
        }

        versionPatternEntries++;

        if (record.executableExists) {
            versionPatternExisting++;
        } else {
            versionPatternMissing++;
        }

        if (
            record.discriminator.empty()
        ) {
            recordsWithoutDiscriminator++;
        }

        groups[
            record.normalizedExecutablePath
        ].push_back(
            std::move(
                record
            )
        );
    }

    unsigned long long fallbackGroups =
        0;

    unsigned long long multiRecordGroups =
        0;

    unsigned long long multiRecordMembers =
        0;

    unsigned long long historicalPathGroups =
        0;

    unsigned long long oneExistingGroups =
        0;

    unsigned long long noExistingGroups =
        0;

    unsigned long long ambiguousExistingGroups =
        0;

    unsigned long long sameExactPathDuplicateGroups =
        0;

    unsigned long long historicalChainCandidates =
        0;

    for (
        const auto& groupPair :
        groups
    ) {
        fallbackGroups++;

        const std::wstring& normalizedPath =
            groupPair.first;

        const std::vector<RegistryRecord>& members =
            groupPair.second;

        if (
            members.size() <
            2
        ) {
            continue;
        }

        multiRecordGroups++;

        multiRecordMembers +=
            static_cast<unsigned long long>(
                members.size()
            );

        std::set<std::wstring>
            exactPaths;

        std::set<std::wstring>
            discriminators;

        std::map<
            std::wstring,
            unsigned long long
        > exactPathCounts;

        unsigned long long existingMembers =
            0;

        bool everyMemberHasDiscriminator =
            true;

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
                existingMembers++;
            }

            if (
                member.discriminator.empty()
            ) {
                everyMemberHasDiscriminator =
                    false;
            } else {
                discriminators.insert(
                    member.discriminator
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

        const bool historicalPaths =
            exactPaths.size() >
            1;

        const bool oneExisting =
            existingMembers ==
            1;

        const bool noExisting =
            existingMembers ==
            0;

        const bool ambiguousExisting =
            existingMembers >
            1;

        const bool eachRecordHasUniqueExactPath =
            exactPaths.size() ==
            members.size();

        const bool historicalChainCandidate =
            historicalPaths &&
            oneExisting &&
            eachRecordHasUniqueExactPath &&
            everyMemberHasDiscriminator &&
            !sameExactPathDuplicate;

        if (historicalPaths) {
            historicalPathGroups++;
        }

        if (oneExisting) {
            oneExistingGroups++;
        }

        if (noExisting) {
            noExistingGroups++;
        }

        if (ambiguousExisting) {
            ambiguousExistingGroups++;
        }

        if (sameExactPathDuplicate) {
            sameExactPathDuplicateGroups++;
        }

        if (historicalChainCandidate) {
            historicalChainCandidates++;
        }

        Wh_Log(
            L"NONPACKAGE_VERSION_GROUP "
            L"group=%llu "
            L"memberCount=%llu "
            L"uniqueExactPaths=%llu "
            L"uniqueDiscriminators=%llu "
            L"existingMembers=%llu "
            L"missingMembers=%llu "
            L"historicalPaths=%d "
            L"sameExactPathDuplicate=%d "
            L"oneExisting=%d "
            L"noExisting=%d "
            L"ambiguousExisting=%d "
            L"historicalChainCandidate=%d "
            L"normalizedPath=\"%s\"",
            multiRecordGroups,
            static_cast<unsigned long long>(
                members.size()
            ),
            static_cast<unsigned long long>(
                exactPaths.size()
            ),
            static_cast<unsigned long long>(
                discriminators.size()
            ),
            existingMembers,
            static_cast<unsigned long long>(
                members.size()
            ) -
                existingMembers,
            historicalPaths
                ? 1
                : 0,
            sameExactPathDuplicate
                ? 1
                : 0,
            oneExisting
                ? 1
                : 0,
            noExisting
                ? 1
                : 0,
            ambiguousExisting
                ? 1
                : 0,
            historicalChainCandidate
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
                L"NONPACKAGE_VERSION_GROUP_MEMBER "
                L"group=%llu "
                L"member=%llu "
                L"id=%llu "
                L"position=%llu "
                L"exists=%d "
                L"discriminator=\"%s\" "
                L"publisher=\"%s\" "
                L"tooltip=\"%s\" "
                L"path=\"%s\"",
                multiRecordGroups,
                static_cast<unsigned long long>(
                    memberIndex +
                    1
                ),
                static_cast<unsigned long long>(
                    member.identity
                ),
                member.oneBasedPosition,
                member.executableExists
                    ? 1
                    : 0,
                member.discriminator.c_str(),
                member.publisher.c_str(),
                member.initialTooltip.c_str(),
                member.executablePath.c_str()
            );
        }
    }

    Wh_Log(
        L"NONPACKAGE_VERSION_AUDIT_SUMMARY "
        L"uiOrderEntries=%llu "
        L"nonPackagedEntries=%llu "
        L"versionPatternEntries=%llu "
        L"versionPatternExisting=%llu "
        L"versionPatternMissing=%llu "
        L"recordsWithoutDiscriminator=%llu "
        L"fallbackGroups=%llu "
        L"multiRecordGroups=%llu "
        L"multiRecordMembers=%llu "
        L"historicalPathGroups=%llu "
        L"oneExistingGroups=%llu "
        L"noExistingGroups=%llu "
        L"ambiguousExistingGroups=%llu "
        L"sameExactPathDuplicateGroups=%llu "
        L"historicalChainCandidates=%llu",
        static_cast<unsigned long long>(
            snapshot.entries.size()
        ),
        nonPackagedEntries,
        versionPatternEntries,
        versionPatternExisting,
        versionPatternMissing,
        recordsWithoutDiscriminator,
        fallbackGroups,
        multiRecordGroups,
        multiRecordMembers,
        historicalPathGroups,
        oneExistingGroups,
        noExistingGroups,
        ambiguousExistingGroups,
        sameExactPathDuplicateGroups,
        historicalChainCandidates
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
        L"0.14.0 initializing"
    );

    if (!IsPrimaryShellProcess()) {
        Wh_Log(
            L"NONPACKAGE_VERSION_AUDIT_SKIPPED "
            L"reason=\"non-primary Explorer process\" "
            L"processId=%lu",
            GetCurrentProcessId()
        );

        return TRUE;
    }

    Wh_Log(
        L"NONPACKAGE_VERSION_AUDIT_BEGIN "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    RunVersionDirectoryAudit();

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
