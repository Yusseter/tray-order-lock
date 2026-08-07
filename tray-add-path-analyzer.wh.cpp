// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Audits packaged tray identity fallback groups and installed package versions.
// @version         0.13.0
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

Version 0.13.0 audits a fallback logical identity for packaged tray icons:

- Package family name.
- Executable path relative to the package directory.

The IconGuid or UID remains recorded as an icon discriminator, but it is not
included in the fallback grouping key. This allows tray records created by
different package versions to be compared even when their GUIDs change.

For every fallback group, the analyzer reports:

- Registry record count.
- Distinct package full-name count.
- Distinct GUID or UID discriminator count.
- Records whose package version is still installed.
- Records belonging to package versions that are no longer installed.
- Multiple records belonging to the same package full name.
- Whether the group resembles a single historical icon chain.
- Whether the currently installed records are ambiguous.

Installed package state is queried with GetPackagePathByFullName.

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

using GetPackagePathByFullName_t =
    LONG(WINAPI*)(
        PCWSTR packageFullName,
        UINT32* pathLength,
        PWSTR path
    );

GetPackagePathByFullName_t
    g_getPackagePathByFullName =
        nullptr;

struct UIOrderSnapshot {
    bool valid =
        false;

    LONG status =
        ERROR_SUCCESS;

    std::vector<std::uint64_t> entries;
};

struct PackagePathInfo {
    bool valid =
        false;

    std::wstring packageFullName;
    std::wstring packageName;
    std::wstring packageVersion;
    std::wstring architecture;
    std::wstring resourceId;
    std::wstring publisherId;
    std::wstring packageFamilyName;
    std::wstring relativeExecutablePath;
};

struct PackageInstallState {
    bool apiAvailable =
        false;

    bool installed =
        false;

    LONG queryStatus =
        ERROR_SUCCESS;

    LONG pathStatus =
        ERROR_SUCCESS;

    std::wstring installedPath;
};

struct RegistryRecord {
    std::uint64_t identity =
        0;

    unsigned long long oneBasedPosition =
        0;

    std::wstring executablePath;
    std::wstring initialTooltip;

    bool uidValid =
        false;

    DWORD uid =
        0;

    std::wstring iconGuidText;

    PackagePathInfo package;
    PackageInstallState installState;

    std::wstring discriminator;
    std::wstring fallbackKey;
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

std::wstring NormalizePath(
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

bool ParsePackageFullName(
    const std::wstring& packageFullName,
    PackagePathInfo* package
) {
    if (!package) {
        return false;
    }

    const std::size_t separator4 =
        packageFullName.rfind(
            L'_'
        );

    if (
        separator4 ==
            std::wstring::npos ||
        separator4 ==
            0 ||
        separator4 +
            1 >=
            packageFullName.size()
    ) {
        return false;
    }

    const std::size_t separator3 =
        packageFullName.rfind(
            L'_',
            separator4 -
                1
        );

    if (
        separator3 ==
        std::wstring::npos
    ) {
        return false;
    }

    const std::size_t separator2 =
        packageFullName.rfind(
            L'_',
            separator3 -
                1
        );

    if (
        separator2 ==
        std::wstring::npos
    ) {
        return false;
    }

    const std::size_t separator1 =
        packageFullName.rfind(
            L'_',
            separator2 -
                1
        );

    if (
        separator1 ==
            std::wstring::npos ||
        separator1 ==
            0
    ) {
        return false;
    }

    package->packageName =
        packageFullName.substr(
            0,
            separator1
        );

    package->packageVersion =
        packageFullName.substr(
            separator1 +
                1,
            separator2 -
                separator1 -
                1
        );

    package->architecture =
        packageFullName.substr(
            separator2 +
                1,
            separator3 -
                separator2 -
                1
        );

    package->resourceId =
        packageFullName.substr(
            separator3 +
                1,
            separator4 -
                separator3 -
                1
        );

    package->publisherId =
        packageFullName.substr(
            separator4 +
                1
        );

    if (
        package->packageName.empty() ||
        package->packageVersion.empty() ||
        package->architecture.empty() ||
        package->publisherId.empty()
    ) {
        return false;
    }

    package->packageFamilyName =
        package->packageName +
        L"_" +
        package->publisherId;

    return true;
}

bool ExtractPackagePathInfo(
    const std::wstring& executablePath,
    PackagePathInfo* package
) {
    if (!package) {
        return false;
    }

    *package =
        {};

    const std::wstring normalizedPath =
        NormalizePath(
            executablePath
        );

    const std::wstring lowerPath =
        ToLower(
            normalizedPath
        );

    const std::size_t markerPosition =
        lowerPath.find(
            kWindowsAppsMarker
        );

    if (
        markerPosition ==
        std::wstring::npos
    ) {
        return false;
    }

    const std::size_t packageStart =
        markerPosition +
        std::wcslen(
            kWindowsAppsMarker
        );

    const std::size_t packageEnd =
        normalizedPath.find(
            L'\\',
            packageStart
        );

    if (
        packageEnd ==
            std::wstring::npos ||
        packageEnd ==
            packageStart ||
        packageEnd +
            1 >=
            normalizedPath.size()
    ) {
        return false;
    }

    package->packageFullName =
        normalizedPath.substr(
            packageStart,
            packageEnd -
                packageStart
        );

    package->relativeExecutablePath =
        normalizedPath.substr(
            packageEnd +
                1
        );

    if (
        !ParsePackageFullName(
            package->packageFullName,
            package
        )
    ) {
        return false;
    }

    package->valid =
        true;

    return true;
}

bool IsWindowsAppsPath(
    const std::wstring& executablePath
) {
    const std::wstring normalizedPath =
        NormalizePath(
            executablePath
        );

    const std::wstring lowerPath =
        ToLower(
            normalizedPath
        );

    return
        lowerPath.find(
            kWindowsAppsMarker
        ) !=
        std::wstring::npos;
}

bool LoadPackagePathFunction() {
    HMODULE kernel32Module =
        GetModuleHandleW(
            L"kernel32.dll"
        );

    if (!kernel32Module) {
        Wh_Log(
            L"PACKAGE_PATH_API_UNAVAILABLE "
            L"reason=\"kernel32.dll not loaded\""
        );

        return false;
    }

    g_getPackagePathByFullName =
        reinterpret_cast<
            GetPackagePathByFullName_t
        >(
            GetProcAddress(
                kernel32Module,
                "GetPackagePathByFullName"
            )
        );

    if (!g_getPackagePathByFullName) {
        Wh_Log(
            L"PACKAGE_PATH_API_UNAVAILABLE "
            L"reason=\"GetPackagePathByFullName not exported\""
        );

        return false;
    }

    Wh_Log(
        L"PACKAGE_PATH_API_READY"
    );

    return true;
}

PackageInstallState QueryPackageInstallState(
    const std::wstring& packageFullName
) {
    PackageInstallState state;

    state.apiAvailable =
        g_getPackagePathByFullName !=
        nullptr;

    if (!state.apiAvailable) {
        state.queryStatus =
            ERROR_PROC_NOT_FOUND;

        state.pathStatus =
            ERROR_PROC_NOT_FOUND;

        return state;
    }

    UINT32 requiredCharacters =
        0;

    state.queryStatus =
        g_getPackagePathByFullName(
            packageFullName.c_str(),
            &requiredCharacters,
            nullptr
        );

    if (
        state.queryStatus !=
            ERROR_INSUFFICIENT_BUFFER &&
        state.queryStatus !=
            ERROR_SUCCESS
    ) {
        state.pathStatus =
            state.queryStatus;

        return state;
    }

    state.installed =
        true;

    if (requiredCharacters == 0) {
        state.pathStatus =
            ERROR_SUCCESS;

        return state;
    }

    std::vector<wchar_t> pathBuffer(
        requiredCharacters,
        L'\0'
    );

    UINT32 actualCharacters =
        requiredCharacters;

    state.pathStatus =
        g_getPackagePathByFullName(
            packageFullName.c_str(),
            &actualCharacters,
            pathBuffer.data()
        );

    if (
        state.pathStatus ==
        ERROR_SUCCESS
    ) {
        state.installedPath =
            std::wstring(
                pathBuffer.data()
            );
    }

    return state;
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

std::wstring BuildFallbackKey(
    const RegistryRecord& record
) {
    if (!record.package.valid) {
        return L"";
    }

    return
        ToLower(
            record.package.packageFamilyName
        ) +
        L"|" +
        ToLower(
            NormalizePath(
                record.package.relativeExecutablePath
            )
        );
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

    record.iconGuidText =
        QueryStringValue(
            subkey,
            L"IconGuid"
        );

    ExtractPackagePathInfo(
        record.executablePath,
        &record.package
    );

    if (record.package.valid) {
        record.installState =
            QueryPackageInstallState(
                record.package.packageFullName
            );
    }

    record.discriminator =
        BuildDiscriminator(
            record
        );

    record.fallbackKey =
        BuildFallbackKey(
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

void RunFallbackIdentityAudit() {
    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    if (!snapshot.valid) {
        Wh_Log(
            L"PACKAGE_FALLBACK_AUDIT_FAILED "
            L"registryStatus=%ld",
            snapshot.status
        );

        return;
    }

    std::map<
        std::wstring,
        std::vector<RegistryRecord>
    > groups;

    unsigned long long windowsAppsEntries =
        0;

    unsigned long long parsedPackageEntries =
        0;

    unsigned long long packageParseFailures =
        0;

    unsigned long long installedRecords =
        0;

    unsigned long long unavailableRecords =
        0;

    unsigned long long unkeyedRecords =
        0;

    unsigned long long recordsWithoutDiscriminator =
        0;

    for (
        std::size_t index = 0;
        index < snapshot.entries.size();
        index++
    ) {
        const std::uint64_t identity =
            snapshot.entries[index];

        const std::wstring subkey =
            MakeTrayEntrySubkey(
                identity
            );

        const std::wstring executablePath =
            QueryStringValue(
                subkey,
                L"ExecutablePath"
            );

        if (
            !IsWindowsAppsPath(
                executablePath
            )
        ) {
            continue;
        }

        windowsAppsEntries++;

        RegistryRecord record =
            ReadRegistryRecord(
                identity,
                static_cast<unsigned long long>(
                    index +
                    1
                )
            );

        if (!record.package.valid) {
            packageParseFailures++;

            Wh_Log(
                L"PACKAGE_FALLBACK_PARSE_FAILURE "
                L"id=%llu "
                L"position=%llu "
                L"path=\"%s\"",
                static_cast<unsigned long long>(
                    record.identity
                ),
                record.oneBasedPosition,
                record.executablePath.c_str()
            );

            continue;
        }

        parsedPackageEntries++;

        if (record.installState.installed) {
            installedRecords++;
        } else {
            unavailableRecords++;
        }

        if (record.discriminator.empty()) {
            recordsWithoutDiscriminator++;
        }

        if (record.fallbackKey.empty()) {
            unkeyedRecords++;

            Wh_Log(
                L"PACKAGE_FALLBACK_UNKEYED "
                L"id=%llu "
                L"position=%llu "
                L"packageFullName=\"%s\" "
                L"relativePath=\"%s\"",
                static_cast<unsigned long long>(
                    record.identity
                ),
                record.oneBasedPosition,
                record.package.packageFullName.c_str(),
                record.package.relativeExecutablePath.c_str()
            );

            continue;
        }

        groups[
            record.fallbackKey
        ].push_back(
            std::move(
                record
            )
        );
    }

    unsigned long long fallbackGroupCount =
        0;

    unsigned long long multiRecordGroupCount =
        0;

    unsigned long long multiRecordMemberCount =
        0;

    unsigned long long versionSpanningGroupCount =
        0;

    unsigned long long sameFullNameDuplicateGroupCount =
        0;

    unsigned long long singleInstalledGroupCount =
        0;

    unsigned long long noInstalledGroupCount =
        0;

    unsigned long long ambiguousInstalledGroupCount =
        0;

    unsigned long long historicalChainCandidateCount =
        0;

    for (
        const auto& groupPair :
        groups
    ) {
        fallbackGroupCount++;

        const std::wstring& fallbackKey =
            groupPair.first;

        const std::vector<RegistryRecord>& members =
            groupPair.second;

        if (members.size() < 2) {
            continue;
        }

        multiRecordGroupCount++;

        multiRecordMemberCount +=
            static_cast<unsigned long long>(
                members.size()
            );

        std::set<std::wstring>
            packageFullNames;

        std::set<std::wstring>
            discriminators;

        std::map<
            std::wstring,
            unsigned long long
        > packageFullNameCounts;

        unsigned long long installedMembers =
            0;

        bool everyMemberHasDiscriminator =
            true;

        for (
            const RegistryRecord& member :
            members
        ) {
            const std::wstring normalizedFullName =
                ToLower(
                    member.package.packageFullName
                );

            packageFullNames.insert(
                normalizedFullName
            );

            packageFullNameCounts[
                normalizedFullName
            ]++;

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

            if (
                member.installState.installed
            ) {
                installedMembers++;
            }
        }

        bool sameFullNameDuplicate =
            false;

        for (
            const auto& count :
            packageFullNameCounts
        ) {
            if (count.second > 1) {
                sameFullNameDuplicate =
                    true;

                break;
            }
        }

        const bool spansVersions =
            packageFullNames.size() >
            1;

        const bool singleInstalled =
            installedMembers ==
            1;

        const bool noInstalled =
            installedMembers ==
            0;

        const bool ambiguousInstalled =
            installedMembers >
            1;

        const bool everyRecordHasUniqueFullName =
            packageFullNames.size() ==
            members.size();

        const bool everyDiscriminatorIsUnique =
            everyMemberHasDiscriminator &&
            discriminators.size() ==
                members.size();

        const bool historicalChainCandidate =
            spansVersions &&
            singleInstalled &&
            everyRecordHasUniqueFullName &&
            everyDiscriminatorIsUnique &&
            !sameFullNameDuplicate;

        if (spansVersions) {
            versionSpanningGroupCount++;
        }

        if (sameFullNameDuplicate) {
            sameFullNameDuplicateGroupCount++;
        }

        if (singleInstalled) {
            singleInstalledGroupCount++;
        }

        if (noInstalled) {
            noInstalledGroupCount++;
        }

        if (ambiguousInstalled) {
            ambiguousInstalledGroupCount++;
        }

        if (historicalChainCandidate) {
            historicalChainCandidateCount++;
        }

        Wh_Log(
            L"PACKAGE_FALLBACK_GROUP "
            L"group=%llu "
            L"memberCount=%llu "
            L"uniquePackageFullNames=%llu "
            L"uniqueDiscriminators=%llu "
            L"installedMembers=%llu "
            L"staleMembers=%llu "
            L"spansVersions=%d "
            L"sameFullNameDuplicate=%d "
            L"singleInstalled=%d "
            L"noInstalled=%d "
            L"ambiguousInstalled=%d "
            L"historicalChainCandidate=%d "
            L"key=\"%s\"",
            multiRecordGroupCount,
            static_cast<unsigned long long>(
                members.size()
            ),
            static_cast<unsigned long long>(
                packageFullNames.size()
            ),
            static_cast<unsigned long long>(
                discriminators.size()
            ),
            installedMembers,
            static_cast<unsigned long long>(
                members.size()
            ) -
                installedMembers,
            spansVersions
                ? 1
                : 0,
            sameFullNameDuplicate
                ? 1
                : 0,
            singleInstalled
                ? 1
                : 0,
            noInstalled
                ? 1
                : 0,
            ambiguousInstalled
                ? 1
                : 0,
            historicalChainCandidate
                ? 1
                : 0,
            fallbackKey.c_str()
        );

        for (
            std::size_t memberIndex = 0;
            memberIndex < members.size();
            memberIndex++
        ) {
            const RegistryRecord& member =
                members[
                    memberIndex
                ];

            Wh_Log(
                L"PACKAGE_FALLBACK_GROUP_MEMBER "
                L"group=%llu "
                L"member=%llu "
                L"id=%llu "
                L"position=%llu "
                L"installed=%d "
                L"installQueryStatus=%ld "
                L"installPathStatus=%ld "
                L"packageFamily=\"%s\" "
                L"packageFullName=\"%s\" "
                L"version=\"%s\" "
                L"architecture=\"%s\" "
                L"resourceId=\"%s\" "
                L"relativePath=\"%s\" "
                L"discriminator=\"%s\" "
                L"tooltip=\"%s\" "
                L"installedPath=\"%s\" "
                L"fullPath=\"%s\"",
                multiRecordGroupCount,
                static_cast<unsigned long long>(
                    memberIndex +
                    1
                ),
                static_cast<unsigned long long>(
                    member.identity
                ),
                member.oneBasedPosition,
                member.installState.installed
                    ? 1
                    : 0,
                member.installState.queryStatus,
                member.installState.pathStatus,
                member.package.packageFamilyName.c_str(),
                member.package.packageFullName.c_str(),
                member.package.packageVersion.c_str(),
                member.package.architecture.c_str(),
                member.package.resourceId.c_str(),
                member.package.relativeExecutablePath.c_str(),
                member.discriminator.c_str(),
                member.initialTooltip.c_str(),
                member.installState.installedPath.c_str(),
                member.executablePath.c_str()
            );
        }
    }

    Wh_Log(
        L"PACKAGE_FALLBACK_AUDIT_SUMMARY "
        L"uiOrderEntries=%llu "
        L"windowsAppsEntries=%llu "
        L"parsedPackageEntries=%llu "
        L"packageParseFailures=%llu "
        L"installedRecords=%llu "
        L"unavailableRecords=%llu "
        L"recordsWithoutDiscriminator=%llu "
        L"unkeyedRecords=%llu "
        L"fallbackGroups=%llu "
        L"multiRecordGroups=%llu "
        L"multiRecordMembers=%llu "
        L"versionSpanningGroups=%llu "
        L"sameFullNameDuplicateGroups=%llu "
        L"singleInstalledGroups=%llu "
        L"noInstalledGroups=%llu "
        L"ambiguousInstalledGroups=%llu "
        L"historicalChainCandidates=%llu "
        L"packagePathApiAvailable=%d",
        static_cast<unsigned long long>(
            snapshot.entries.size()
        ),
        windowsAppsEntries,
        parsedPackageEntries,
        packageParseFailures,
        installedRecords,
        unavailableRecords,
        recordsWithoutDiscriminator,
        unkeyedRecords,
        fallbackGroupCount,
        multiRecordGroupCount,
        multiRecordMemberCount,
        versionSpanningGroupCount,
        sameFullNameDuplicateGroupCount,
        singleInstalledGroupCount,
        noInstalledGroupCount,
        ambiguousInstalledGroupCount,
        historicalChainCandidateCount,
        g_getPackagePathByFullName
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
        L"0.13.0 initializing"
    );

    if (!IsPrimaryShellProcess()) {
        Wh_Log(
            L"PACKAGE_FALLBACK_AUDIT_SKIPPED "
            L"reason=\"non-primary Explorer process\" "
            L"processId=%lu",
            GetCurrentProcessId()
        );

        return TRUE;
    }

    LoadPackagePathFunction();

    Wh_Log(
        L"PACKAGE_FALLBACK_AUDIT_BEGIN "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    RunFallbackIdentityAudit();

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
