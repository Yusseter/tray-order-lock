// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Audits candidate logical identities for packaged tray icons.
// @version         0.11.0
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

Version 0.11.0 audits existing notification-area registry records whose
ExecutablePath is located under WindowsApps.

For each packaged record, it derives a candidate logical identity from:

- Package family name.
- Executable path relative to the package directory.
- IconGuid when present, otherwise UID.

Package full names contain version, architecture, and resource information.
The candidate key intentionally excludes those changing fields while retaining
the stable package name and publisher ID.

The analyzer reports only duplicate candidate groups, allowing records from
different installed package versions to be compared.

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
#include <cwctype>
#include <map>
#include <set>
#include <string>
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

struct RegistryRecord {
    std::uint64_t identity =
        0;

    unsigned long long oneBasedPosition =
        0;

    std::wstring executablePath;
    std::wstring publisher;
    std::wstring initialTooltip;

    bool uidValid =
        false;

    DWORD uid =
        0;

    bool iconGuidValid =
        false;

    GUID iconGuid{};

    PackagePathInfo package;
    std::wstring discriminator;
    std::wstring logicalKey;
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
        resultBytes !=
            sizeof(result)
    ) {
        return false;
    }

    *value =
        result;

    return true;
}

bool QueryGuidValue(
    const std::wstring& subkey,
    const wchar_t* valueName,
    GUID* value
) {
    if (!value) {
        return false;
    }

    DWORD registryType =
        REG_NONE;

    GUID result{};

    DWORD resultBytes =
        sizeof(result);

    const LONG status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            valueName,
            RRF_RT_REG_BINARY,
            &registryType,
            &result,
            &resultBytes
        );

    if (
        status != ERROR_SUCCESS ||
        resultBytes !=
            sizeof(result)
    ) {
        return false;
    }

    *value =
        result;

    return true;
}

bool IsZeroGuid(
    const GUID& value
) {
    const GUID zero{};

    return
        std::memcmp(
            &value,
            &zero,
            sizeof(GUID)
        ) ==
        0;
}

std::wstring FormatGuid(
    const GUID& guid
) {
    wchar_t buffer[
        64
    ]{};

    swprintf_s(
        buffer,
        L"{%08X-%04X-%04X-"
        L"%02X%02X-"
        L"%02X%02X%02X%02X%02X%02X}",
        static_cast<unsigned int>(
            guid.Data1
        ),
        static_cast<unsigned int>(
            guid.Data2
        ),
        static_cast<unsigned int>(
            guid.Data3
        ),
        static_cast<unsigned int>(
            guid.Data4[0]
        ),
        static_cast<unsigned int>(
            guid.Data4[1]
        ),
        static_cast<unsigned int>(
            guid.Data4[2]
        ),
        static_cast<unsigned int>(
            guid.Data4[3]
        ),
        static_cast<unsigned int>(
            guid.Data4[4]
        ),
        static_cast<unsigned int>(
            guid.Data4[5]
        ),
        static_cast<unsigned int>(
            guid.Data4[6]
        ),
        static_cast<unsigned int>(
            guid.Data4[7]
        )
    );

    return
        std::wstring(
            buffer
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

std::wstring BuildDiscriminator(
    const RegistryRecord& record
) {
    if (
        record.iconGuidValid &&
        !IsZeroGuid(
            record.iconGuid
        )
    ) {
        return
            L"guid:" +
            ToLower(
                FormatGuid(
                    record.iconGuid
                )
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

std::wstring BuildLogicalKey(
    const RegistryRecord& record
) {
    if (
        !record.package.valid ||
        record.discriminator.empty()
    ) {
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
        ) +
        L"|" +
        record.discriminator;
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

    record.iconGuidValid =
        QueryGuidValue(
            subkey,
            L"IconGuid",
            &record.iconGuid
        );

    ExtractPackagePathInfo(
        record.executablePath,
        &record.package
    );

    record.discriminator =
        BuildDiscriminator(
            record
        );

    record.logicalKey =
        BuildLogicalKey(
            record
        );

    return record;
}

void RunPackageIdentityAudit() {
    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    if (!snapshot.valid) {
        Wh_Log(
            L"PACKAGE_IDENTITY_AUDIT_FAILED "
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

    unsigned long long guidPackageEntries =
        0;

    unsigned long long uidPackageEntries =
        0;

    unsigned long long unkeyedPackageEntries =
        0;

    for (
        std::size_t index = 0;
        index < snapshot.entries.size();
        index++
    ) {
        const std::uint64_t identity =
            snapshot.entries[index];

        RegistryRecord record =
            ReadRegistryRecord(
                identity,
                static_cast<unsigned long long>(
                    index +
                    1
                )
            );

        const std::wstring normalizedPath =
            NormalizePath(
                record.executablePath
            );

        const std::wstring lowerPath =
            ToLower(
                normalizedPath
            );

        if (
            lowerPath.find(
                kWindowsAppsMarker
            ) ==
            std::wstring::npos
        ) {
            continue;
        }

        windowsAppsEntries++;

        if (!record.package.valid) {
            packageParseFailures++;

            Wh_Log(
                L"PACKAGE_PARSE_FAILURE "
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

        if (
            record.iconGuidValid &&
            !IsZeroGuid(
                record.iconGuid
            )
        ) {
            guidPackageEntries++;
        } else if (record.uidValid) {
            uidPackageEntries++;
        }

        if (record.logicalKey.empty()) {
            unkeyedPackageEntries++;

            Wh_Log(
                L"PACKAGE_UNKEYED_RECORD "
                L"id=%llu "
                L"position=%llu "
                L"packageFullName=\"%s\" "
                L"relativePath=\"%s\" "
                L"uidValid=%d "
                L"uid=%u "
                L"guidValid=%d "
                L"guid=\"%s\"",
                static_cast<unsigned long long>(
                    record.identity
                ),
                record.oneBasedPosition,
                record.package.packageFullName.c_str(),
                record.package.relativeExecutablePath.c_str(),
                record.uidValid
                    ? 1
                    : 0,
                record.uid,
                record.iconGuidValid
                    ? 1
                    : 0,
                record.iconGuidValid
                    ? FormatGuid(
                          record.iconGuid
                      ).c_str()
                    : L""
            );

            continue;
        }

        groups[
            record.logicalKey
        ].push_back(
            std::move(
                record
            )
        );
    }

    unsigned long long logicalGroupCount =
        0;

    unsigned long long duplicateGroupCount =
        0;

    unsigned long long duplicateMemberCount =
        0;

    unsigned long long versionSpanningGroupCount =
        0;

    unsigned long long sameFullNameDuplicateGroupCount =
        0;

    for (
        const auto& groupPair :
        groups
    ) {
        logicalGroupCount++;

        const std::wstring& logicalKey =
            groupPair.first;

        const std::vector<RegistryRecord>& members =
            groupPair.second;

        if (members.size() < 2) {
            continue;
        }

        duplicateGroupCount++;

        duplicateMemberCount +=
            static_cast<unsigned long long>(
                members.size()
            );

        std::set<std::wstring> packageFullNames;

        for (
            const RegistryRecord& member :
            members
        ) {
            packageFullNames.insert(
                ToLower(
                    member.package.packageFullName
                )
            );
        }

        const bool spansVersions =
            packageFullNames.size() >
            1;

        const bool sameFullNameDuplicate =
            packageFullNames.size() <
            members.size();

        if (spansVersions) {
            versionSpanningGroupCount++;
        }

        if (sameFullNameDuplicate) {
            sameFullNameDuplicateGroupCount++;
        }

        Wh_Log(
            L"PACKAGE_LOGICAL_GROUP "
            L"group=%llu "
            L"memberCount=%llu "
            L"uniquePackageFullNames=%llu "
            L"spansVersions=%d "
            L"sameFullNameDuplicate=%d "
            L"key=\"%s\"",
            duplicateGroupCount,
            static_cast<unsigned long long>(
                members.size()
            ),
            static_cast<unsigned long long>(
                packageFullNames.size()
            ),
            spansVersions
                ? 1
                : 0,
            sameFullNameDuplicate
                ? 1
                : 0,
            logicalKey.c_str()
        );

        for (
            std::size_t memberIndex = 0;
            memberIndex < members.size();
            memberIndex++
        ) {
            const RegistryRecord& member =
                members[memberIndex];

            Wh_Log(
                L"PACKAGE_LOGICAL_GROUP_MEMBER "
                L"group=%llu "
                L"member=%llu "
                L"id=%llu "
                L"position=%llu "
                L"packageFamily=\"%s\" "
                L"packageFullName=\"%s\" "
                L"version=\"%s\" "
                L"architecture=\"%s\" "
                L"resourceId=\"%s\" "
                L"relativePath=\"%s\" "
                L"discriminator=\"%s\" "
                L"publisher=\"%s\" "
                L"tooltip=\"%s\" "
                L"fullPath=\"%s\"",
                duplicateGroupCount,
                static_cast<unsigned long long>(
                    memberIndex +
                    1
                ),
                static_cast<unsigned long long>(
                    member.identity
                ),
                member.oneBasedPosition,
                member.package.packageFamilyName.c_str(),
                member.package.packageFullName.c_str(),
                member.package.packageVersion.c_str(),
                member.package.architecture.c_str(),
                member.package.resourceId.c_str(),
                member.package.relativeExecutablePath.c_str(),
                member.discriminator.c_str(),
                member.publisher.c_str(),
                member.initialTooltip.c_str(),
                member.executablePath.c_str()
            );
        }
    }

    Wh_Log(
        L"PACKAGE_IDENTITY_AUDIT_SUMMARY "
        L"uiOrderEntries=%llu "
        L"windowsAppsEntries=%llu "
        L"parsedPackageEntries=%llu "
        L"packageParseFailures=%llu "
        L"guidPackageEntries=%llu "
        L"uidPackageEntries=%llu "
        L"unkeyedPackageEntries=%llu "
        L"logicalGroups=%llu "
        L"duplicateGroups=%llu "
        L"duplicateMembers=%llu "
        L"versionSpanningGroups=%llu "
        L"sameFullNameDuplicateGroups=%llu",
        static_cast<unsigned long long>(
            snapshot.entries.size()
        ),
        windowsAppsEntries,
        parsedPackageEntries,
        packageParseFailures,
        guidPackageEntries,
        uidPackageEntries,
        unkeyedPackageEntries,
        logicalGroupCount,
        duplicateGroupCount,
        duplicateMemberCount,
        versionSpanningGroupCount,
        sameFullNameDuplicateGroupCount
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
        L"0.11.0 initializing"
    );

    if (!IsPrimaryShellProcess()) {
        Wh_Log(
            L"PACKAGE_IDENTITY_AUDIT_SKIPPED "
            L"reason=\"non-primary Explorer process\" "
            L"processId=%lu",
            GetCurrentProcessId()
        );

        return TRUE;
    }

    Wh_Log(
        L"PACKAGE_IDENTITY_AUDIT_BEGIN "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    RunPackageIdentityAudit();

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
