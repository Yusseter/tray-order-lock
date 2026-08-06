// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Audits raw UID and IconGuid registry representations for packaged tray icons.
// @version         0.12.0
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

Version 0.12.0 audits the raw registry representation of the UID and IconGuid
values belonging to notification-area records under WindowsApps.

For every packaged record, the analyzer reports:

- Registry value existence and query status.
- Registry value type.
- Raw byte length.
- Raw hexadecimal contents.
- A decoded numeric or GUID interpretation when possible.
- Package full name and executable path relative to the package directory.

This determines why version 0.11.0 could read only a small subset of packaged
icon discriminators.

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

struct RawRegistryValue {
    bool exists =
        false;

    LONG status =
        ERROR_SUCCESS;

    DWORD type =
        REG_NONE;

    std::vector<BYTE> data;
};

struct PackagePathInfo {
    bool valid =
        false;

    std::wstring packageFullName;
    std::wstring relativeExecutablePath;
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

RawRegistryValue QueryRawRegistryValue(
    const std::wstring& subkey,
    const wchar_t* valueName
) {
    RawRegistryValue result;

    HKEY key =
        nullptr;

    LONG status =
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            0,
            KEY_QUERY_VALUE,
            &key
        );

    if (status != ERROR_SUCCESS) {
        result.status =
            status;

        return result;
    }

    for (
        int attempt = 0;
        attempt < 3;
        attempt++
    ) {
        DWORD type =
            REG_NONE;

        DWORD requiredBytes =
            0;

        status =
            RegQueryValueExW(
                key,
                valueName,
                nullptr,
                &type,
                nullptr,
                &requiredBytes
            );

        if (status != ERROR_SUCCESS) {
            result.status =
                status;

            result.type =
                type;

            break;
        }

        std::vector<BYTE> data(
            requiredBytes
        );

        DWORD actualBytes =
            requiredBytes;

        status =
            RegQueryValueExW(
                key,
                valueName,
                nullptr,
                &type,
                data.empty()
                    ? nullptr
                    : data.data(),
                &actualBytes
            );

        if (status == ERROR_MORE_DATA) {
            continue;
        }

        result.status =
            status;

        result.type =
            type;

        if (status != ERROR_SUCCESS) {
            break;
        }

        data.resize(
            actualBytes
        );

        result.exists =
            true;

        result.data =
            std::move(
                data
            );

        break;
    }

    RegCloseKey(
        key
    );

    return result;
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

    package->valid =
        true;

    return true;
}

const wchar_t* RegistryTypeName(
    DWORD type
) {
    switch (type) {
        case REG_NONE:
            return L"REG_NONE";

        case REG_SZ:
            return L"REG_SZ";

        case REG_EXPAND_SZ:
            return L"REG_EXPAND_SZ";

        case REG_BINARY:
            return L"REG_BINARY";

        case REG_DWORD:
            return L"REG_DWORD";

        case REG_DWORD_BIG_ENDIAN:
            return L"REG_DWORD_BIG_ENDIAN";

        case REG_LINK:
            return L"REG_LINK";

        case REG_MULTI_SZ:
            return L"REG_MULTI_SZ";

        case REG_RESOURCE_LIST:
            return L"REG_RESOURCE_LIST";

        case REG_FULL_RESOURCE_DESCRIPTOR:
            return L"REG_FULL_RESOURCE_DESCRIPTOR";

        case REG_RESOURCE_REQUIREMENTS_LIST:
            return L"REG_RESOURCE_REQUIREMENTS_LIST";

        case REG_QWORD:
            return L"REG_QWORD";

        default:
            return L"REG_UNKNOWN";
    }
}

std::wstring FormatHex(
    const std::vector<BYTE>& data
) {
    std::wstring result;

    for (
        std::size_t index = 0;
        index < data.size();
        index++
    ) {
        if (index != 0) {
            result +=
                L' ';
        }

        wchar_t byteText[
            4
        ]{};

        swprintf_s(
            byteText,
            L"%02X",
            static_cast<unsigned int>(
                data[index]
            )
        );

        result +=
            byteText;
    }

    return result;
}

std::wstring DecodeWideString(
    const RawRegistryValue& value
) {
    if (
        !value.exists ||
        (
            value.type !=
                REG_SZ &&
            value.type !=
                REG_EXPAND_SZ &&
            value.type !=
                REG_MULTI_SZ
        ) ||
        value.data.empty() ||
        value.data.size() %
            sizeof(wchar_t) !=
        0
    ) {
        return L"";
    }

    const std::size_t characterCount =
        value.data.size() /
        sizeof(wchar_t);

    std::wstring text(
        characterCount,
        L'\0'
    );

    std::memcpy(
        text.data(),
        value.data.data(),
        value.data.size()
    );

    while (
        !text.empty() &&
        text.back() ==
            L'\0'
    ) {
        text.pop_back();
    }

    for (
        wchar_t& character :
        text
    ) {
        if (character == L'\0') {
            character =
                L'|';
        }
    }

    return text;
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

std::wstring DecodeUidValue(
    const RawRegistryValue& value
) {
    if (!value.exists) {
        return L"";
    }

    if (
        value.type ==
            REG_DWORD &&
        value.data.size() ==
            sizeof(std::uint32_t)
    ) {
        std::uint32_t decoded =
            0;

        std::memcpy(
            &decoded,
            value.data.data(),
            sizeof(decoded)
        );

        return
            L"dword:" +
            std::to_wstring(
                decoded
            );
    }

    if (
        value.type ==
            REG_QWORD &&
        value.data.size() ==
            sizeof(std::uint64_t)
    ) {
        std::uint64_t decoded =
            0;

        std::memcpy(
            &decoded,
            value.data.data(),
            sizeof(decoded)
        );

        return
            L"qword:" +
            std::to_wstring(
                decoded
            );
    }

    if (
        value.type ==
            REG_BINARY &&
        value.data.size() ==
            sizeof(std::uint32_t)
    ) {
        std::uint32_t decoded =
            0;

        std::memcpy(
            &decoded,
            value.data.data(),
            sizeof(decoded)
        );

        return
            L"binary32:" +
            std::to_wstring(
                decoded
            );
    }

    if (
        value.type ==
            REG_BINARY &&
        value.data.size() ==
            sizeof(std::uint64_t)
    ) {
        std::uint64_t decoded =
            0;

        std::memcpy(
            &decoded,
            value.data.data(),
            sizeof(decoded)
        );

        return
            L"binary64:" +
            std::to_wstring(
                decoded
            );
    }

    const std::wstring text =
        DecodeWideString(
            value
        );

    if (!text.empty()) {
        return
            L"text:" +
            text;
    }

    return L"";
}

std::wstring DecodeGuidValue(
    const RawRegistryValue& value
) {
    if (!value.exists) {
        return L"";
    }

    if (
        value.data.size() ==
        sizeof(GUID)
    ) {
        GUID decoded{};

        std::memcpy(
            &decoded,
            value.data.data(),
            sizeof(decoded)
        );

        return
            L"binary-guid:" +
            FormatGuid(
                decoded
            );
    }

    const std::wstring text =
        DecodeWideString(
            value
        );

    if (!text.empty()) {
        return
            L"text-guid:" +
            text;
    }

    return L"";
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

void LogTypeSummary(
    const wchar_t* valueName,
    const std::map<
        DWORD,
        unsigned long long
    >& counts
) {
    for (
        const auto& count :
        counts
    ) {
        Wh_Log(
            L"PACKAGE_RAW_TYPE_SUMMARY "
            L"value=\"%s\" "
            L"type=%lu "
            L"typeName=\"%s\" "
            L"count=%llu",
            valueName,
            count.first,
            RegistryTypeName(
                count.first
            ),
            count.second
        );
    }
}

void RunRawIdentityAudit() {
    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    if (!snapshot.valid) {
        Wh_Log(
            L"PACKAGE_RAW_IDENTITY_AUDIT_FAILED "
            L"registryStatus=%ld",
            snapshot.status
        );

        return;
    }

    unsigned long long windowsAppsEntries =
        0;

    unsigned long long packageParseFailures =
        0;

    unsigned long long uidPresent =
        0;

    unsigned long long uidMissing =
        0;

    unsigned long long uidQueryFailures =
        0;

    unsigned long long uidDecoded =
        0;

    unsigned long long iconGuidPresent =
        0;

    unsigned long long iconGuidMissing =
        0;

    unsigned long long iconGuidQueryFailures =
        0;

    unsigned long long iconGuidDecoded =
        0;

    unsigned long long recordsWithUidOnly =
        0;

    unsigned long long recordsWithGuidOnly =
        0;

    unsigned long long recordsWithBoth =
        0;

    unsigned long long recordsWithNeither =
        0;

    std::map<
        DWORD,
        unsigned long long
    > uidTypeCounts;

    std::map<
        DWORD,
        unsigned long long
    > iconGuidTypeCounts;

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

        const std::wstring normalizedPath =
            NormalizePath(
                executablePath
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

        PackagePathInfo package;

        if (
            !ExtractPackagePathInfo(
                executablePath,
                &package
            )
        ) {
            packageParseFailures++;

            Wh_Log(
                L"PACKAGE_RAW_PATH_PARSE_FAILURE "
                L"id=%llu "
                L"position=%llu "
                L"path=\"%s\"",
                static_cast<unsigned long long>(
                    identity
                ),
                static_cast<unsigned long long>(
                    index +
                    1
                ),
                executablePath.c_str()
            );

            continue;
        }

        const RawRegistryValue uid =
            QueryRawRegistryValue(
                subkey,
                L"UID"
            );

        const RawRegistryValue iconGuid =
            QueryRawRegistryValue(
                subkey,
                L"IconGuid"
            );

        if (uid.exists) {
            uidPresent++;

            uidTypeCounts[
                uid.type
            ]++;
        } else if (
            uid.status ==
                ERROR_FILE_NOT_FOUND
        ) {
            uidMissing++;
        } else {
            uidQueryFailures++;
        }

        if (iconGuid.exists) {
            iconGuidPresent++;

            iconGuidTypeCounts[
                iconGuid.type
            ]++;
        } else if (
            iconGuid.status ==
                ERROR_FILE_NOT_FOUND
        ) {
            iconGuidMissing++;
        } else {
            iconGuidQueryFailures++;
        }

        if (
            uid.exists &&
            iconGuid.exists
        ) {
            recordsWithBoth++;
        } else if (uid.exists) {
            recordsWithUidOnly++;
        } else if (iconGuid.exists) {
            recordsWithGuidOnly++;
        } else {
            recordsWithNeither++;
        }

        const std::wstring uidHex =
            FormatHex(
                uid.data
            );

        const std::wstring uidDecodedText =
            DecodeUidValue(
                uid
            );

        const std::wstring iconGuidHex =
            FormatHex(
                iconGuid.data
            );

        const std::wstring iconGuidDecodedText =
            DecodeGuidValue(
                iconGuid
            );

        if (!uidDecodedText.empty()) {
            uidDecoded++;
        }

        if (!iconGuidDecodedText.empty()) {
            iconGuidDecoded++;
        }

        Wh_Log(
            L"PACKAGE_RAW_IDENTITY_VALUES "
            L"id=%llu "
            L"position=%llu "
            L"packageFullName=\"%s\" "
            L"relativePath=\"%s\" "
            L"uidExists=%d "
            L"uidStatus=%ld "
            L"uidType=%lu "
            L"uidTypeName=\"%s\" "
            L"uidBytes=%llu "
            L"uidHex=\"%s\" "
            L"uidDecoded=\"%s\" "
            L"iconGuidExists=%d "
            L"iconGuidStatus=%ld "
            L"iconGuidType=%lu "
            L"iconGuidTypeName=\"%s\" "
            L"iconGuidBytes=%llu "
            L"iconGuidHex=\"%s\" "
            L"iconGuidDecoded=\"%s\" "
            L"fullPath=\"%s\"",
            static_cast<unsigned long long>(
                identity
            ),
            static_cast<unsigned long long>(
                index +
                    1
            ),
            package.packageFullName.c_str(),
            package.relativeExecutablePath.c_str(),
            uid.exists
                ? 1
                : 0,
            uid.status,
            uid.type,
            RegistryTypeName(
                uid.type
            ),
            static_cast<unsigned long long>(
                uid.data.size()
            ),
            uidHex.c_str(),
            uidDecodedText.c_str(),
            iconGuid.exists
                ? 1
                : 0,
            iconGuid.status,
            iconGuid.type,
            RegistryTypeName(
                iconGuid.type
            ),
            static_cast<unsigned long long>(
                iconGuid.data.size()
            ),
            iconGuidHex.c_str(),
            iconGuidDecodedText.c_str(),
            executablePath.c_str()
        );
    }

    LogTypeSummary(
        L"UID",
        uidTypeCounts
    );

    LogTypeSummary(
        L"IconGuid",
        iconGuidTypeCounts
    );

    Wh_Log(
        L"PACKAGE_RAW_IDENTITY_AUDIT_SUMMARY "
        L"uiOrderEntries=%llu "
        L"windowsAppsEntries=%llu "
        L"packageParseFailures=%llu "
        L"uidPresent=%llu "
        L"uidMissing=%llu "
        L"uidQueryFailures=%llu "
        L"uidDecoded=%llu "
        L"iconGuidPresent=%llu "
        L"iconGuidMissing=%llu "
        L"iconGuidQueryFailures=%llu "
        L"iconGuidDecoded=%llu "
        L"recordsWithUidOnly=%llu "
        L"recordsWithGuidOnly=%llu "
        L"recordsWithBoth=%llu "
        L"recordsWithNeither=%llu",
        static_cast<unsigned long long>(
            snapshot.entries.size()
        ),
        windowsAppsEntries,
        packageParseFailures,
        uidPresent,
        uidMissing,
        uidQueryFailures,
        uidDecoded,
        iconGuidPresent,
        iconGuidMissing,
        iconGuidQueryFailures,
        iconGuidDecoded,
        recordsWithUidOnly,
        recordsWithGuidOnly,
        recordsWithBoth,
        recordsWithNeither
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
        L"0.12.0 initializing"
    );

    if (!IsPrimaryShellProcess()) {
        Wh_Log(
            L"PACKAGE_RAW_IDENTITY_AUDIT_SKIPPED "
            L"reason=\"non-primary Explorer process\" "
            L"processId=%lu",
            GetCurrentProcessId()
        );

        return TRUE;
    }

    Wh_Log(
        L"PACKAGE_RAW_IDENTITY_AUDIT_BEGIN "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    RunRawIdentityAudit();

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
