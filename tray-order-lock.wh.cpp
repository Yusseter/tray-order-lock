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

Version 0.2.0 adds persistent manual ordering and automatic restoration of known tray icons.

Version 0.2.0 functionality:

- Lock all reordering:
  preserves the 0.1.0 behavior and blocks tray move requests.
- Preserve order, allow manual changes:
  allows Windows to perform manual tray moves and learns the resulting
  canonical logical order.
- Canonical logical order is persisted in Windhawk local storage and survives
  complete Explorer process restarts.
- Live NotificationAreaIcon2 objects are mapped to the 64-bit
  NotifyIconSettings/UIOrderList identity used by Windows.
- Manual moves use the live ABI-to-Windows-identity mapping whenever available.
- A conservative UIOrderList before/after comparison remains as a fallback for
  icons which were constructed before the live mapping hook was installed.

Logical identity currently uses:

- IconGuid when available.
- Otherwise, version-normalized executable path plus UID.

Ambiguous or unsupported logical identities are not learned automatically.

In Preserve order mode, returning known icons are restored automatically when
their live canonical relation is violated. Restoration uses Windows' own
NotificationAreaIconManager2::MoveIcon path and never writes UIOrderList
directly. New icons can either keep Windows' default position or be placed at
the end of the overflow area. Ambiguous icons are left untouched.
*/
// ==/WindhawkModReadme==

// ==WindhawkModSettings==
/*
- orderingBehavior: lockAll
  $name: Ordering behavior
  $options:
    - lockAll: Lock all reordering
    - preserveManual: Preserve order, allow manual changes

- newIconBehavior: windowsDefault
  $name: New icon placement
  $options:
    - windowsDefault: Use Windows default position
    - placeAtEnd: Place new icons at the end
*/
// ==/WindhawkModSettings==

#include <windows.h>
#include <objbase.h>
#include <unknwn.h>
#include <windhawk_utils.h>

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr wchar_t kPersistentDevelopmentLogBuild[] =
    L"0.2.0-dev-order-drift-persistent-package-history";

std::mutex g_persistentDevelopmentLogMutex;
HANDLE g_persistentDevelopmentLogFile = INVALID_HANDLE_VALUE;
std::wstring g_persistentDevelopmentLogPath;
bool g_persistentDevelopmentLogInitialized = false;

bool EnsurePersistentDevelopmentLogDirectory(
    const std::wstring& path
) {
    const DWORD attributes =
        GetFileAttributesW(path.c_str());

    if (attributes != INVALID_FILE_ATTRIBUTES) {
        return
            (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }

    if (CreateDirectoryW(path.c_str(), nullptr)) {
        return true;
    }

    return GetLastError() == ERROR_ALREADY_EXISTS;
}

void WritePersistentDevelopmentLogRawLocked(
    const std::wstring& text
) {
    if (
        g_persistentDevelopmentLogFile ==
            INVALID_HANDLE_VALUE
    ) {
        return;
    }

    DWORD written = 0;

    WriteFile(
        g_persistentDevelopmentLogFile,
        text.data(),
        static_cast<DWORD>(
            text.size() * sizeof(wchar_t)
        ),
        &written,
        nullptr
    );
}

void InitializePersistentDevelopmentLogLocked() {
    if (g_persistentDevelopmentLogInitialized) {
        return;
    }

    g_persistentDevelopmentLogInitialized = true;

    wchar_t localAppData[32768]{};

    const DWORD length =
        GetEnvironmentVariableW(
            L"LOCALAPPDATA",
            localAppData,
            ARRAYSIZE(localAppData)
        );

    if (!length || length >= ARRAYSIZE(localAppData)) {
        return;
    }

    std::wstring rootDirectory(localAppData, length);
    rootDirectory += L"\\TrayOrderLock";

    if (!EnsurePersistentDevelopmentLogDirectory(rootDirectory)) {
        return;
    }

    std::wstring logDirectory =
        rootDirectory + L"\\Logs";

    if (!EnsurePersistentDevelopmentLogDirectory(logDirectory)) {
        return;
    }

    SYSTEMTIME now{};
    GetLocalTime(&now);

    wchar_t fileName[256]{};

    _snwprintf_s(
        fileName,
        ARRAYSIZE(fileName),
        _TRUNCATE,
        L"\\tray-order-lock-%04u%02u%02u-%02u%02u%02u-%03u-pid%lu.log",
        now.wYear,
        now.wMonth,
        now.wDay,
        now.wHour,
        now.wMinute,
        now.wSecond,
        now.wMilliseconds,
        GetCurrentProcessId()
    );

    g_persistentDevelopmentLogPath =
        logDirectory + fileName;

    g_persistentDevelopmentLogFile =
        CreateFileW(
            g_persistentDevelopmentLogPath.c_str(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ |
                FILE_SHARE_WRITE |
                FILE_SHARE_DELETE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

    if (
        g_persistentDevelopmentLogFile ==
            INVALID_HANDLE_VALUE
    ) {
        g_persistentDevelopmentLogPath.clear();
        return;
    }

    LARGE_INTEGER size{};

    if (
        GetFileSizeEx(
            g_persistentDevelopmentLogFile,
            &size
        ) &&
        size.QuadPart == 0
    ) {
        const wchar_t bom = 0xFEFF;
        DWORD written = 0;

        WriteFile(
            g_persistentDevelopmentLogFile,
            &bom,
            sizeof(bom),
            &written,
            nullptr
        );
    }

    wchar_t header[4096]{};

    _snwprintf_s(
        header,
        ARRAYSIZE(header),
        _TRUNCATE,
        L"# Tray Order Lock persistent development log\r\n"
        L"# build=%s\r\n"
        L"# started=%04u-%02u-%02u %02u:%02u:%02u.%03u\r\n"
        L"# processId=%lu\r\n"
        L"# path=%s\r\n",
        kPersistentDevelopmentLogBuild,
        now.wYear,
        now.wMonth,
        now.wDay,
        now.wHour,
        now.wMinute,
        now.wSecond,
        now.wMilliseconds,
        GetCurrentProcessId(),
        g_persistentDevelopmentLogPath.c_str()
    );

    WritePersistentDevelopmentLogRawLocked(header);

    Wh_Log(
        L"TRAY_ORDER_LOCK_PERSISTENT_LOG_READY "
        L"build=%s path=\"%s\"",
        kPersistentDevelopmentLogBuild,
        g_persistentDevelopmentLogPath.c_str()
    );
}

void AppendPersistentDevelopmentLog(
    int sourceLine,
    const char* sourceFunction,
    const wchar_t* message
) {
    SYSTEMTIME now{};
    GetLocalTime(&now);

    wchar_t prefix[512]{};

    _snwprintf_s(
        prefix,
        ARRAYSIZE(prefix),
        _TRUNCATE,
        L"%04u-%02u-%02u %02u:%02u:%02u.%03u "
        L"pid=%lu tid=%lu source=%d:%S | ",
        now.wYear,
        now.wMonth,
        now.wDay,
        now.wHour,
        now.wMinute,
        now.wSecond,
        now.wMilliseconds,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        sourceLine,
        sourceFunction
    );

    std::wstring output = prefix;
    output += message;
    output += L"\r\n";

    std::lock_guard<std::mutex> lock(
        g_persistentDevelopmentLogMutex
    );

    InitializePersistentDevelopmentLogLocked();
    WritePersistentDevelopmentLogRawLocked(output);
}

void PersistentWhLog(
    int sourceLine,
    const char* sourceFunction,
    const wchar_t* format,
    ...
) {
    wchar_t message[32768]{};

    va_list args;
    va_start(args, format);

    _vsnwprintf_s(
        message,
        ARRAYSIZE(message),
        _TRUNCATE,
        format,
        args
    );

    va_end(args);

    AppendPersistentDevelopmentLog(
        sourceLine,
        sourceFunction,
        message
    );

    Wh_Log(
        L"[source=%d:%S] %s",
        sourceLine,
        sourceFunction,
        message
    );
}

void ClosePersistentDevelopmentLog() {
    std::lock_guard<std::mutex> lock(
        g_persistentDevelopmentLogMutex
    );

    if (
        g_persistentDevelopmentLogFile !=
            INVALID_HANDLE_VALUE
    ) {
        FlushFileBuffers(
            g_persistentDevelopmentLogFile
        );

        CloseHandle(
            g_persistentDevelopmentLogFile
        );

        g_persistentDevelopmentLogFile =
            INVALID_HANDLE_VALUE;
    }

    g_persistentDevelopmentLogPath.clear();
    g_persistentDevelopmentLogInitialized = false;
}

#define TOR_LOG(message, ...) \
    do { \
        PersistentWhLog( \
            __LINE__, \
            __FUNCTION__, \
            message, \
            ##__VA_ARGS__ \
        ); \
    } while (0)

constexpr wchar_t kNotifyIconSettingsPath[] =
    L"Control Panel\\NotifyIconSettings";

constexpr wchar_t kUIOrderListValueName[] =
    L"UIOrderList";

constexpr wchar_t kCanonicalOrderValueName[] =
    L"CanonicalOrderV200";

constexpr wchar_t kLiveBaselineTrustedValueName[] =
    L"CanonicalLiveBaselineTrustedV1";

constexpr wchar_t kLiveBaselineSizeValueName[] =
    L"CanonicalLiveBaselineSizeV1";

constexpr wchar_t kCanonicalStorageHeader[] =
    L"TRAY_ORDER_LOCK_V200";

constexpr std::size_t kMaximumStoredOrderChars =
    262144;

constexpr int kOverflowLocation =
    1;

enum class OrderingBehavior {
    LockAll = 0,
    PreserveManual = 1,
};

enum class NewIconBehavior {
    WindowsDefault = 0,
    PlaceAtEnd = 1,
};

struct UIOrderSnapshot {
    bool valid = false;
    LONG status = ERROR_SUCCESS;

    std::vector<std::uint64_t> entries;
};

struct LogicalSnapshotEntry {
    std::uint64_t identity = 0;
    std::wstring key;
    bool unique = false;
};

struct ContinuityIdentityMetadata {
    bool guidBacked = false;

    DWORD uid = 0;
    std::wstring tooltip;

    std::wstring normalizedExecutablePath;
    std::vector<unsigned int> packageVersion;

    std::vector<BYTE> iconSnapshot;
};

struct LiveIdentityMapping {
    void* implementation = nullptr;
    void* abi = nullptr;
    std::uint64_t windowsIdentity = 0;
};

struct LiveOverflowEntry {
    std::uint64_t windowsIdentity = 0;
    std::wstring logicalKey;

    bool mapped = false;
    bool uniqueLogical = false;
};

struct LiveOverflowSnapshot {
    bool valid = false;

    HRESULT getterResult = E_FAIL;
    HRESULT vectorQueryResult = E_FAIL;
    HRESULT sizeResult = E_FAIL;

    unsigned int size = 0;
    unsigned int mappedEntries = 0;

    bool targetFound = false;
    unsigned int targetIndex = 0;

    std::vector<LiveOverflowEntry> entries;
};

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

using NotificationAreaIconManager_AddVisible_t =
    void(__cdecl*)(
        void* pThis,
        void* iconImplementation
    );

using NotificationAreaIconManager_MoveIcon_t =
    void(__cdecl*)(
        void* pThis,
        void* notificationAreaIconValue,
        int location,
        unsigned int index
    );

using TaskbarModel_GetOverflowIcons_t =
    int(__cdecl*)(
        void* pThis,
        void** result
    );

using Vector_GetAt_t =
    HRESULT(STDMETHODCALLTYPE*)(
        void* pThis,
        unsigned int index,
        void** value
    );

using Vector_GetSize_t =
    HRESULT(STDMETHODCALLTYPE*)(
        void* pThis,
        unsigned int* size
    );

using TaskbarModel_MoveNotificationAreaIcon_t =
    int(__cdecl*)(
        void* pThis,
        void* notificationAreaIconAbi,
        int location,
        unsigned int index
    );

using CreateWindowExW_t =
    decltype(&CreateWindowExW);

NotificationAreaIcon2_Constructor_t
    NotificationAreaIcon2_Constructor_Target =
        nullptr;

NotificationAreaIcon2_Constructor_t
    NotificationAreaIcon2_Constructor_Original =
        nullptr;

NotificationAreaIcon_QueryInterface_t
    NotificationAreaIcon_QueryInterface =
        nullptr;
bool g_queryInterfaceUsesDefaultAbi = false;

NotificationAreaIconManager_AddVisible_t
    NotificationAreaIconManager_AddVisible_Original =
        nullptr;

NotificationAreaIconManager_MoveIcon_t
    NotificationAreaIconManager_MoveIcon =
        nullptr;

TaskbarModel_GetOverflowIcons_t
    TaskbarModel_GetOverflowIcons_Original =
        nullptr;

TaskbarModel_MoveNotificationAreaIcon_t
    TaskbarModel_MoveNotificationAreaIcon_Original =
        nullptr;

const GUID* g_notificationAreaIconInterfaceId =
    nullptr;

const GUID* g_notificationAreaIconVectorId =
    nullptr;

CreateWindowExW_t
    CreateWindowExW_Original =
        nullptr;

std::atomic<void*> g_taskbarModel6 =
    nullptr;

std::atomic<bool> g_taskbarHooksInitializing =
    false;

std::atomic<bool> g_taskbarHooksInitialized =
    false;

std::atomic<int> g_orderingBehavior =
    static_cast<int>(
        OrderingBehavior::LockAll
    );

std::atomic<int> g_newIconBehavior =
    static_cast<int>(
        NewIconBehavior::WindowsDefault
    );

std::atomic<unsigned long long> g_blockedMoveCount =
    0;

std::atomic<unsigned long long> g_allowedMoveCount =
    0;

std::atomic<unsigned long long> g_learnedMoveCount =
    0;

std::atomic<unsigned long long> g_skippedLearningCount =
    0;

std::atomic<unsigned long long> g_liveConstructorCount =
    0;

std::atomic<unsigned long long> g_liveMappingCount =
    0;

std::atomic<unsigned long long> g_liveMappedMoveCount =
    0;

std::atomic<unsigned long long> g_registryFallbackMoveCount =
    0;

std::atomic<unsigned long long> g_visibleAddCount =
    0;

std::atomic<unsigned long long> g_overflowGetterCount =
    0;

std::atomic<unsigned long long> g_restoreObservationCount =
    0;

std::atomic<unsigned long long> g_restoreKnownCandidateCount =
    0;

std::atomic<unsigned long long> g_restoreNewIconCount =
    0;

std::atomic<unsigned long long> g_restoreSkipCount =
    0;

std::atomic<unsigned long long> g_restoreMoveAttemptCount =
    0;

std::atomic<unsigned long long> g_restoreMoveObservedCount =
    0;

std::atomic<unsigned long long> g_restoreMoveVerifiedCount =
    0;

std::atomic<unsigned long long> g_internalForwardedMoveCount =
    0;

std::atomic<unsigned long long> g_restoreSuppressedTaskbarMoveCount =
    0;

std::mutex g_canonicalMutex;

std::vector<std::wstring> g_canonicalOrder;

bool g_canonicalLoadedFromStorage =
    false;

std::atomic<bool> g_liveBaselineTrusted = false;
std::atomic<unsigned int> g_liveBaselineSize = 0;

// An initially untrusted baseline becomes active in the next session.
std::atomic<bool> g_liveBaselineActiveInSession = false;

std::mutex g_liveMappingMutex;

std::vector<LiveIdentityMapping> g_liveMappings;

std::mutex g_restoreRetryMutex;
std::vector<std::uint64_t> g_restoreRetryIdentities;

thread_local unsigned int g_internalMoveDepth =
    0;

thread_local unsigned int g_taskbarMoveDepth =
    0;

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

int CompareVersionParts(
    const std::vector<unsigned int>& left,
    const std::vector<unsigned int>& right
) {
    const std::size_t count =
        std::max(
            left.size(),
            right.size()
        );

    for (std::size_t index = 0; index < count; index++) {
        const unsigned int leftPart =
            index < left.size()
                ? left[index]
                : 0;

        const unsigned int rightPart =
            index < right.size()
                ? right[index]
                : 0;

        if (leftPart < rightPart) {
            return -1;
        }

        if (leftPart > rightPart) {
            return 1;
        }
    }

    return 0;
}

bool ParseNumericDottedVersion(
    const std::wstring& value,
    std::vector<unsigned int>* parts
) {
    if (!parts || !IsNumericDottedVersionCore(value)) {
        return false;
    }

    parts->clear();

    unsigned long long current = 0;
    bool digitSeen = false;

    for (wchar_t character : value) {
        if (character >= L'0' && character <= L'9') {
            current =
                current * 10 +
                static_cast<unsigned int>(
                    character - L'0'
                );

            if (current > 0xFFFFFFFFULL) {
                parts->clear();
                return false;
            }

            digitSeen = true;
            continue;
        }

        if (character != L'.' || !digitSeen) {
            parts->clear();
            return false;
        }

        parts->push_back(
            static_cast<unsigned int>(current)
        );

        current = 0;
        digitSeen = false;
    }

    if (!digitSeen) {
        parts->clear();
        return false;
    }

    parts->push_back(
        static_cast<unsigned int>(current)
    );

    return
        parts->size() >= 2;
}

std::wstring BuildWindowsAppsGuidContinuityPath(
    const std::wstring& executablePath,
    std::vector<unsigned int>* packageVersion
) {
    if (packageVersion) {
        packageVersion->clear();
    }

    std::wstring path =
        ToLower(
            NormalizeSlashes(
                executablePath
            )
        );

    if (path.empty()) {
        return L"";
    }

    const std::wstring marker =
        L"\\windowsapps\\";

    const std::size_t markerIndex =
        path.find(
            marker
        );

    if (markerIndex == std::wstring::npos) {
        return L"";
    }

    const std::size_t packageStart =
        markerIndex +
        marker.size();

    const std::size_t packageEnd =
        path.find(
            L'\\',
            packageStart
        );

    if (
        packageEnd == std::wstring::npos ||
        packageEnd <= packageStart
    ) {
        return L"";
    }

    std::wstring package =
        path.substr(
            packageStart,
            packageEnd - packageStart
        );

    bool versionNormalized = false;

    std::size_t separator =
        package.find(L'_');

    while (separator != std::wstring::npos) {
        const std::size_t nextSeparator =
            package.find(
                L'_',
                separator + 1
            );

        if (nextSeparator == std::wstring::npos) {
            break;
        }

        const std::wstring candidate =
            package.substr(
                separator + 1,
                nextSeparator - separator - 1
            );

        std::vector<unsigned int> parsedVersion;

        if (
            ParseNumericDottedVersion(
                candidate,
                &parsedVersion
            )
        ) {
            package.replace(
                separator + 1,
                candidate.size(),
                L"<version>"
            );

            if (packageVersion) {
                *packageVersion =
                    std::move(parsedVersion);
            }

            versionNormalized = true;
            break;
        }

        separator =
            nextSeparator;
    }

    if (!versionNormalized) {
        return L"";
    }

    path.replace(
        packageStart,
        packageEnd - packageStart,
        package
    );

    return path;
}
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

bool QueryBinaryValue(
    const std::wstring& subkey,
    const wchar_t* valueName,
    std::vector<BYTE>* value
) {
    if (!value) {
        return false;
    }

    value->clear();

    DWORD registryType =
        REG_NONE;

    DWORD requiredBytes =
        0;

    LONG status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            valueName,
            RRF_RT_REG_BINARY,
            &registryType,
            nullptr,
            &requiredBytes
        );

    if (
        status !=
            ERROR_SUCCESS ||
        registryType !=
            REG_BINARY ||
        requiredBytes ==
            0
    ) {
        return false;
    }

    value->resize(
        requiredBytes
    );

    DWORD actualBytes =
        requiredBytes;

    status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            valueName,
            RRF_RT_REG_BINARY,
            &registryType,
            value->data(),
            &actualBytes
        );

    if (
        status !=
            ERROR_SUCCESS ||
        actualBytes ==
            0
    ) {
        value->clear();
        return false;
    }

    value->resize(
        actualBytes
    );

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

std::wstring NormalizeContinuityTooltip(
    std::wstring value
) {
    std::size_t first =
        0;

    while (
        first <
            value.size() &&
        std::iswspace(
            value[first]
        )
    ) {
        first++;
    }

    std::size_t last =
        value.size();

    while (
        last >
            first &&
        std::iswspace(
            value[last - 1]
        )
    ) {
        last--;
    }

    return
        ToLower(
            value.substr(
                first,
                last - first
            )
        );
}

// Keep package identity evidence when Windows prunes its old tray registry entry.
std::mutex g_packageHistoryMutex;
std::vector<std::pair<std::wstring, std::wstring>> g_packageHistory;
constexpr std::size_t kPackageHistoryChars = 131072;

void RememberPackageIdentity(
    const std::wstring& key, const std::wstring& path,
    const std::vector<BYTE>& snapshot
) {
    if ((key.compare(0, 5, L"guid:") != 0 && key.compare(0, 4, L"uid:") != 0) ||
        key.size() > 2048 ||
        path.find_first_of(L"\r\n") != std::wstring::npos || path.size() > 32768 ||
        snapshot.empty() || snapshot.size() > 32768) {
        return;
    }
    std::wstring value = L"TOR_PACKAGE_V1\n" + path + L"\n";
    constexpr wchar_t hex[] = L"0123456789abcdef";
    for (BYTE byte : snapshot) {
        value += hex[byte >> 4];
        value += hex[byte & 15];
    }
    std::lock_guard<std::mutex> lock(g_packageHistoryMutex);
    auto found = std::find_if(g_packageHistory.begin(), g_packageHistory.end(),
        [&](const auto& entry) { return entry.first == key; });
    if (found != g_packageHistory.end() && found->second == value) {
        return;
    }
    if (Wh_SetStringValue((L"PackageIdentityV1." + key).c_str(), value.c_str())) {
        if (found != g_packageHistory.end()) {
            found->second = std::move(value);
        } else {
            if (g_packageHistory.size() == 128) {
                g_packageHistory.erase(g_packageHistory.begin());
            }
            g_packageHistory.emplace_back(key, std::move(value));
        }
    }
}

bool LoadPackageIdentity(
    const std::wstring& key, ContinuityIdentityMetadata* metadata
) {
    const bool guid = key.compare(0, 5, L"guid:") == 0;
    if (!metadata || (!guid && key.compare(0, 4, L"uid:") != 0) || key.size() > 2048) {
        return false;
    }
    std::wstring value;
    {
        std::lock_guard<std::mutex> lock(g_packageHistoryMutex);
        const auto found = std::find_if(g_packageHistory.begin(), g_packageHistory.end(),
            [&](const auto& entry) { return entry.first == key; });
        if (found != g_packageHistory.end()) {
            value = found->second;
        } else {
            std::vector<wchar_t> buffer(kPackageHistoryChars);
            const auto length = Wh_GetStringValue(
                (L"PackageIdentityV1." + key).c_str(), buffer.data(), buffer.size());
            if (length == 0 || length >= buffer.size()) {
                return false;
            }
            value.assign(buffer.data(), length);
        }
    }
    const std::wstring header = L"TOR_PACKAGE_V1\n";
    const auto separator = value.find(L'\n', header.size());
    if (value.compare(0, header.size(), header) != 0 || separator == std::wstring::npos ||
        separator - header.size() > 32768) {
        return false;
    }
    ContinuityIdentityMetadata parsed;
    const auto executablePath = value.substr(header.size(), separator - header.size());
    parsed.normalizedExecutablePath = BuildWindowsAppsGuidContinuityPath(
        executablePath, &parsed.packageVersion);
    const auto count = value.size() - separator - 1;
    if (parsed.normalizedExecutablePath.empty() || count == 0 || count > 65536 || count % 2) {
        return false;
    }
    constexpr wchar_t hex[] = L"0123456789abcdef";
    for (auto index = separator + 1; index < value.size(); index += 2) {
        const auto high = std::find(hex, hex + 16, value[index]);
        const auto low = std::find(hex, hex + 16, value[index + 1]);
        if (high == hex + 16 || low == hex + 16) {
            return false;
        }
        parsed.iconSnapshot.push_back(static_cast<BYTE>(((high - hex) << 4) | (low - hex)));
    }
    parsed.guidBacked = guid;
    if (!guid) {
        const auto marker = key.find(L"|path:");
        if (marker == std::wstring::npos || marker == 4) {
            return false;
        }
        std::uint64_t uid = 0;
        for (std::size_t index = 4; index < marker; ++index) {
            if (key[index] < L'0' || key[index] > L'9' || uid > 429496729u) {
                return false;
            }
            uid = uid * 10 + (key[index] - L'0');
        }
        if (uid > 4294967295ULL) {
            return false;
        }
        if (key != L"uid:" + std::to_wstring(uid) + L"|path:" +
                   BuildVersionNormalizedPath(executablePath)) {
            return false;
        }
        parsed.uid = static_cast<DWORD>(uid);
        parsed.normalizedExecutablePath.erase(
            0, parsed.normalizedExecutablePath.find(L"\\windowsapps\\"));
    }
    *metadata = std::move(parsed);
    return true;
}

bool BuildContinuityIdentityMetadata(
    std::uint64_t identity,
    ContinuityIdentityMetadata* metadata
) {
    if (!metadata) {
        return false;
    }

    *metadata =
        ContinuityIdentityMetadata{};

    const std::wstring subkey =
        MakeTrayEntrySubkey(
            identity
        );

    std::wstring iconGuid;

    const bool hasGuid =
        QueryIconGuid(
            subkey,
            &iconGuid
        );

    if (hasGuid) {
        const auto executablePath = QueryStringValue(subkey, L"ExecutablePath");
        metadata->normalizedExecutablePath =
            BuildWindowsAppsGuidContinuityPath(
                executablePath,
                &metadata->packageVersion
            );

        if (
            metadata->normalizedExecutablePath.empty()
        ) {
            return false;
        }

        if (
            !QueryBinaryValue(
                subkey,
                L"IconSnapshot",
                &metadata->iconSnapshot
            )
        ) {
            return false;
        }

        metadata->guidBacked =
            true;

        RememberPackageIdentity(L"guid:" + iconGuid, executablePath,
                                metadata->iconSnapshot);

        return true;
    }

    if (
        !QueryDwordValue(
            subkey,
            L"UID",
            &metadata->uid
        )
    ) {
        return false;
    }

    metadata->tooltip =
        NormalizeContinuityTooltip(
            QueryStringValue(
                subkey,
                L"InitialTooltip"
            )
        );

    metadata->normalizedExecutablePath =
        BuildWindowsAppsGuidContinuityPath(
            QueryStringValue(subkey, L"ExecutablePath"),
            &metadata->packageVersion
        );
    const std::size_t marker =
        metadata->normalizedExecutablePath.find(L"\\windowsapps\\");
    if (marker != std::wstring::npos) {
        metadata->normalizedExecutablePath.erase(0, marker);
    }
    if (metadata->tooltip.empty() && metadata->normalizedExecutablePath.empty()) {
        return false;
    }

    if (
        !QueryBinaryValue(
            subkey,
            L"IconSnapshot",
            &metadata->iconSnapshot
        )
    ) {
        return false;
    }

    if (!metadata->normalizedExecutablePath.empty()) {
        const auto path = QueryStringValue(subkey, L"ExecutablePath");
        RememberPackageIdentity(
            L"uid:" + std::to_wstring(metadata->uid) + L"|path:" +
                BuildVersionNormalizedPath(path), path, metadata->iconSnapshot
        );
    }

    return true;
}

bool ContinuityIdentityMatches(
    const ContinuityIdentityMetadata& left,
    const ContinuityIdentityMetadata& right
) {
    if (left.guidBacked || right.guidBacked) {
        const auto leftMarker = left.normalizedExecutablePath.find(L"\\windowsapps\\");
        const auto rightMarker = right.normalizedExecutablePath.find(L"\\windowsapps\\");
        return leftMarker != std::wstring::npos && rightMarker != std::wstring::npos &&
            left.normalizedExecutablePath.substr(leftMarker) ==
                right.normalizedExecutablePath.substr(rightMarker) &&
            !left.iconSnapshot.empty() && left.iconSnapshot == right.iconSnapshot;
    }
    if (left.tooltip.empty() || right.tooltip.empty()) {
        return !left.normalizedExecutablePath.empty() &&
            left.normalizedExecutablePath == right.normalizedExecutablePath &&
            left.uid == right.uid && left.iconSnapshot == right.iconSnapshot;
    }

    return
        left.uid ==
            right.uid &&
        left.tooltip ==
            right.tooltip &&
        left.iconSnapshot ==
            right.iconSnapshot;
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

unsigned int CountIdentity(
    const UIOrderSnapshot& snapshot,
    std::uint64_t identity
) {
    if (
        !snapshot.valid ||
        identity ==
            0
    ) {
        return 0;
    }

    return
        static_cast<unsigned int>(
            std::count(
                snapshot.entries.begin(),
                snapshot.entries.end(),
                identity
            )
        );
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

struct ContinuityGroupAnalysis {
    std::vector<std::uint64_t> identities;
    std::vector<std::wstring> keys;
    bool ambiguous = false;
    bool metadataConfirmed = false;

    unsigned int canonicalMembers = 0;

    std::size_t earliestCanonicalIndex = 0;
    std::uint64_t earliestCanonicalIdentity = 0;
    std::wstring earliestCanonicalKey;
};

bool ContinuityGroupContainsKey(
    const ContinuityGroupAnalysis& group,
    const std::wstring& key
) {
    return
        std::find(
            group.keys.begin(),
            group.keys.end(),
            key
        ) !=
        group.keys.end();
}

bool FindGuidContinuityPredecessorFromRegistry(
    const ContinuityIdentityMetadata& targetMetadata,
    const std::wstring& targetKey,
    const std::vector<std::wstring>& canonicalSnapshot,
    std::uint64_t* predecessorIdentity,
    std::wstring* predecessorKey
) {
    if (
        !targetMetadata.guidBacked ||
        targetMetadata.packageVersion.empty() ||
        targetKey.empty() ||
        !predecessorIdentity ||
        !predecessorKey
    ) {
        return false;
    }

    *predecessorIdentity = 0;
    predecessorKey->clear();

    HKEY settingsKey = nullptr;

    const LONG openStatus =
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            kNotifyIconSettingsPath,
            0,
            KEY_READ,
            &settingsKey
        );

    if (openStatus != ERROR_SUCCESS) {
        return false;
    }

    bool found = false;
    bool ambiguous = false;
    unsigned int registryEntries = 0;
    unsigned int metadataMatches = 0;
    unsigned int canonicalMatches = 0;
    unsigned int eligibleMatches = 0;

    std::uint64_t selectedIdentity = 0;
    std::wstring selectedKey;
    std::vector<unsigned int> selectedVersion;

    DWORD enumerationIndex = 0;

    for (;;) {
        wchar_t subkeyName[64]{};
        DWORD subkeyNameLength =
            ARRAYSIZE(subkeyName);

        const LONG enumerationStatus =
            RegEnumKeyExW(
                settingsKey,
                enumerationIndex,
                subkeyName,
                &subkeyNameLength,
                nullptr,
                nullptr,
                nullptr,
                nullptr
            );

        if (
            enumerationStatus ==
            ERROR_NO_MORE_ITEMS
        ) {
            break;
        }

        enumerationIndex++;

        if (
            enumerationStatus !=
            ERROR_SUCCESS
        ) {
            continue;
        }

        if (
            subkeyNameLength >=
            ARRAYSIZE(subkeyName)
        ) {
            continue;
        }

        subkeyName[subkeyNameLength] =
            L'\0';

        wchar_t* parseEnd = nullptr;

        const unsigned long long parsedIdentity =
            std::wcstoull(
                subkeyName,
                &parseEnd,
                10
            );

        if (
            parsedIdentity == 0 ||
            !parseEnd ||
            *parseEnd != L'\0'
        ) {
            continue;
        }

        const std::uint64_t candidateIdentity =
            static_cast<std::uint64_t>(
                parsedIdentity
            );

        registryEntries++;
        ContinuityIdentityMetadata candidateMetadata;

        if (
            !BuildContinuityIdentityMetadata(
                candidateIdentity,
                &candidateMetadata
            ) ||
            !candidateMetadata.guidBacked ||
            candidateMetadata.packageVersion.empty() ||
            !ContinuityIdentityMatches(
                targetMetadata,
                candidateMetadata
            )
        ) {
            continue;
        }

        metadataMatches++;
        const std::wstring candidateKey =
            BuildLogicalKey(
                candidateIdentity
            );

        if (
            candidateKey.empty() ||
            candidateKey == targetKey ||
            std::find(
                canonicalSnapshot.begin(),
                canonicalSnapshot.end(),
                candidateKey
            ) == canonicalSnapshot.end()
        ) {
            continue;
        }

        canonicalMatches++;
        const int relativeToTarget =
            CompareVersionParts(
                candidateMetadata.packageVersion,
                targetMetadata.packageVersion
            );

        if (relativeToTarget > 0) {
            continue;
        }

        eligibleMatches++;
        if (!found) {
            found = true;
            ambiguous = false;

            selectedIdentity =
                candidateIdentity;

            selectedKey =
                candidateKey;

            selectedVersion =
                candidateMetadata.packageVersion;

            continue;
        }

        const int relativeToSelected =
            CompareVersionParts(
                candidateMetadata.packageVersion,
                selectedVersion
            );

        if (relativeToSelected > 0) {
            ambiguous = false;

            selectedIdentity =
                candidateIdentity;

            selectedKey =
                candidateKey;

            selectedVersion =
                candidateMetadata.packageVersion;
        }
        else if (
            relativeToSelected == 0 &&
            candidateKey != selectedKey
        ) {
            ambiguous = true;
        }
    }

    RegCloseKey(
        settingsKey
    );

    if (
        !found ||
        ambiguous
    ) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_GUID_PREDECESSOR_REJECTED "
            L"reason=%s targetKey=\"%s\" "
            L"registryEntries=%u metadataMatches=%u "
            L"canonicalMatches=%u eligibleMatches=%u",
            ambiguous ? L"ambiguous" : L"no-match",
            targetKey.c_str(),
            registryEntries,
            metadataMatches,
            canonicalMatches,
            eligibleMatches
        );
        return false;
    }

    *predecessorIdentity =
        selectedIdentity;

    *predecessorKey =
        selectedKey;

    return true;
}

bool FindWindowsAppsUidCanonicalPredecessor(
    std::uint64_t targetIdentity,
    const std::wstring& targetKey,
    const std::vector<std::wstring>& canonical,
    std::wstring* predecessorKey,
    bool* ambiguousResult = nullptr
) {
    if (ambiguousResult) {
        *ambiguousResult = false;
    }
    if (!predecessorKey || targetKey.empty() ||
        std::find(canonical.begin(), canonical.end(), targetKey) !=
            canonical.end()) {
        return false;
    }

    const std::wstring subkey = MakeTrayEntrySubkey(targetIdentity);
    DWORD uid = 0;

    std::wstring guid;
    const bool guidTarget = QueryIconGuid(subkey, &guid);
    if (!guidTarget && !QueryDwordValue(subkey, L"UID", &uid)) {
        return false;
    }

    std::vector<unsigned int> targetVersion;
    std::wstring family = BuildWindowsAppsGuidContinuityPath(
        QueryStringValue(subkey, L"ExecutablePath"), &targetVersion
    );

    if (family.empty() || targetVersion.empty()) {
        return false;
    }

    family.erase(0, family.find(L"\\windowsapps\\"));

    const std::wstring prefix =
        L"uid:" + std::to_wstring(uid) + L"|path:";

    std::wstring bestKey;
    std::vector<unsigned int> bestVersion;
    bool ambiguous = false;
    std::wstring selectedUidPrefix;

    for (const std::wstring& key : canonical) {
        const auto pathMarker = key.find(L"|path:");
        if (key.compare(0, 4, L"uid:") != 0 || pathMarker == std::wstring::npos ||
            (!guidTarget && key.compare(0, prefix.size(), prefix) != 0)) {
            continue;
        }

        std::vector<unsigned int> version;
        std::wstring candidateFamily =
            BuildWindowsAppsGuidContinuityPath(
                key.substr(pathMarker + 6), &version
            );

        if (!candidateFamily.empty()) {
            candidateFamily.erase(0, candidateFamily.find(L"\\windowsapps\\"));
        }

        if (candidateFamily != family || version.empty() ||
            CompareVersionParts(version, targetVersion) > 0) {
            continue;
        }

        // A GUID has no UID to disambiguate multiple tray icons in one package.
        const std::wstring uidPrefix = key.substr(0, pathMarker);
        if (guidTarget && !selectedUidPrefix.empty() && uidPrefix != selectedUidPrefix) {
            if (ambiguousResult) {
                *ambiguousResult = true;
            }
            return false;
        }
        selectedUidPrefix = uidPrefix;

        const int comparison = bestKey.empty()
            ? 1
            : CompareVersionParts(version, bestVersion);

        if (comparison > 0) {
            bestKey = key;
            bestVersion = std::move(version);
            ambiguous = false;
        } else if (comparison == 0) {
            ambiguous = true;
        }
    }

    if (bestKey.empty() || ambiguous) {
        if (ambiguousResult) {
            *ambiguousResult = ambiguous;
        }
        return false;
    }

    *predecessorKey = bestKey;

    TOR_LOG(
        L"TRAY_ORDER_LOCK_UID_CANONICAL_PREDECESSOR "
        L"windowsIdentity=%llu predecessorKey=\"%s\" targetKey=\"%s\"",
        static_cast<unsigned long long>(targetIdentity),
        predecessorKey->c_str(), targetKey.c_str()
    );

    return true;
}
bool AnalyzePackageRollback(
    const ContinuityIdentityMetadata& target,
    const std::wstring& targetKey,
    const std::vector<LogicalSnapshotEntry>& logical,
    const std::vector<std::wstring>& canonical,
    ContinuityGroupAnalysis* analysis
) {
    const auto targetMarker = target.normalizedExecutablePath.find(L"\\windowsapps\\");
    if (targetMarker == std::wstring::npos || target.packageVersion.empty() ||
        std::find(canonical.begin(), canonical.end(), targetKey) != canonical.end()) {
        return false;
    }
    const auto family = target.normalizedExecutablePath.substr(targetMarker);
    std::size_t familyMembers = 0;
    std::size_t selectedIndex = canonical.size();
    bool matchingRollback = false;
    std::wstring selectedKey;
    std::uint64_t selectedIdentity = 0;
    for (std::size_t index = 0; index < canonical.size(); ++index) {
        const auto& key = canonical[index];
        if (key.compare(0, 5, L"guid:") != 0 && key.compare(0, 4, L"uid:") != 0) {
            continue;
        }
        if (key.compare(0, 4, L"uid:") == 0) {
            const auto pathMarker = key.find(L"|path:");
            const auto path = pathMarker == std::wstring::npos ? L"" :
                BuildWindowsAppsGuidContinuityPath(key.substr(pathMarker + 6), nullptr);
            const auto marker = path.find(L"\\windowsapps\\");
            if (marker == std::wstring::npos || path.substr(marker) != family) {
                continue;
            }
        }
        ContinuityIdentityMetadata candidate;
        bool complete = false;
        bool seen = false;
        std::uint64_t identity = 0;
        for (const auto& entry : logical) {
            if (entry.key == key) {
                const bool unique = !seen && entry.unique;
                seen = true;
                complete = unique && BuildContinuityIdentityMetadata(entry.identity, &candidate);
                identity = entry.identity;
            }
        }
        if (!seen) {
            complete = LoadPackageIdentity(key, &candidate);
        }
        auto candidatePath = candidate.normalizedExecutablePath;
        if (candidatePath.empty() && key.compare(0, 4, L"uid:") == 0) {
            const auto pathMarker = key.find(L"|path:");
            if (pathMarker != std::wstring::npos) {
                candidatePath = BuildWindowsAppsGuidContinuityPath(
                    key.substr(pathMarker + 6), nullptr);
            }
        }
        const auto marker = candidatePath.find(L"\\windowsapps\\");
        if (marker == std::wstring::npos || candidatePath.substr(marker) != family) {
            continue;
        }
        ++familyMembers;
        if (complete && ContinuityIdentityMatches(target, candidate) &&
            CompareVersionParts(candidate.packageVersion, target.packageVersion) > 0) {
            matchingRollback = true;
            selectedKey = key;
            selectedIdentity = identity;
            selectedIndex = index;
        }
    }
    if (!matchingRollback) {
        return false;
    }
    // Version order cannot identify the last preferred position during a rollback.
    // Require one fully verified package identity, rather than choosing a version.
    analysis->ambiguous = familyMembers != 1;
    if (!analysis->ambiguous) {
        analysis->identities = {selectedIdentity};
        analysis->keys = {selectedKey};
        analysis->metadataConfirmed = true;
        analysis->canonicalMembers = 1;
        analysis->earliestCanonicalIndex = selectedIndex;
        analysis->earliestCanonicalIdentity = selectedIdentity;
        analysis->earliestCanonicalKey = selectedKey;
    }
    return true;
}

bool FindCachedPackageGuidAnchor(
    const ContinuityIdentityMetadata& target,
    const std::wstring& targetKey,
    const std::vector<std::wstring>& canonical,
    std::wstring* predecessor,
    bool* ambiguous
) {
    *ambiguous = false;
    if (std::find(canonical.begin(), canonical.end(), targetKey) != canonical.end()) {
        return false;
    }
    std::vector<unsigned int> bestVersion;
    bool bestMatches = false;
    const auto targetMarker = target.normalizedExecutablePath.find(L"\\windowsapps\\");
    if (targetMarker == std::wstring::npos) {
        return false;
    }
    predecessor->clear();
    for (const auto& key : canonical) {
        ContinuityIdentityMetadata candidate;
        if (key.compare(0, 5, L"guid:") != 0 ||
            !LoadPackageIdentity(key, &candidate) ||
            CompareVersionParts(candidate.packageVersion, target.packageVersion) > 0) {
            continue;
        }
        const auto marker = candidate.normalizedExecutablePath.find(L"\\windowsapps\\");
        if (marker == std::wstring::npos ||
            candidate.normalizedExecutablePath.substr(marker) !=
                target.normalizedExecutablePath.substr(targetMarker)) {
            continue;
        }
        const int comparison = predecessor->empty() ? 1 :
            CompareVersionParts(candidate.packageVersion, bestVersion);
        if (comparison > 0) {
            *predecessor = key;
            bestVersion = candidate.packageVersion;
            bestMatches = ContinuityIdentityMatches(target, candidate);
            *ambiguous = false;
        } else if (comparison == 0) {
            *ambiguous = true;
        }
    }
    *ambiguous = *ambiguous || (!predecessor->empty() && !bestMatches);
    return !predecessor->empty() && !*ambiguous;
}

bool FindWindowsAppsGuidAnchorForUid(
    const ContinuityIdentityMetadata& target,
    const std::wstring& targetKey,
    const std::vector<LogicalSnapshotEntry>& logical,
    const std::vector<std::wstring>& canonical,
    ContinuityGroupAnalysis* analysis
) {
    if (target.guidBacked || target.normalizedExecutablePath.empty() ||
        target.packageVersion.empty() ||
        std::find(canonical.begin(), canonical.end(), targetKey) != canonical.end()) {
        return false;
    }

    const std::wstring uidPrefix = L"uid:" + std::to_wstring(target.uid) + L"|path:";
    std::vector<unsigned int> bestVersion;
    std::size_t bestIndex = canonical.size();
    std::uint64_t bestIdentity = 0;
    bool bestGuid = false;
    bool ambiguous = false;
    bool otherUid = false;
    for (std::size_t index = 0; index < canonical.size(); ++index) {
        const auto& key = canonical[index];
        std::vector<unsigned int> version;
        std::uint64_t identity = 0;
        bool guid = key.compare(0, 5, L"guid:") == 0;
        bool unique = true;
        if (guid) {
            for (const auto& entry : logical) {
                if (entry.key != key) {
                    continue;
                }
                ContinuityIdentityMetadata candidate;
                const bool complete =
                    BuildContinuityIdentityMetadata(entry.identity, &candidate);
                const auto marker = candidate.normalizedExecutablePath.find(L"\\windowsapps\\");
                if (marker != std::wstring::npos &&
                    candidate.normalizedExecutablePath.substr(marker) ==
                        target.normalizedExecutablePath) {
                    unique = unique && entry.unique && identity == 0 && complete &&
                        candidate.guidBacked && ContinuityIdentityMatches(target, candidate);
                    version = candidate.packageVersion;
                    identity = entry.identity;
                }
            }
            if (identity == 0) {
                ContinuityIdentityMetadata candidate;
                if (LoadPackageIdentity(key, &candidate) &&
                    ContinuityIdentityMatches(target, candidate)) {
                    version = candidate.packageVersion;
                }
            }
        } else if (key.compare(0, 4, L"uid:") == 0) {
            const auto pathMarker = key.find(L"|path:");
            if (pathMarker == std::wstring::npos) {
                continue;
            }
            auto family = BuildWindowsAppsGuidContinuityPath(
                key.substr(pathMarker + 6), &version);
            const auto marker = family.find(L"\\windowsapps\\");
            if (marker == std::wstring::npos ||
                family.substr(marker) != target.normalizedExecutablePath) {
                continue;
            }
            if (key.compare(0, uidPrefix.size(), uidPrefix) != 0) {
                if (!version.empty() && CompareVersionParts(version, target.packageVersion) <= 0) {
                    otherUid = true;
                }
                continue;
            }
        }
        if (version.empty() || CompareVersionParts(version, target.packageVersion) > 0) {
            continue;
        }
        const int comparison = bestIndex == canonical.size()
            ? 1 : CompareVersionParts(version, bestVersion);
        if (comparison > 0) {
            bestIndex = index;
            bestVersion = version;
            bestIdentity = identity;
            bestGuid = guid;
            ambiguous = !unique;
        } else if (comparison == 0) {
            ambiguous = true;
            if (guid) {
                bestGuid = true;
                bestIndex = index;
            }
        }
    }
    if (!bestGuid) {
        return false;
    }
    ambiguous = ambiguous || otherUid;
    analysis->ambiguous = ambiguous;
    if (!ambiguous) {
        analysis->identities = {bestIdentity};
        analysis->keys = {canonical[bestIndex]};
        analysis->canonicalMembers = 1;
        analysis->earliestCanonicalIndex = bestIndex;
        analysis->earliestCanonicalIdentity = bestIdentity;
        analysis->earliestCanonicalKey = canonical[bestIndex];
        analysis->metadataConfirmed = true;
    }
    TOR_LOG(
        L"TRAY_ORDER_LOCK_GUID_TO_UID_CANDIDATE "
        L"ambiguous=%d predecessorKey=\"%s\" targetKey=\"%s\"",
        ambiguous ? 1 : 0, canonical[bestIndex].c_str(), targetKey.c_str()
    );
    return true;
}

bool AnalyzeContinuityGroup(
    std::uint64_t targetIdentity,
    const std::wstring& targetKey,
    const std::vector<LogicalSnapshotEntry>& logicalSnapshot,
    const std::vector<std::wstring>& canonicalSnapshot,
    ContinuityGroupAnalysis* analysis
) {
    if (
        targetIdentity == 0 ||
        targetKey.empty() ||
        !analysis
    ) {
        return false;
    }

    *analysis =
        ContinuityGroupAnalysis{};

    ContinuityIdentityMetadata targetMetadata;

    if (
        !BuildContinuityIdentityMetadata(
            targetIdentity,
            &targetMetadata
        )
    ) {
        return false;
    }

    if (AnalyzePackageRollback(targetMetadata, targetKey, logicalSnapshot,
                               canonicalSnapshot, analysis)) {
        if (!analysis->ambiguous) {
            analysis->identities.push_back(targetIdentity);
            analysis->keys.push_back(targetKey);
        }
        return true;
    }

    if (!targetMetadata.guidBacked) {
        if (FindWindowsAppsGuidAnchorForUid(
                targetMetadata, targetKey, logicalSnapshot, canonicalSnapshot,
                analysis)) {
            if (!analysis->ambiguous) {
                analysis->identities.push_back(targetIdentity);
                analysis->keys.push_back(targetKey);
            }
            return true;
        }
        std::wstring predecessor;
        bool ambiguous = false;
        FindWindowsAppsUidCanonicalPredecessor(
            targetIdentity, targetKey, canonicalSnapshot, &predecessor,
            &ambiguous
        );
        if (ambiguous) {
            analysis->ambiguous = true;
            return true;
        }
    }

    if (targetMetadata.guidBacked) {
        std::uint64_t predecessorIdentity = 0;
        std::wstring predecessorKey;

        if (
            !FindGuidContinuityPredecessorFromRegistry(
                targetMetadata,
                targetKey,
                canonicalSnapshot,
                &predecessorIdentity,
                &predecessorKey
            )
        ) {
            bool ambiguous = false;
            if (!FindCachedPackageGuidAnchor(
                    targetMetadata, targetKey, canonicalSnapshot,
                    &predecessorKey, &ambiguous) &&
                (ambiguous || !FindWindowsAppsUidCanonicalPredecessor(
                    targetIdentity, targetKey, canonicalSnapshot,
                    &predecessorKey, &ambiguous))) {
                analysis->ambiguous = ambiguous;
                return ambiguous;
            }

            for (const LogicalSnapshotEntry& entry : logicalSnapshot) {
                if (entry.key == predecessorKey) {
                    ContinuityIdentityMetadata candidate;
                    if (!entry.unique || predecessorIdentity != 0 ||
                        !BuildContinuityIdentityMetadata(entry.identity, &candidate) ||
                        !ContinuityIdentityMatches(targetMetadata, candidate)) {
                        analysis->ambiguous = true;
                        return true;
                    }
                    predecessorIdentity = entry.identity;
                }
            }
        }

        if (predecessorIdentity == 0) {
            ContinuityIdentityMetadata cached;
            if (LoadPackageIdentity(predecessorKey, &cached)) {
                if (!ContinuityIdentityMatches(targetMetadata, cached)) {
                    analysis->ambiguous = true;
                    return true;
                }
                analysis->metadataConfirmed = true;
            }
        }

        const bool targetKnown =
            std::find(
                canonicalSnapshot.begin(),
                canonicalSnapshot.end(),
                targetKey
            ) != canonicalSnapshot.end();

        TOR_LOG(
            L"TRAY_ORDER_LOCK_GUID_CONTINUITY_PREDECESSOR "
            L"windowsIdentity=%llu "
            L"targetKnown=%d "
            L"predecessorIdentity=%llu "
            L"predecessorKey=\"%s\" "
            L"targetKey=\"%s\"",
            static_cast<unsigned long long>(
                targetIdentity
            ),
            targetKnown
                ? 1
                : 0,
            static_cast<unsigned long long>(
                predecessorIdentity
            ),
            predecessorKey.c_str(),
            targetKey.c_str()
        );

        // targetKnown can be true after an earlier new-icon
        // place-at-end adoption. The registry predecessor is still
        // authoritative for continuity migration in that case.
        analysis->identities.push_back(
            targetIdentity
        );

        analysis->keys.push_back(
            targetKey
        );

        analysis->identities.push_back(
            predecessorIdentity
        );

        analysis->keys.push_back(
            predecessorKey
        );
        analysis->metadataConfirmed = analysis->metadataConfirmed ||
            predecessorIdentity != 0 || predecessorKey.compare(0, 5, L"guid:") == 0;
    }
    else if (!BuildWindowsAppsGuidContinuityPath(
                 QueryStringValue(MakeTrayEntrySubkey(targetIdentity),
                                  L"ExecutablePath"), nullptr).empty() &&
             std::find(canonicalSnapshot.begin(), canonicalSnapshot.end(),
                       targetKey) == canonicalSnapshot.end()) {
        std::wstring predecessor;
        if (!FindWindowsAppsUidCanonicalPredecessor(
                targetIdentity, targetKey, canonicalSnapshot, &predecessor)) {
            return false;
        }

        unsigned int targetMatches = 0;
        unsigned int predecessorMatches = 0;
        bool predecessorSeen = false;
        std::uint64_t predecessorIdentity = 0;
        for (const LogicalSnapshotEntry& entry : logicalSnapshot) {
            if (entry.key == predecessor) {
                predecessorSeen = true;
            }
            if (!entry.unique) {
                continue;
            }
            if (entry.identity == targetIdentity && entry.key == targetKey) {
                targetMatches++;
            }
            if (entry.key == predecessor) {
                ContinuityIdentityMetadata candidate;
                if (BuildContinuityIdentityMetadata(entry.identity, &candidate) &&
                    ContinuityIdentityMatches(targetMetadata, candidate)) {
                    predecessorMatches++;
                    predecessorIdentity = entry.identity;
                }
            }
        }
        // Keep the existing canonical-only fallback when old registry data was removed.
        bool cachedPredecessor = false;
        if (!predecessorSeen) {
            ContinuityIdentityMetadata cached;
            cachedPredecessor = LoadPackageIdentity(predecessor, &cached);
            if (cachedPredecessor && ContinuityIdentityMatches(targetMetadata, cached)) {
                predecessorMatches = 1;
                analysis->metadataConfirmed = true;
            }
        }
        const bool priorKeyOnly = !predecessorSeen && !cachedPredecessor &&
            !targetMetadata.tooltip.empty();
        if (targetMatches != 1 ||
            (predecessorMatches != 1 && !priorKeyOnly)) {
            analysis->ambiguous = true;
            return true;
        }
        analysis->identities = {targetIdentity, predecessorIdentity};
        analysis->keys = {targetKey, predecessor};
    }
    else {
        unsigned int targetMatches = 0;

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

            ContinuityIdentityMetadata candidateMetadata;

            if (
                !BuildContinuityIdentityMetadata(
                    entry.identity,
                    &candidateMetadata
                ) ||
                candidateMetadata.guidBacked != targetMetadata.guidBacked ||
                !ContinuityIdentityMatches(
                    targetMetadata,
                    candidateMetadata
                )
            ) {
                continue;
            }

            analysis->identities.push_back(
                entry.identity
            );

            analysis->keys.push_back(
                entry.key
            );

            if (
                entry.identity ==
                    targetIdentity &&
                entry.key ==
                    targetKey
            ) {
                targetMatches++;
            }
        }

        if (targetMatches == 1 && analysis->keys.size() == 1) {
            std::wstring predecessorKey;

            if (FindWindowsAppsUidCanonicalPredecessor(
                    targetIdentity, targetKey, canonicalSnapshot,
                    &predecessorKey)) {
                analysis->identities.push_back(0);
                analysis->keys.push_back(predecessorKey);
            }
        }

        if (
            targetMatches != 1 ||
            analysis->keys.size() < 2
        ) {
            TOR_LOG(
                L"TRAY_ORDER_LOCK_CONTINUITY_NO_CANDIDATE "
                L"reason=\"uid-no-unique-peer\" "
                L"windowsIdentity=%llu targetMatches=%u "
                L"matchingEntries=%llu targetKey=\"%s\"",
                static_cast<unsigned long long>(targetIdentity),
                targetMatches,
                static_cast<unsigned long long>(analysis->keys.size()),
                targetKey.c_str()
            );
            *analysis =
                ContinuityGroupAnalysis{};

            return false;
        }
    }

    analysis->earliestCanonicalIndex =
        canonicalSnapshot.size();

    for (
        std::size_t index = 0;
        index < canonicalSnapshot.size();
        index++
    ) {
        const auto groupKey =
            std::find(
                analysis->keys.begin(),
                analysis->keys.end(),
                canonicalSnapshot[index]
            );

        if (
            groupKey ==
            analysis->keys.end()
        ) {
            continue;
        }

        analysis->canonicalMembers++;

        if (
            index >=
            analysis->earliestCanonicalIndex
        ) {
            continue;
        }

        analysis->earliestCanonicalIndex =
            index;

        const std::size_t groupIndex =
            static_cast<std::size_t>(
                std::distance(
                    analysis->keys.begin(),
                    groupKey
                )
            );

        analysis->earliestCanonicalKey =
            analysis->keys[groupIndex];

        analysis->earliestCanonicalIdentity =
            analysis->identities[groupIndex];
    }

    return
        analysis->canonicalMembers != 0;
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

std::uint64_t DiagnosticHashCodeUnit(
    std::uint64_t hash,
    std::uint16_t codeUnit
) {
    constexpr std::uint64_t kPrime =
        1099511628211ULL;

    hash ^=
        static_cast<std::uint8_t>(
            codeUnit &
            0x00FFu
        );

    hash *=
        kPrime;

    hash ^=
        static_cast<std::uint8_t>(
            (
                codeUnit >>
                8
            ) &
            0x00FFu
        );

    hash *=
        kPrime;

    return hash;
}

std::uint64_t DiagnosticCanonicalFingerprint(
    const std::vector<std::wstring>& order
) {
    std::uint64_t hash =
        14695981039346656037ULL;

    for (
        const std::wstring& key :
        order
    ) {
        for (
            wchar_t character :
            key
        ) {
            hash =
                DiagnosticHashCodeUnit(
                    hash,
                    static_cast<std::uint16_t>(
                        character
                    )
                );
        }

        hash =
            DiagnosticHashCodeUnit(
                hash,
                static_cast<std::uint16_t>(
                    L'\n'
                )
            );
    }

    return hash;
}

bool PersistCanonicalOrderLocked() {
    const std::wstring serialized =
        SerializeCanonicalOrderLocked();

    const std::uint64_t fingerprint =
        DiagnosticCanonicalFingerprint(
            g_canonicalOrder
        );

    const BOOL succeeded =
        Wh_SetStringValue(
            kCanonicalOrderValueName,
            serialized.c_str()
        );

    TOR_LOG(
        L"TRAY_ORDER_LOCK_CANONICAL_WRITE "
        L"succeeded=%d "
        L"entries=%llu "
        L"fingerprint=%016llX "
        L"chars=%llu",
        succeeded
            ? 1
            : 0,
        static_cast<unsigned long long>(
            g_canonicalOrder.size()
        ),
        static_cast<unsigned long long>(
            fingerprint
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

unsigned int MergeLoadedLiveKeysLocked(
    const std::vector<LogicalSnapshotEntry>& logicalSnapshot,
    const std::vector<std::wstring>& canonicalBeforeMerge,
    unsigned int* continuityDeferred
) {
    unsigned int added =
        0;

    unsigned int deferred =
        0;

    for (
        const LogicalSnapshotEntry& entry :
        logicalSnapshot
    ) {
        if (
            !entry.unique ||
            entry.key.empty() ||
            ContainsCanonicalKeyLocked(
                entry.key
            )
        ) {
            continue;
        }

        ContinuityGroupAnalysis group;

        const bool hasGroup =
            AnalyzeContinuityGroup(
                entry.identity,
                entry.key,
                logicalSnapshot,
                canonicalBeforeMerge,
                &group
            );
        std::wstring possiblePredecessor;
        bool ambiguous = false;
        const bool hasPossiblePredecessor = !hasGroup &&
            FindWindowsAppsUidCanonicalPredecessor(
                entry.identity, entry.key, canonicalBeforeMerge,
                &possiblePredecessor, &ambiguous
            );
        ContinuityIdentityMetadata metadata;
        const bool packageMetadataPending = !hasGroup &&
            !BuildWindowsAppsGuidContinuityPath(
                QueryStringValue(MakeTrayEntrySubkey(entry.identity),
                                 L"ExecutablePath"), nullptr).empty() &&
            !BuildContinuityIdentityMetadata(entry.identity, &metadata);

        if ((hasGroup && (group.ambiguous || group.canonicalMembers != 0)) ||
            hasPossiblePredecessor || ambiguous || packageMetadataPending) {
            deferred++;

            TOR_LOG(
                L"TRAY_ORDER_LOCK_CANONICAL_CONTINUITY_GROUP_DEFERRED "
                L"windowsIdentity=%llu "
                L"groupMembers=%llu "
                L"canonicalMembers=%u "
                L"anchorIndex=%llu "
                L"targetKey=\"%s\" "
                L"anchorKey=\"%s\"",
                static_cast<unsigned long long>(
                    entry.identity
                ),
                static_cast<unsigned long long>(
                    group.keys.size()
                ),
                group.canonicalMembers,
                static_cast<unsigned long long>(
                    group.earliestCanonicalIndex
                ),
                entry.key.c_str(),
                group.earliestCanonicalKey.empty()
                    ? L"<none>"
                    : group.earliestCanonicalKey.c_str()
            );

            continue;
        }

        g_canonicalOrder.push_back(
            entry.key
        );

        added++;
    }

    if (continuityDeferred) {
        *continuityDeferred =
            deferred;
    }

    return added;
}
void InitializeCanonicalState() {
    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    if (
        !snapshot.valid
    ) {
        TOR_LOG(
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

    const int savedBaselineSize = Wh_GetIntValue(
        kLiveBaselineSizeValueName, 0
    );

    const bool trustedBaseline =
        loaded &&
        savedBaselineSize >= 2 &&
        savedBaselineSize <= 64 &&
        Wh_GetIntValue(
            kLiveBaselineTrustedValueName, 0
        ) == 1;

    g_liveBaselineTrusted.store(
        trustedBaseline,
        std::memory_order_release
    );

    g_liveBaselineActiveInSession.store(
        trustedBaseline,
        std::memory_order_release
    );

    g_liveBaselineSize.store(
        trustedBaseline
            ? static_cast<unsigned int>(savedBaselineSize)
            : 0,
        std::memory_order_release
    );

    TOR_LOG(
        L"TRAY_ORDER_LOCK_LIVE_BASELINE_STATE "
        L"trusted=%d storedLiveSize=%d canonicalEntries=%llu",
        trustedBaseline ? 1 : 0,
        savedBaselineSize,
        static_cast<unsigned long long>(
            g_canonicalOrder.size()
        )
    );

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

        TOR_LOG(
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

    const std::vector<std::wstring> canonicalBeforeMerge =
        g_canonicalOrder;

    unsigned int continuityDeferred =
        0;

    const unsigned int merged =
        MergeLoadedLiveKeysLocked(
            logicalSnapshot,
            canonicalBeforeMerge,
            &continuityDeferred
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

    TOR_LOG(
        L"TRAY_ORDER_LOCK_CANONICAL_LOAD "
        L"loaded=1 "
        L"uiOrderEntries=%llu "
        L"canonicalEntries=%llu "
        L"newLiveKeys=%u "
        L"continuityDeferred=%u "
        L"persisted=%d",
        static_cast<unsigned long long>(
            snapshot.entries.size()
        ),
        static_cast<unsigned long long>(
            g_canonicalOrder.size()
        ),
        merged,
        continuityDeferred,
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

void RecordLearningSkip(
    const wchar_t* reason,
    std::uint64_t identity,
    const wchar_t* identitySource
) {
    const unsigned long long skipped =
        g_skippedLearningCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    TOR_LOG(
        L"TRAY_ORDER_LOCK_MANUAL_LEARN_SKIPPED "
        L"skip=%llu "
        L"reason=\"%s\" "
        L"identity=%llu "
        L"identitySource=%s",
        skipped,
        reason,
        static_cast<unsigned long long>(
            identity
        ),
        identitySource
            ? identitySource
            : L"unknown"
    );
}

// Called only after a user-initiated drag and a complete live mapping.
// Reassign existing live-key slots; leave dormant canonical entries
// in place. No Windows UIOrderList writes are performed.

LiveOverflowSnapshot CaptureLiveOverflowSnapshot(
    void* targetAbi
);

bool HasSimultaneousContinuityAlias(
    const ContinuityGroupAnalysis& group,
    const LiveOverflowSnapshot& live,
    std::uint64_t targetIdentity
) {
    for (const LiveOverflowEntry& entry : live.entries) {
        if (entry.mapped && entry.windowsIdentity != targetIdentity &&
            (std::find(group.identities.begin(), group.identities.end(),
                       entry.windowsIdentity) != group.identities.end() ||
             std::find(group.keys.begin(), group.keys.end(), entry.logicalKey) !=
                 group.keys.end())) {
            return true;
        }
    }
    return false;
}

bool HasDuplicateLiveIdentity(
    const LiveOverflowSnapshot& live,
    std::uint64_t targetIdentity
) {
    unsigned int matches = 0;
    for (const LiveOverflowEntry& entry : live.entries) {
        if (entry.mapped && entry.windowsIdentity == targetIdentity &&
            ++matches > 1) {
            return true;
        }
    }
    return false;
}

bool TryRebaseCanonicalLiveOrderLocked(
    const LiveOverflowSnapshot& live,
    const std::wstring& movedKey,
    int location,
    unsigned int requestedIndex,
    unsigned int* changedSlots
) {
    if (changedSlots) {
        *changedSlots = 0;
    }

    constexpr unsigned int kMaxLiveBaselineSize = 64;

    if (
        location != kOverflowLocation ||
        !live.valid ||
        live.size < 2 ||
        live.size > kMaxLiveBaselineSize ||
        live.entries.size() != live.size ||
        live.mappedEntries != live.size
    ) {
        return false;
    }

    std::vector<std::size_t> slots;

    std::vector<ContinuityIdentityMetadata> metadata(
        live.size
    );

    std::vector<bool> metadataValid(
        live.size, false
    );

    unsigned int targetCount = 0;
    unsigned int movedIndex = 0;

    for (
        unsigned int index = 0;
        index < live.size;
        ++index
    ) {
        const LiveOverflowEntry& entry =
            live.entries[index];

        if (
            !entry.mapped ||
            !entry.uniqueLogical ||
            entry.logicalKey.empty() ||
            std::count(
                g_canonicalOrder.begin(),
                g_canonicalOrder.end(),
                entry.logicalKey
            ) != 1
        ) {
            return false;
        }

        const auto canonicalIt = std::find(
            g_canonicalOrder.begin(),
            g_canonicalOrder.end(),
            entry.logicalKey
        );

        slots.push_back(
            static_cast<std::size_t>(
                std::distance(
                    g_canonicalOrder.begin(),
                    canonicalIt
                )
            )
        );

        if (entry.logicalKey == movedKey) {
            targetCount++;
            movedIndex = index;
        }

        metadataValid[index] =
            BuildContinuityIdentityMetadata(
                entry.windowsIdentity,
                &metadata[index]
            );
    }

    if (
        targetCount != 1 ||
        movedIndex != requestedIndex
    ) {
        return false;
    }

    // Do not establish a baseline from two simultaneously live
    // no-GUID registrations with matching continuity metadata.

    for (
        unsigned int i = 0;
        i < live.size;
        ++i
    ) {
        if (!metadataValid[i]) {
            continue;
        }

        for (
            unsigned int j = i + 1;
            j < live.size;
            ++j
        ) {
            if (
                metadataValid[j] &&
                ContinuityIdentityMatches(
                    metadata[i],
                    metadata[j]
                )
            ) {
                return false;
            }
        }
    }

    std::sort(
        slots.begin(),
        slots.end()
    );

    if (
        std::adjacent_find(
            slots.begin(),
            slots.end()
        ) != slots.end()
    ) {
        return false;
    }

    unsigned int changed = 0;

    for (
        unsigned int i = 0;
        i < live.size;
        ++i
    ) {
        if (
            g_canonicalOrder[slots[i]] !=
            live.entries[i].logicalKey
        ) {
            g_canonicalOrder[slots[i]] =
                live.entries[i].logicalKey;

            changed++;
        }
    }

    if (changedSlots) {
        *changedSlots = changed;
    }

    return true;
}
void LearnManualMove(
    const UIOrderSnapshot& after,
    std::uint64_t movedIdentity,
    const wchar_t* identitySource,
    int location,
    unsigned int requestedIndex
) {
    if (
        movedIdentity ==
        0
    ) {
        RecordLearningSkip(
            L"moved-identity-not-resolved",
            0,
            identitySource
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
        RecordLearningSkip(
            L"logical-identity-not-unique",
            movedIdentity,
            identitySource
        );

        return;
    }

    std::vector<std::wstring> canonicalForContinuity;

    {
        std::lock_guard<std::mutex> continuityLock(
            g_canonicalMutex
        );

        canonicalForContinuity =
            g_canonicalOrder;
    }

    ContinuityGroupAnalysis manualContinuityGroup;

    const LiveOverflowSnapshot liveAfterManual =
        CaptureLiveOverflowSnapshot(nullptr);

    if (liveAfterManual.valid &&
        HasDuplicateLiveIdentity(liveAfterManual, movedIdentity)) {
        RecordLearningSkip(L"duplicate-live-identity", movedIdentity,
                           identitySource);
        return;
    }

    const bool hasManualContinuityGroup =
        AnalyzeContinuityGroup(
            movedIdentity,
            movedEntry->key,
            logicalAfter,
            canonicalForContinuity,
            &manualContinuityGroup
        ) && !manualContinuityGroup.ambiguous && liveAfterManual.valid &&
        liveAfterManual.mappedEntries == liveAfterManual.size &&
        !HasSimultaneousContinuityAlias(
            manualContinuityGroup, liveAfterManual, movedIdentity
        );

    auto IsManualContinuityAlias =
        [&](const LogicalSnapshotEntry& candidate) {
            if (
                !hasManualContinuityGroup ||
                candidate.identity ==
                    movedIdentity
            ) {
                return false;
            }

            return
                std::find(
                    manualContinuityGroup.identities.begin(),
                    manualContinuityGroup.identities.end(),
                    candidate.identity
                ) !=
                manualContinuityGroup.identities.end();
        };

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
        RecordLearningSkip(
            L"moved-identity-not-in-logical-snapshot",
            movedIdentity,
            identitySource
        );

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
            !candidate.key.empty() &&
            !IsManualContinuityAlias(
                candidate
            )
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
            !candidate.key.empty() &&
            !IsManualContinuityAlias(
                candidate
            )
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
        RecordLearningSkip(
            L"no-reliable-logical-neighbor",
            movedIdentity,
            identitySource
        );

        return;
    }

    std::lock_guard<std::mutex> lock(
        g_canonicalMutex
    );

    const std::vector<std::wstring> canonicalBeforeOrder =
        g_canonicalOrder;

    const std::uint64_t canonicalBeforeFingerprint =
        DiagnosticCanonicalFingerprint(
            g_canonicalOrder
        );

    std::size_t targetCanonicalIndexBefore =
        g_canonicalOrder.size();

    const auto targetBeforeIterator =
        std::find(
            g_canonicalOrder.begin(),
            g_canonicalOrder.end(),
            movedEntry->key
        );

    if (
        targetBeforeIterator !=
        g_canonicalOrder.end()
    ) {
        targetCanonicalIndexBefore =
            static_cast<std::size_t>(
                std::distance(
                    g_canonicalOrder.begin(),
                    targetBeforeIterator
                )
            );
    }

    unsigned int continuityAliasesRemoved =
        0;

    if (hasManualContinuityGroup) {
        for (
            const std::wstring& aliasKey :
            manualContinuityGroup.keys
        ) {
            if (
                aliasKey ==
                movedEntry->key
            ) {
                continue;
            }

            const std::size_t beforeSize =
                g_canonicalOrder.size();

            g_canonicalOrder.erase(
                std::remove(
                    g_canonicalOrder.begin(),
                    g_canonicalOrder.end(),
                    aliasKey
                ),
                g_canonicalOrder.end()
            );

            continuityAliasesRemoved +=
                static_cast<unsigned int>(
                    beforeSize -
                    g_canonicalOrder.size()
                );
        }
    }

    unsigned int mergedKeys =
        0;

    for (
        const LogicalSnapshotEntry& entry :
        logicalAfter
    ) {
        if (
            !entry.unique ||
            entry.key.empty()
        ) {
            continue;
        }

        if (
            hasManualContinuityGroup &&
            entry.key !=
                movedEntry->key &&
            ContinuityGroupContainsKey(
                manualContinuityGroup,
                entry.key
            )
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

        mergedKeys++;
    }

    std::size_t precedingCanonicalIndex =
        g_canonicalOrder.size();

    std::size_t followingCanonicalIndex =
        g_canonicalOrder.size();

    if (!precedingKey.empty()) {
        const auto precedingCanonicalIterator =
            std::find(
                g_canonicalOrder.begin(),
                g_canonicalOrder.end(),
                precedingKey
            );

        if (
            precedingCanonicalIterator !=
            g_canonicalOrder.end()
        ) {
            precedingCanonicalIndex =
                static_cast<std::size_t>(
                    std::distance(
                        g_canonicalOrder.begin(),
                        precedingCanonicalIterator
                    )
                );
        }
    }

    if (!followingKey.empty()) {
        const auto followingCanonicalIterator =
            std::find(
                g_canonicalOrder.begin(),
                g_canonicalOrder.end(),
                followingKey
            );

        if (
            followingCanonicalIterator !=
            g_canonicalOrder.end()
        ) {
            followingCanonicalIndex =
                static_cast<std::size_t>(
                    std::distance(
                        g_canonicalOrder.begin(),
                        followingCanonicalIterator
                    )
                );
        }
    }

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
        g_canonicalOrder =
            canonicalBeforeOrder;

        RecordLearningSkip(
            L"canonical-neighbor-not-found",
            movedIdentity,
            identitySource
        );

        return;
    }

    unsigned int rebasedSlots = 0;

    const bool liveRebased =
        TryRebaseCanonicalLiveOrderLocked(
            liveAfterManual,
            movedEntry->key,
            location,
            requestedIndex,
            &rebasedSlots
        );

    TOR_LOG(
        L"TRAY_ORDER_LOCK_MANUAL_CONTINUITY_CONTEXT "
        L"continuityGroup=%d "
        L"groupMembers=%llu "
        L"aliasesRemoved=%u "
        L"mergedKeys=%u",
        hasManualContinuityGroup
            ? 1
            : 0,
        static_cast<unsigned long long>(
            hasManualContinuityGroup
                ? manualContinuityGroup.keys.size()
                : 0
        ),
        continuityAliasesRemoved,
        mergedKeys
    );

    // A changed canonical order must not retain its old trust marker.

    const bool baselineWasActive =
        g_liveBaselineActiveInSession.load(
            std::memory_order_acquire
        );

    const bool baselineInvalidated =
        Wh_SetIntValue(
            kLiveBaselineTrustedValueName, 0
        ) != FALSE;

    g_liveBaselineTrusted.store(
        false,
        std::memory_order_release
    );

    g_liveBaselineActiveInSession.store(
        false,
        std::memory_order_release
    );

    g_liveBaselineSize.store(
        0,
        std::memory_order_release
    );

    if (!baselineInvalidated) {
        g_canonicalOrder = canonicalBeforeOrder;

        RecordLearningSkip(
            L"live-baseline-invalidation-failed",
            movedIdentity,
            identitySource
        );

        return;
    }

    const bool persisted =
        PersistCanonicalOrderLocked();

    if (!persisted) {
        g_canonicalOrder =
            canonicalBeforeOrder;

        RecordLearningSkip(
            L"canonical-persist-failed",
            movedIdentity,
            identitySource
        );

        return;
    }

    bool baselinePersisted = false;

    if (liveRebased) {
        const bool sizePersisted =
            Wh_SetIntValue(
                kLiveBaselineSizeValueName,
                static_cast<int>(
                    liveAfterManual.size
                )
            ) != FALSE;

        baselinePersisted =
            sizePersisted &&
            Wh_SetIntValue(
                kLiveBaselineTrustedValueName, 1
            ) != FALSE;

        if (baselinePersisted) {
            g_liveBaselineSize.store(
                liveAfterManual.size,
                std::memory_order_release
            );

            g_liveBaselineTrusted.store(
                true,
                std::memory_order_release
            );

            g_liveBaselineActiveInSession.store(
                baselineWasActive,
                std::memory_order_release
            );
        }
    }

    TOR_LOG(
        L"TRAY_ORDER_LOCK_MANUAL_LIVE_REBASE "
        L"applied=%d trusted=%d changedSlots=%u "
        L"liveValid=%d liveSize=%u liveMapped=%u "
        L"requestedIndex=%u",
        liveRebased ? 1 : 0,
        baselinePersisted ? 1 : 0,
        rebasedSlots,
        liveAfterManual.valid ? 1 : 0,
        liveAfterManual.size,
        liveAfterManual.mappedEntries,
        requestedIndex
    );

    const std::uint64_t canonicalAfterFingerprint =
        DiagnosticCanonicalFingerprint(
            g_canonicalOrder
        );

    std::size_t targetCanonicalIndexAfter =
        g_canonicalOrder.size();

    const auto targetAfterIterator =
        std::find(
            g_canonicalOrder.begin(),
            g_canonicalOrder.end(),
            movedEntry->key
        );

    if (
        targetAfterIterator !=
        g_canonicalOrder.end()
    ) {
        targetCanonicalIndexAfter =
            static_cast<std::size_t>(
                std::distance(
                    g_canonicalOrder.begin(),
                    targetAfterIterator
                )
            );
    }

    const unsigned long long learned =
        g_learnedMoveCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    TOR_LOG(
        L"TRAY_ORDER_LOCK_MANUAL_CANONICAL_CONTEXT "
        L"targetKey=\"%s\" "
        L"targetBeforeIndex=%llu "
        L"targetAfterIndex=%llu "
        L"precedingCanonicalIndex=%llu "
        L"followingCanonicalIndex=%llu "
        L"canonicalEntries=%llu "
        L"canonicalBefore=%016llX "
        L"canonicalAfter=%016llX",
        movedEntry->key.c_str(),
        static_cast<unsigned long long>(
            targetCanonicalIndexBefore
        ),
        static_cast<unsigned long long>(
            targetCanonicalIndexAfter
        ),
        static_cast<unsigned long long>(
            precedingCanonicalIndex
        ),
        static_cast<unsigned long long>(
            followingCanonicalIndex
        ),
        static_cast<unsigned long long>(
            g_canonicalOrder.size()
        ),
        static_cast<unsigned long long>(
            canonicalBeforeFingerprint
        ),
        static_cast<unsigned long long>(
            canonicalAfterFingerprint
        )
    );

    TOR_LOG(
        L"TRAY_ORDER_LOCK_MANUAL_MOVE_LEARNED "
        L"learned=%llu "
        L"identity=%llu "
        L"identitySource=%s "
        L"targetKey=\"%s\" "
        L"precedingKey=\"%s\" "
        L"followingKey=\"%s\" "
        L"canonicalBefore=%016llX "
        L"canonicalAfter=%016llX "
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
        identitySource,
        movedEntry->key.c_str(),
        precedingKey.empty()
            ? L"<none>"
            : precedingKey.c_str(),
        followingKey.empty()
            ? L"<none>"
            : followingKey.c_str(),
        static_cast<unsigned long long>(
            canonicalBeforeFingerprint
        ),
        static_cast<unsigned long long>(
            canonicalAfterFingerprint
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

void StoreLiveMapping(
    const LiveIdentityMapping& mapping
) {
    std::lock_guard<std::mutex> lock(
        g_liveMappingMutex
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
        g_liveMappingMutex
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

bool LookupLiveMappingByImplementation(
    void* implementation,
    LiveIdentityMapping* mapping
) {
    if (
        !implementation ||
        !mapping
    ) {
        return false;
    }

    std::lock_guard<std::mutex> lock(
        g_liveMappingMutex
    );

    for (
        const LiveIdentityMapping& candidate :
        g_liveMappings
    ) {
        if (
            candidate.implementation ==
            implementation
        ) {
            *mapping =
                candidate;

            return true;
        }
    }

    return false;
}

std::vector<std::wstring>
GetCanonicalOrderSnapshot() {
    std::lock_guard<std::mutex> lock(
        g_canonicalMutex
    );

    return g_canonicalOrder;
}

void CacheTaskbarModel6(
    void* taskbarModel6
) {
    if (!taskbarModel6) {
        return;
    }

    void* current =
        g_taskbarModel6.load(
            std::memory_order_acquire
        );

    if (current == taskbarModel6) {
        return;
    }

    reinterpret_cast<IUnknown*>(
        taskbarModel6
    )->AddRef();

    void* previous =
        g_taskbarModel6.exchange(
            taskbarModel6,
            std::memory_order_acq_rel
        );

    if (previous) {
        reinterpret_cast<IUnknown*>(
            previous
        )->Release();
    }

    TOR_LOG(
        L"TRAY_ORDER_LOCK_OVERFLOW_MODEL_CAPTURED "
        L"processId=%lu "
        L"taskbarModel6=%p",
        GetCurrentProcessId(),
        taskbarModel6
    );
}

void ReleaseCachedTaskbarModel6() {
    void* taskbarModel6 =
        g_taskbarModel6.exchange(
            nullptr,
            std::memory_order_acq_rel
        );

    if (taskbarModel6) {
        reinterpret_cast<IUnknown*>(
            taskbarModel6
        )->Release();
    }
}

bool IsSameComObject(
    void* left,
    void* right
) {
    if (
        !left ||
        !right
    ) {
        return false;
    }

    IUnknown* leftUnknown =
        nullptr;

    IUnknown* rightUnknown =
        nullptr;

    static const GUID kIUnknownGuid =
    {
        0x00000000,
        0x0000,
        0x0000,
        {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
    };
    
    const HRESULT leftResult =
        reinterpret_cast<IUnknown*>(
            left
        )->QueryInterface(
            kIUnknownGuid,
            reinterpret_cast<void**>(
                &leftUnknown
            )
        );
    
    const HRESULT rightResult =
        reinterpret_cast<IUnknown*>(
            right
        )->QueryInterface(
            kIUnknownGuid,
            reinterpret_cast<void**>(
                &rightUnknown
            )
        );

    const bool same =
        SUCCEEDED(leftResult) &&
        SUCCEEDED(rightResult) &&
        leftUnknown &&
        rightUnknown &&
        leftUnknown == rightUnknown;

    if (leftUnknown) {
        leftUnknown->Release();
    }

    if (rightUnknown) {
        rightUnknown->Release();
    }

    return same;
}

LiveOverflowSnapshot CaptureLiveOverflowSnapshot(
    void* targetAbi
) {
    LiveOverflowSnapshot snapshot;

    void* taskbarModel6 =
        g_taskbarModel6.load(
            std::memory_order_acquire
        );

    if (
        !taskbarModel6 ||
        !TaskbarModel_GetOverflowIcons_Original ||
        !g_notificationAreaIconVectorId
    ) {
        return snapshot;
    }

    void* collectionAbi =
        nullptr;

    snapshot.getterResult =
        static_cast<HRESULT>(
            TaskbarModel_GetOverflowIcons_Original(
                taskbarModel6,
                &collectionAbi
            )
        );

    if (
        FAILED(snapshot.getterResult) ||
        !collectionAbi
    ) {
        return snapshot;
    }

    void* vectorAbi =
        nullptr;

    snapshot.vectorQueryResult =
        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->QueryInterface(
            *g_notificationAreaIconVectorId,
            &vectorAbi
        );

    if (
        FAILED(snapshot.vectorQueryResult) ||
        !vectorAbi
    ) {
        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->Release();

        return snapshot;
    }

    void** vtable =
        *reinterpret_cast<void***>(
            vectorAbi
        );

    if (!vtable) {
        reinterpret_cast<IUnknown*>(
            vectorAbi
        )->Release();

        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->Release();

        return snapshot;
    }

    Vector_GetAt_t getAt =
        reinterpret_cast<Vector_GetAt_t>(
            vtable[6]
        );

    Vector_GetSize_t getSize =
        reinterpret_cast<Vector_GetSize_t>(
            vtable[7]
        );

    if (
        !getAt ||
        !getSize
    ) {
        reinterpret_cast<IUnknown*>(
            vectorAbi
        )->Release();

        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->Release();

        return snapshot;
    }

    snapshot.sizeResult =
        getSize(
            vectorAbi,
            &snapshot.size
        );

    if (FAILED(snapshot.sizeResult)) {
        reinterpret_cast<IUnknown*>(
            vectorAbi
        )->Release();

        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->Release();

        return snapshot;
    }

    snapshot.entries.reserve(
        snapshot.size
    );

    for (
        unsigned int index = 0;
        index < snapshot.size;
        index++
    ) {
        LiveOverflowEntry entry;

        void* itemAbi =
            nullptr;

        const HRESULT getAtResult =
            getAt(
                vectorAbi,
                index,
                &itemAbi
            );

        if (
            SUCCEEDED(getAtResult) &&
            itemAbi
        ) {
            if (
                targetAbi &&
                !snapshot.targetFound &&
                IsSameComObject(
                    itemAbi,
                    targetAbi
                )
            ) {
                snapshot.targetFound =
                    true;

                snapshot.targetIndex =
                    index;
            }

            LiveIdentityMapping mapping;

            if (
                LookupLiveMapping(
                    itemAbi,
                    &mapping
                )
            ) {
                entry.mapped =
                    true;

                entry.windowsIdentity =
                    mapping.windowsIdentity;

                entry.logicalKey =
                    BuildLogicalKey(
                        mapping.windowsIdentity
                    );

                snapshot.mappedEntries++;
            }

            reinterpret_cast<IUnknown*>(
                itemAbi
            )->Release();
        }

        snapshot.entries.push_back(
            std::move(entry)
        );
    }

    for (
        std::size_t index = 0;
        index < snapshot.entries.size();
        index++
    ) {
        if (
            snapshot.entries[index]
                .logicalKey.empty()
        ) {
            continue;
        }

        unsigned int occurrences =
            0;

        for (
            const LiveOverflowEntry& candidate :
            snapshot.entries
        ) {
            if (
                candidate.logicalKey ==
                snapshot.entries[index]
                    .logicalKey
            ) {
                occurrences++;
            }
        }

        snapshot.entries[index]
            .uniqueLogical =
                occurrences == 1;
    }

    reinterpret_cast<IUnknown*>(
        vectorAbi
    )->Release();

    reinterpret_cast<IUnknown*>(
        collectionAbi
    )->Release();

    snapshot.valid =
        true;

    return snapshot;
}

bool FindUniqueOverflowIndexForKey(
    const LiveOverflowSnapshot& snapshot,
    const std::wstring& key,
    unsigned int* index
) {
    if (
        !snapshot.valid ||
        key.empty() ||
        !index
    ) {
        return false;
    }

    for (
        unsigned int current = 0;
        current < snapshot.entries.size();
        current++
    ) {
        const LiveOverflowEntry& entry =
            snapshot.entries[current];

        if (
            entry.uniqueLogical &&
            entry.logicalKey == key
        ) {
            *index =
                current;

            return true;
        }
    }

    return false;
}

unsigned int CountOverflowLogicalKey(
    const LiveOverflowSnapshot& snapshot,
    const std::wstring& key
) {
    if (
        !snapshot.valid ||
        key.empty()
    ) {
        return 0;
    }

    unsigned int count =
        0;

    for (
        const LiveOverflowEntry& entry :
        snapshot.entries
    ) {
        if (entry.logicalKey == key) {
            count++;
        }
    }

    return count;
}

enum class ContinuityReconcileResult {
    NoCandidate = 0,
    Reconciled = 1,
    Deferred = 2,
};

bool HasSufficientTrustedLiveBaseline(unsigned int liveSize);

bool IsSafeContinuityLiveState(
    const LiveIdentityMapping& targetMapping,
    const ContinuityGroupAnalysis& group
) {
    const LiveOverflowSnapshot live =
        CaptureLiveOverflowSnapshot(
            targetMapping.abi
        );

    if (
        !live.valid ||
        !live.targetFound ||
        live.mappedEntries !=
            live.size
    ) {
        return false;
    }

    if (HasSimultaneousContinuityAlias(
            group, live, targetMapping.windowsIdentity)) {
        return false;
    }

    ContinuityIdentityMetadata targetMetadata;

    if (
        !BuildContinuityIdentityMetadata(
            targetMapping.windowsIdentity,
            &targetMetadata
        )
    ) {
        return false;
    }

    if (!BuildWindowsAppsGuidContinuityPath(
            QueryStringValue(MakeTrayEntrySubkey(targetMapping.windowsIdentity),
                             L"ExecutablePath"), nullptr).empty() &&
        (!g_liveBaselineActiveInSession.load(std::memory_order_acquire) ||
         (!group.metadataConfirmed && !HasSufficientTrustedLiveBaseline(live.size)))) {
        return false;
    }

    unsigned int targetLiveCount =
        0;

    for (
        const LiveOverflowEntry& entry :
        live.entries
    ) {
        if (!entry.mapped || !entry.uniqueLogical || entry.logicalKey.empty()) {
            return false;
        }

        if (
            entry.windowsIdentity ==
            targetMapping.windowsIdentity
        ) {
            targetLiveCount++;

            continue;
        }

        ContinuityIdentityMetadata candidateMetadata;

        if (
            BuildContinuityIdentityMetadata(
                entry.windowsIdentity,
                &candidateMetadata
            ) &&
            ContinuityIdentityMatches(
                targetMetadata,
                candidateMetadata
            )
        ) {
            return false;
        }
    }

    return
        targetLiveCount ==
        1;
}

ContinuityReconcileResult
TryReconcileCanonicalContinuityGroup(
    const LiveIdentityMapping& targetMapping,
    const std::wstring& targetKey
) {
    const std::vector<std::wstring> canonicalSnapshot =
        GetCanonicalOrderSnapshot();
    ContinuityIdentityMetadata targetMetadata;

    if (
        !BuildContinuityIdentityMetadata(
            targetMapping.windowsIdentity,
            &targetMetadata
        )
    ) {
        std::wstring possiblePredecessor;
        bool ambiguous = false;
        const bool packageMetadataPending =
            !BuildWindowsAppsGuidContinuityPath(
                QueryStringValue(MakeTrayEntrySubkey(targetMapping.windowsIdentity),
                                 L"ExecutablePath"), nullptr).empty();
        if (packageMetadataPending || FindWindowsAppsUidCanonicalPredecessor(
                targetMapping.windowsIdentity, targetKey, canonicalSnapshot,
                &possiblePredecessor, &ambiguous) || ambiguous) {
            TOR_LOG(
                L"TRAY_ORDER_LOCK_CONTINUITY_GROUP_DEFERRED "
                L"reason=\"target-metadata-unavailable\" "
                L"windowsIdentity=%llu targetKey=\"%s\"",
                static_cast<unsigned long long>(targetMapping.windowsIdentity),
                targetKey.c_str()
            );
            return ContinuityReconcileResult::Deferred;
        }
        TOR_LOG(
            L"TRAY_ORDER_LOCK_CONTINUITY_NO_CANDIDATE "
            L"reason=\"target-metadata-unavailable\" "
            L"windowsIdentity=%llu targetKey=\"%s\"",
            static_cast<unsigned long long>(targetMapping.windowsIdentity),
            targetKey.c_str()
        );
        return ContinuityReconcileResult::NoCandidate;
    }

    const UIOrderSnapshot uiOrder =
        CaptureUIOrderSnapshot();

    if (!uiOrder.valid) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_CONTINUITY_GROUP_DEFERRED "
            L"reason=\"invalid-ui-order\" "
            L"windowsIdentity=%llu "
            L"targetKey=\"%s\"",
            static_cast<unsigned long long>(
                targetMapping.windowsIdentity
            ),
            targetKey.c_str()
        );

        return
            ContinuityReconcileResult::Deferred;
    }

    const std::vector<LogicalSnapshotEntry> logical =
        BuildLogicalSnapshot(
            uiOrder
        );

    // A recorded UID position may be a manual preference, so do not replace it.
    if (!targetMetadata.guidBacked &&
        !BuildWindowsAppsGuidContinuityPath(
            QueryStringValue(MakeTrayEntrySubkey(targetMapping.windowsIdentity),
                             L"ExecutablePath"), nullptr).empty() &&
        std::find(canonicalSnapshot.begin(), canonicalSnapshot.end(),
                  targetKey) != canonicalSnapshot.end()) {
        return ContinuityReconcileResult::NoCandidate;
    }

    ContinuityGroupAnalysis group;

    if (
        !AnalyzeContinuityGroup(
            targetMapping.windowsIdentity,
            targetKey,
            logical,
            canonicalSnapshot,
            &group
        )
    ) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_CONTINUITY_NO_CANDIDATE "
            L"reason=\"group-analysis-failed\" "
            L"windowsIdentity=%llu targetKey=\"%s\"",
            static_cast<unsigned long long>(targetMapping.windowsIdentity),
            targetKey.c_str()
        );
        return
            ContinuityReconcileResult::NoCandidate;
    }

    if (group.ambiguous || group.canonicalMembers == 0 ||
        (!targetMetadata.guidBacked && targetMetadata.tooltip.empty() &&
         group.canonicalMembers > 1)) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_CONTINUITY_GROUP_DEFERRED "
            L"reason=\"%s\" "
            L"windowsIdentity=%llu "
            L"groupMembers=%llu "
            L"targetKey=\"%s\"",
            group.ambiguous || group.canonicalMembers > 1
                ? L"ambiguous-canonical-group"
                : L"no-canonical-group-anchor",
            static_cast<unsigned long long>(
                targetMapping.windowsIdentity
            ),
            static_cast<unsigned long long>(
                group.keys.size()
            ),
            targetKey.c_str()
        );

        return
            ContinuityReconcileResult::Deferred;
    }

    if (
        !IsSafeContinuityLiveState(
            targetMapping,
            group
        )
    ) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_CONTINUITY_GROUP_DEFERRED "
            L"reason=\"unsafe-live-state\" "
            L"windowsIdentity=%llu "
            L"groupMembers=%llu "
            L"canonicalMembers=%u "
            L"targetKey=\"%s\"",
            static_cast<unsigned long long>(
                targetMapping.windowsIdentity
            ),
            static_cast<unsigned long long>(
                group.keys.size()
            ),
            group.canonicalMembers,
            targetKey.c_str()
        );

        return
            ContinuityReconcileResult::Deferred;
    }

    std::lock_guard<std::mutex> lock(
        g_canonicalMutex
    );

    if (g_canonicalOrder != canonicalSnapshot) {
        return ContinuityReconcileResult::Deferred;
    }

    std::size_t earliestIndex =
        g_canonicalOrder.size();

    std::size_t targetPreviousIndex =
        g_canonicalOrder.size();

    unsigned int canonicalMembers =
        0;

    for (
        std::size_t index = 0;
        index <
            g_canonicalOrder.size();
        index++
    ) {
        if (
            !ContinuityGroupContainsKey(
                group,
                g_canonicalOrder[index]
            )
        ) {
            continue;
        }

        canonicalMembers++;

        if (
            index <
            earliestIndex
        ) {
            earliestIndex =
                index;
        }

        if (
            g_canonicalOrder[index] ==
            targetKey
        ) {
            targetPreviousIndex =
                index;
        }
    }

    if (canonicalMembers == 0) {
        return
            ContinuityReconcileResult::Deferred;
    }

    const std::vector<std::wstring> beforeOrder =
        g_canonicalOrder;

    const std::uint64_t beforeFingerprint =
        DiagnosticCanonicalFingerprint(
            beforeOrder
        );

    std::vector<std::wstring> updated;

    updated.reserve(
        beforeOrder.size()
    );

    for (
        const std::wstring& key :
        beforeOrder
    ) {
        if (
            ContinuityGroupContainsKey(
                group,
                key
            )
        ) {
            continue;
        }

        updated.push_back(
            key
        );
    }

    const std::size_t preservedIndex =
        std::min(
            earliestIndex,
            updated.size()
        );

    updated.insert(
        updated.begin() +
            preservedIndex,
        targetKey
    );

    if (updated == beforeOrder) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_CONTINUITY_GROUP_STABLE "
            L"windowsIdentity=%llu "
            L"groupMembers=%llu "
            L"canonicalIndex=%llu "
            L"targetKey=\"%s\"",
            static_cast<unsigned long long>(
                targetMapping.windowsIdentity
            ),
            static_cast<unsigned long long>(
                group.keys.size()
            ),
            static_cast<unsigned long long>(
                preservedIndex
            ),
            targetKey.c_str()
        );

        return
            ContinuityReconcileResult::Reconciled;
    }

    const std::uint64_t afterFingerprint =
        DiagnosticCanonicalFingerprint(
            updated
        );

    g_canonicalOrder =
        updated;

    const bool persisted =
        PersistCanonicalOrderLocked();

    if (!persisted) {
        g_canonicalOrder =
            beforeOrder;
    }

    const unsigned int aliasesRemoved =
        canonicalMembers >
                0
            ? canonicalMembers - 1
            : 0;

    TOR_LOG(
        L"TRAY_ORDER_LOCK_CONTINUITY_GROUP_MIGRATION "
        L"windowsIdentity=%llu "
        L"groupMembers=%llu "
        L"canonicalMembers=%u "
        L"anchorIndex=%llu "
        L"targetPreviousIndex=%llu "
        L"preservedIndex=%llu "
        L"aliasesRemoved=%u "
        L"beforeFingerprint=%016llX "
        L"afterFingerprint=%016llX "
        L"persisted=%d "
        L"targetKey=\"%s\"",
        static_cast<unsigned long long>(
            targetMapping.windowsIdentity
        ),
        static_cast<unsigned long long>(
            group.keys.size()
        ),
        canonicalMembers,
        static_cast<unsigned long long>(
            earliestIndex
        ),
        static_cast<unsigned long long>(
            targetPreviousIndex
        ),
        static_cast<unsigned long long>(
            preservedIndex
        ),
        aliasesRemoved,
        static_cast<unsigned long long>(
            beforeFingerprint
        ),
        static_cast<unsigned long long>(
            afterFingerprint
        ),
        persisted
            ? 1
            : 0,
        targetKey.c_str()
    );

    return
        persisted
            ? ContinuityReconcileResult::Reconciled
            : ContinuityReconcileResult::Deferred;
}
bool IsCanonicalRelationSatisfied(
    unsigned int targetIndex,
    bool precedingFound,
    unsigned int precedingIndex,
    bool followingFound,
    unsigned int followingIndex
) {
    if (
        precedingFound &&
        followingFound
    ) {
        return
            precedingIndex <
                targetIndex &&
            targetIndex <
                followingIndex;
    }

    if (
        precedingFound
    ) {
        return
            precedingIndex <
            targetIndex;
    }

    if (
        followingFound
    ) {
        return
            targetIndex <
            followingIndex;
    }

    return false;
}
unsigned int ClampVectorIndex(
    unsigned int index,
    unsigned int size
) {
    if (size == 0) {
        return 0;
    }

    if (index >= size) {
        return size - 1;
    }

    return index;
}

unsigned int CalculateImmediatelyAfterIndex(
    unsigned int anchorIndex,
    unsigned int targetIndex,
    unsigned int size
) {
    const unsigned int desiredIndex =
        targetIndex < anchorIndex
            ? anchorIndex
            : anchorIndex + 1;

    return
        ClampVectorIndex(
            desiredIndex,
            size
        );
}

unsigned int CalculateImmediatelyBeforeIndex(
    unsigned int anchorIndex,
    unsigned int targetIndex,
    unsigned int size
) {
    const unsigned int desiredIndex =
        targetIndex < anchorIndex
            ? anchorIndex - 1
            : anchorIndex;

    return
        ClampVectorIndex(
            desiredIndex,
            size
        );
}

bool AppendNewCanonicalKeyAtEnd(
    const std::wstring& targetKey,
    const std::vector<std::wstring>& canonicalSnapshot,
    bool* persisted
) {
    if (
        targetKey.empty()
    ) {
        return false;
    }

    std::lock_guard<std::mutex> lock(
        g_canonicalMutex
    );

    if (g_canonicalOrder != canonicalSnapshot) {
        return false;
    }

    if (
        ContainsCanonicalKeyLocked(
            targetKey
        )
    ) {
        if (persisted) {
            *persisted =
                true;
        }

        return true;
    }

    g_canonicalOrder.push_back(
        targetKey
    );

    const bool writeSucceeded =
        PersistCanonicalOrderLocked();

    if (!writeSucceeded) {
        g_canonicalOrder.pop_back();
    }

    if (persisted) {
        *persisted =
            writeSucceeded;
    }

    return writeSucceeded;
}

bool AdoptNewIconAtWindowsDefault(
    const std::wstring& targetKey,
    const std::vector<std::wstring>& canonicalSnapshot,
    const LiveOverflowSnapshot& overflow,
    bool* persisted
) {
    if (
        targetKey.empty() ||
        !overflow.valid ||
        !overflow.targetFound ||
        overflow.targetIndex >=
            overflow.entries.size()
    ) {
        return false;
    }

    std::wstring precedingKey;
    std::wstring followingKey;

    for (
        unsigned int index =
            overflow.targetIndex;
        index >
            0;
        index--
    ) {
        const LiveOverflowEntry& entry =
            overflow.entries[
                index -
                1
            ];

        if (
            !entry.uniqueLogical ||
            entry.logicalKey.empty()
        ) {
            continue;
        }

        if (
            std::find(
                canonicalSnapshot.begin(),
                canonicalSnapshot.end(),
                entry.logicalKey
            ) !=
                canonicalSnapshot.end()
        ) {
            precedingKey =
                entry.logicalKey;

            break;
        }
    }

    for (
        unsigned int index =
            overflow.targetIndex +
            1;
        index <
            overflow.entries.size();
        index++
    ) {
        const LiveOverflowEntry& entry =
            overflow.entries[index];

        if (
            !entry.uniqueLogical ||
            entry.logicalKey.empty()
        ) {
            continue;
        }

        if (
            std::find(
                canonicalSnapshot.begin(),
                canonicalSnapshot.end(),
                entry.logicalKey
            ) !=
                canonicalSnapshot.end()
        ) {
            followingKey =
                entry.logicalKey;

            break;
        }
    }

    if (
        precedingKey.empty() &&
        followingKey.empty()
    ) {
        return false;
    }

    std::lock_guard<std::mutex> lock(
        g_canonicalMutex
    );

    if (g_canonicalOrder != canonicalSnapshot) {
        return false;
    }

    if (
        ContainsCanonicalKeyLocked(
            targetKey
        )
    ) {
        if (persisted) {
            *persisted =
                true;
        }

        return true;
    }

    auto precedingIterator =
        precedingKey.empty()
            ? g_canonicalOrder.end()
            : std::find(
                  g_canonicalOrder.begin(),
                  g_canonicalOrder.end(),
                  precedingKey
              );

    auto followingIterator =
        followingKey.empty()
            ? g_canonicalOrder.end()
            : std::find(
                  g_canonicalOrder.begin(),
                  g_canonicalOrder.end(),
                  followingKey
              );

    if (
        precedingIterator !=
            g_canonicalOrder.end() &&
        followingIterator !=
            g_canonicalOrder.end() &&
        std::distance(
            g_canonicalOrder.begin(),
            precedingIterator
        ) >=
            std::distance(
                g_canonicalOrder.begin(),
                followingIterator
            )
    ) {
        return false;
    }

    if (
        precedingIterator !=
        g_canonicalOrder.end()
    ) {
        g_canonicalOrder.insert(
            std::next(
                precedingIterator
            ),
            targetKey
        );
    }
    else if (
        followingIterator !=
        g_canonicalOrder.end()
    ) {
        g_canonicalOrder.insert(
            followingIterator,
            targetKey
        );
    }
    else {
        return false;
    }

    const bool writeSucceeded =
        PersistCanonicalOrderLocked();

    if (!writeSucceeded) {
        g_canonicalOrder = canonicalSnapshot;
    }

    if (persisted) {
        *persisted =
            writeSucceeded;
    }

    return writeSucceeded;
}

bool AdoptNewIconFromUiOrder(
    const std::wstring& targetKey,
    std::uint64_t windowsIdentity,
    const std::vector<std::wstring>& canonicalSnapshot,
    bool* persisted
) {
    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    if (
        !snapshot.valid
    ) {
        return false;
    }

    const std::vector<LogicalSnapshotEntry> logical =
        BuildLogicalSnapshot(
            snapshot
        );

    const std::vector<std::wstring>& canonical = canonicalSnapshot;

    std::size_t targetIndex =
        logical.size();

    for (
        std::size_t index = 0;
        index <
            logical.size();
        index++
    ) {
        const LogicalSnapshotEntry& entry =
            logical[index];

        if (
            entry.identity ==
                windowsIdentity &&
            entry.unique &&
            entry.key ==
                targetKey
        ) {
            targetIndex =
                index;

            break;
        }
    }

    if (
        targetIndex ==
        logical.size()
    ) {
        return false;
    }

    std::wstring precedingKey;
    std::wstring followingKey;

    for (
        std::size_t index =
            targetIndex;
        index >
            0;
        index--
    ) {
        const LogicalSnapshotEntry& candidate =
            logical[
                index -
                1
            ];

        if (
            candidate.unique &&
            !candidate.key.empty() &&
            std::find(
                canonical.begin(),
                canonical.end(),
                candidate.key
            ) !=
                canonical.end()
        ) {
            precedingKey =
                candidate.key;

            break;
        }
    }

    for (
        std::size_t index =
            targetIndex +
            1;
        index <
            logical.size();
        index++
    ) {
        const LogicalSnapshotEntry& candidate =
            logical[index];

        if (
            candidate.unique &&
            !candidate.key.empty() &&
            std::find(
                canonical.begin(),
                canonical.end(),
                candidate.key
            ) !=
                canonical.end()
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
        return false;
    }

    std::lock_guard<std::mutex> lock(
        g_canonicalMutex
    );

    if (g_canonicalOrder != canonicalSnapshot) {
        return false;
    }

    if (
        ContainsCanonicalKeyLocked(
            targetKey
        )
    ) {
        if (persisted) {
            *persisted =
                true;
        }

        return true;
    }

    auto precedingIterator =
        precedingKey.empty()
            ? g_canonicalOrder.end()
            : std::find(
                  g_canonicalOrder.begin(),
                  g_canonicalOrder.end(),
                  precedingKey
              );

    auto followingIterator =
        followingKey.empty()
            ? g_canonicalOrder.end()
            : std::find(
                  g_canonicalOrder.begin(),
                  g_canonicalOrder.end(),
                  followingKey
              );

    if (
        precedingIterator !=
            g_canonicalOrder.end() &&
        followingIterator !=
            g_canonicalOrder.end() &&
        precedingIterator >=
            followingIterator
    ) {
        return false;
    }

    if (
        precedingIterator !=
        g_canonicalOrder.end()
    ) {
        g_canonicalOrder.insert(
            std::next(
                precedingIterator
            ),
            targetKey
        );
    }
    else if (
        followingIterator !=
        g_canonicalOrder.end()
    ) {
        g_canonicalOrder.insert(
            followingIterator,
            targetKey
        );
    }
    else {
        return false;
    }

    const bool writeSucceeded =
        PersistCanonicalOrderLocked();

    if (!writeSucceeded) {
        g_canonicalOrder = canonicalSnapshot;
    }

    if (persisted) {
        *persisted =
            writeSucceeded;
    }

    return writeSucceeded;
}
void HandleNewIcon(
    void* manager,
    const LiveIdentityMapping& targetMapping,
    const std::wstring& targetKey,
    const std::vector<std::wstring>& canonical,
    unsigned long long observation,
    unsigned long long newIcon
) {
    const NewIconBehavior behavior =
        static_cast<NewIconBehavior>(
            g_newIconBehavior.load(
                std::memory_order_acquire
            )
        );

    const std::uint64_t canonicalFingerprint =
        DiagnosticCanonicalFingerprint(
            canonical
        );

    TOR_LOG(
        L"TRAY_ORDER_LOCK_NEW_ICON_CONTEXT "
        L"observation=%llu "
        L"newIcon=%llu "
        L"windowsIdentity=%llu "
        L"canonicalFingerprint=%016llX "
        L"targetKey=\"%s\"",
        observation,
        newIcon,
        static_cast<unsigned long long>(
            targetMapping.windowsIdentity
        ),
        static_cast<unsigned long long>(
            canonicalFingerprint
        ),
        targetKey.c_str()
    );

    const LiveOverflowSnapshot before =
        CaptureLiveOverflowSnapshot(
            targetMapping.abi
        );

    if (
        !before.valid ||
        !before.targetFound ||
        CountOverflowLogicalKey(
            before,
            targetKey
        ) !=
            1
    ) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_NEW_ICON "
            L"observation=%llu "
            L"newIcon=%llu "
            L"windowsIdentity=%llu "
            L"behavior=%s "
            L"action=\"leave-windows-default\" "
            L"reason=\"unsafe-live-state\"",
            observation,
            newIcon,
            static_cast<unsigned long long>(
                targetMapping.windowsIdentity
            ),
            behavior ==
                    NewIconBehavior::PlaceAtEnd
                ? L"place-at-end"
                : L"windows-default"
        );

        return;
    }

    if (
        behavior ==
        NewIconBehavior::WindowsDefault
    ) {
        bool persisted =
            false;

        bool adopted =
            AdoptNewIconAtWindowsDefault(
                targetKey,
                canonical,
                before,
                &persisted
            );

        const wchar_t* adoptionSource =
            adopted
                ? L"live-overflow"
                : L"none";

        if (
            !adopted
        ) {
            adopted =
                AdoptNewIconFromUiOrder(
                    targetKey,
                    targetMapping.windowsIdentity,
                    canonical,
                    &persisted
                );

            if (
                adopted
            ) {
                adoptionSource =
                    L"ui-order";
            }
        }

        TOR_LOG(
            L"TRAY_ORDER_LOCK_NEW_ICON "
            L"observation=%llu "
            L"newIcon=%llu "
            L"windowsIdentity=%llu "
            L"behavior=windows-default "
            L"action=\"keep-current\" "
            L"targetIndex=%u "
            L"adopted=%d "
            L"persisted=%d "
            L"adoptionSource=%s",
            observation,
            newIcon,
            static_cast<unsigned long long>(
                targetMapping.windowsIdentity
            ),
            before.targetIndex,
            adopted
                ? 1
                : 0,
            persisted
                ? 1
                : 0,
            adoptionSource
        );

        return;
    }

    if (
        before.size ==
        0
    ) {
        return;
    }

    const unsigned int desiredIndex =
        before.size -
        1;

    bool moveAttempted =
        false;

    bool moveVerified =
        before.targetIndex ==
        desiredIndex;

    if (
        !moveVerified &&
        manager &&
        NotificationAreaIconManager_MoveIcon &&
        targetMapping.abi
    ) {
        if (GetCanonicalOrderSnapshot() != canonical) {
            TOR_LOG(L"TRAY_ORDER_LOCK_NEW_ICON_SKIPPED "
                    L"reason=\"canonical-order-changed\"");
            return;
        }
        moveAttempted =
            true;

        void* iconArgumentStorage =
            targetMapping.abi;

        g_internalMoveDepth++;

        NotificationAreaIconManager_MoveIcon(
            manager,
            &iconArgumentStorage,
            kOverflowLocation,
            desiredIndex
        );

        g_internalMoveDepth--;

        const LiveOverflowSnapshot after =
            CaptureLiveOverflowSnapshot(
                targetMapping.abi
            );

        moveVerified =
            after.valid &&
            after.targetFound &&
            CountOverflowLogicalKey(
                after,
                targetKey
            ) ==
                1 &&
            after.size >
                0 &&
            after.targetIndex ==
                after.size -
                1;
    }

    bool persisted =
        false;

    const bool adopted =
        moveVerified &&
        AppendNewCanonicalKeyAtEnd(
            targetKey,
            canonical,
            &persisted
        );

    TOR_LOG(
        L"TRAY_ORDER_LOCK_NEW_ICON "
        L"observation=%llu "
        L"newIcon=%llu "
        L"windowsIdentity=%llu "
        L"behavior=place-at-end "
        L"action=\"place-at-end\" "
        L"beforeIndex=%u "
        L"requestedIndex=%u "
        L"moveAttempted=%d "
        L"verified=%d "
        L"adopted=%d "
        L"persisted=%d",
        observation,
        newIcon,
        static_cast<unsigned long long>(
            targetMapping.windowsIdentity
        ),
        before.targetIndex,
        desiredIndex,
        moveAttempted
            ? 1
            : 0,
        moveVerified
            ? 1
            : 0,
        adopted
            ? 1
            : 0,
        persisted
            ? 1
            : 0
    );
}
void RecordRestoreObservationSkip(
    const wchar_t* reason,
    std::uint64_t windowsIdentity
) {
    if (windowsIdentity != 0) {
        std::lock_guard<std::mutex> lock(g_restoreRetryMutex);
        if (std::find(g_restoreRetryIdentities.begin(),
                      g_restoreRetryIdentities.end(), windowsIdentity) ==
            g_restoreRetryIdentities.end()) {
            if (g_restoreRetryIdentities.size() == 64) {
                g_restoreRetryIdentities.erase(g_restoreRetryIdentities.begin());
            }
            g_restoreRetryIdentities.push_back(windowsIdentity);
        }
    }
    const unsigned long long skip =
        g_restoreSkipCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    TOR_LOG(
        L"TRAY_ORDER_LOCK_RESTORE_OBSERVATION_SKIPPED "
        L"skip=%llu "
        L"reason=\"%s\" "
        L"windowsIdentity=%llu",
        skip,
        reason,
        static_cast<unsigned long long>(
            windowsIdentity
        )
    );
}

bool HasSufficientTrustedLiveBaseline(
    unsigned int liveSize
) {
    if (
        !g_liveBaselineActiveInSession.load(
            std::memory_order_acquire
        )
    ) {
        return false;
    }

    const unsigned int baselineSize =
        g_liveBaselineSize.load(
            std::memory_order_acquire
        );

    if (
        baselineSize < 2 ||
        baselineSize > 64
    ) {
        return false;
    }

    const unsigned int required =
        std::max(
            2u,
            (baselineSize * 3u + 3u) / 4u
        );

    return liveSize >= required;
}
void RestoreCanonicalRelationForMapping(
    void* manager,
    const LiveIdentityMapping& targetMapping
) {
    {
        std::lock_guard<std::mutex> lock(g_restoreRetryMutex);
        g_restoreRetryIdentities.erase(
            std::remove(g_restoreRetryIdentities.begin(),
                        g_restoreRetryIdentities.end(), targetMapping.windowsIdentity),
            g_restoreRetryIdentities.end());
    }
    if (
        g_internalMoveDepth !=
            0 ||
        g_taskbarMoveDepth !=
            0 ||
        static_cast<OrderingBehavior>(
            g_orderingBehavior.load(
                std::memory_order_acquire
            )
        ) !=
            OrderingBehavior::PreserveManual
    ) {
        return;
    }

    const unsigned long long observation =
        g_restoreObservationCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    const std::wstring targetKey =
        BuildLogicalKey(
            targetMapping.windowsIdentity
        );

    if (
        targetKey.empty()
    ) {
        RecordRestoreObservationSkip(
            L"target-logical-key-unsupported",
            targetMapping.windowsIdentity
        );

        return;
    }

    std::vector<std::wstring> canonical =
        GetCanonicalOrderSnapshot();

    const ContinuityReconcileResult continuityResult =
        TryReconcileCanonicalContinuityGroup(
            targetMapping,
            targetKey
        );

    if (
        continuityResult ==
            ContinuityReconcileResult::Deferred
    ) {
        RecordRestoreObservationSkip(
            L"continuity-group-deferred",
            targetMapping.windowsIdentity
        );

        return;
    }

    canonical = GetCanonicalOrderSnapshot();

    const std::uint64_t canonicalFingerprint =
        DiagnosticCanonicalFingerprint(
            canonical
        );

    const auto canonicalTarget =
        std::find(
            canonical.begin(),
            canonical.end(),
            targetKey
        );

    if (
        canonicalTarget != canonical.end() &&
        !g_liveBaselineActiveInSession.load(
            std::memory_order_acquire
        )
    ) {
        RecordRestoreObservationSkip(
            L"canonical-live-baseline-not-active-in-session",
            targetMapping.windowsIdentity
        );

        return;
    }
    if (
        canonicalTarget ==
        canonical.end()
    ) {
        const unsigned long long newIcon =
            g_restoreNewIconCount.fetch_add(
                1,
                std::memory_order_relaxed
            ) +
            1;

        HandleNewIcon(
            manager,
            targetMapping,
            targetKey,
            canonical,
            observation,
            newIcon
        );

        return;
    }

    const unsigned long long candidate =
        g_restoreKnownCandidateCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    const std::size_t canonicalIndex =
        static_cast<std::size_t>(
            std::distance(
                canonical.begin(),
                canonicalTarget
            )
        );

    const LiveOverflowSnapshot before =
        CaptureLiveOverflowSnapshot(
            targetMapping.abi
        );

    if (
        !before.valid
    ) {
        RecordRestoreObservationSkip(
            L"overflow-snapshot-unavailable",
            targetMapping.windowsIdentity
        );

        return;
    }

    if (
        !before.targetFound
    ) {
        RecordRestoreObservationSkip(
            L"target-not-in-overflow",
            targetMapping.windowsIdentity
        );

        return;
    }

    if (
        CountOverflowLogicalKey(
            before,
            targetKey
        ) !=
            1
    ) {
        RecordRestoreObservationSkip(
            L"target-logical-key-not-unique-in-overflow",
            targetMapping.windowsIdentity
        );

        return;
    }

    // A local repair uses verified live anchors, not the number of apps left open.
    if (before.size > 64 || before.entries.size() != before.size ||
        before.mappedEntries != before.size ||
        std::any_of(before.entries.begin(), before.entries.end(),
            [](const LiveOverflowEntry& entry) {
                return !entry.mapped || !entry.uniqueLogical || entry.logicalKey.empty();
            })) {
        RecordRestoreObservationSkip(
            L"incomplete-live-snapshot",
            targetMapping.windowsIdentity
        );

        return;
    }

    bool precedingFound =
        false;

    unsigned int precedingIndex =
        0;

    std::wstring precedingKey;

    for (
        std::size_t index = canonicalIndex;
        index >
            0;
        index--
    ) {
        const std::wstring& candidateKey =
            canonical[
                index -
                1
            ];

        if (
            FindUniqueOverflowIndexForKey(
                before,
                candidateKey,
                &precedingIndex
            )
        ) {
            precedingFound =
                true;

            precedingKey =
                candidateKey;

            break;
        }
    }

    bool followingFound =
        false;

    unsigned int followingIndex =
        0;

    std::wstring followingKey;

    for (
        std::size_t index =
            canonicalIndex +
            1;
        index <
            canonical.size();
        index++
    ) {
        const std::wstring& candidateKey =
            canonical[index];

        if (
            FindUniqueOverflowIndexForKey(
                before,
                candidateKey,
                &followingIndex
            )
        ) {
            followingFound =
                true;

            followingKey =
                candidateKey;

            break;
        }
    }

    TOR_LOG(
        L"TRAY_ORDER_LOCK_RESTORE_CONTEXT "
        L"observation=%llu "
        L"windowsIdentity=%llu "
        L"canonicalIndex=%llu "
        L"canonicalEntries=%llu "
        L"canonicalFingerprint=%016llX "
        L"targetKey=\"%s\" "
        L"precedingKey=\"%s\" "
        L"followingKey=\"%s\" "
        L"precedingFound=%d "
        L"followingFound=%d",
        observation,
        static_cast<unsigned long long>(
            targetMapping.windowsIdentity
        ),
        static_cast<unsigned long long>(
            canonicalIndex
        ),
        static_cast<unsigned long long>(
            canonical.size()
        ),
        static_cast<unsigned long long>(
            canonicalFingerprint
        ),
        targetKey.c_str(),
        precedingKey.empty()
            ? L"<none>"
            : precedingKey.c_str(),
        followingKey.empty()
            ? L"<none>"
            : followingKey.c_str(),
        precedingFound
            ? 1
            : 0,
        followingFound
            ? 1
            : 0
    );

    if (
        !precedingFound &&
        !followingFound
    ) {
        RecordRestoreObservationSkip(
            L"no-live-canonical-neighbor",
            targetMapping.windowsIdentity
        );

        return;
    }

    const bool hasCanonicalPredecessor =
        canonicalIndex >
        0;

    const bool hasCanonicalFollower =
        canonicalIndex +
            1 <
        canonical.size();

    if (
        (
            hasCanonicalPredecessor &&
            !precedingFound
        ) ||
        (
            hasCanonicalFollower &&
            !followingFound
        )
    ) {
        RecordRestoreObservationSkip(
            L"incomplete-live-canonical-neighborhood",
            targetMapping.windowsIdentity
        );

        return;
    }

    if (
        precedingFound &&
        followingFound &&
        precedingIndex >=
            followingIndex
    ) {
        RecordRestoreObservationSkip(
            L"live-neighbor-order-conflicts-with-canonical-order",
            targetMapping.windowsIdentity
        );

        return;
    }

    const bool relationSatisfied =
        IsCanonicalRelationSatisfied(
            before.targetIndex,
            precedingFound,
            precedingIndex,
            followingFound,
            followingIndex
        );

    unsigned int desiredIndex =
        before.targetIndex;

    if (
        !relationSatisfied
    ) {
        if (
            precedingFound
        ) {
            desiredIndex =
                CalculateImmediatelyAfterIndex(
                    precedingIndex,
                    before.targetIndex,
                    before.size
                );
        }
        else {
            desiredIndex =
                CalculateImmediatelyBeforeIndex(
                    followingIndex,
                    before.targetIndex,
                    before.size
                );
        }
    }

    const bool wouldMove =
        !relationSatisfied &&
        desiredIndex !=
            before.targetIndex;

    TOR_LOG(
        L"TRAY_ORDER_LOCK_RESTORE_OBSERVATION "
        L"observation=%llu "
        L"candidate=%llu "
        L"windowsIdentity=%llu "
        L"canonicalIndex=%llu "
        L"overflowSize=%u "
        L"mappedOverflowEntries=%u "
        L"targetIndex=%u "
        L"precedingFound=%d "
        L"precedingIndex=%u "
        L"followingFound=%d "
        L"followingIndex=%u "
        L"relationSatisfied=%d "
        L"wouldMove=%d "
        L"computedTargetIndex=%u",
        observation,
        candidate,
        static_cast<unsigned long long>(
            targetMapping.windowsIdentity
        ),
        static_cast<unsigned long long>(
            canonicalIndex
        ),
        before.size,
        before.mappedEntries,
        before.targetIndex,
        precedingFound
            ? 1
            : 0,
        precedingIndex,
        followingFound
            ? 1
            : 0,
        followingIndex,
        relationSatisfied
            ? 1
            : 0,
        wouldMove
            ? 1
            : 0,
        desiredIndex
    );

    if (
        !wouldMove
    ) {
        return;
    }

    if (
        !manager ||
        !NotificationAreaIconManager_MoveIcon ||
        !targetMapping.abi
    ) {
        RecordRestoreObservationSkip(
            L"manager-move-unavailable",
            targetMapping.windowsIdentity
        );

        return;
    }

    if (GetCanonicalOrderSnapshot() != canonical) {
        RecordRestoreObservationSkip(
            L"canonical-order-changed", targetMapping.windowsIdentity
        );
        return;
    }

    const unsigned long long move =
        g_restoreMoveAttemptCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    TOR_LOG(
        L"TRAY_ORDER_LOCK_RESTORE_MOVE_BEGIN "
        L"move=%llu "
        L"observation=%llu "
        L"windowsIdentity=%llu "
        L"manager=%p "
        L"iconAbi=%p "
        L"targetIndex=%u "
        L"requestedIndex=%u "
        L"precedingFound=%d "
        L"precedingIndex=%u "
        L"followingFound=%d "
        L"followingIndex=%u",
        move,
        observation,
        static_cast<unsigned long long>(
            targetMapping.windowsIdentity
        ),
        manager,
        targetMapping.abi,
        before.targetIndex,
        desiredIndex,
        precedingFound
            ? 1
            : 0,
        precedingIndex,
        followingFound
            ? 1
            : 0,
        followingIndex
    );

    void* iconArgumentStorage =
        targetMapping.abi;

    g_internalMoveDepth++;

    NotificationAreaIconManager_MoveIcon(
        manager,
        &iconArgumentStorage,
        kOverflowLocation,
        desiredIndex
    );

    g_internalMoveDepth--;

    const LiveOverflowSnapshot after =
        CaptureLiveOverflowSnapshot(
            targetMapping.abi
        );

    const bool targetUniqueAfter =
        after.valid &&
        after.targetFound &&
        CountOverflowLogicalKey(
            after,
            targetKey
        ) ==
            1;

    bool precedingFoundAfter =
        false;

    unsigned int precedingIndexAfter =
        0;

    if (
        !precedingKey.empty()
    ) {
        precedingFoundAfter =
            FindUniqueOverflowIndexForKey(
                after,
                precedingKey,
                &precedingIndexAfter
            );
    }

    bool followingFoundAfter =
        false;

    unsigned int followingIndexAfter =
        0;

    if (
        !followingKey.empty()
    ) {
        followingFoundAfter =
            FindUniqueOverflowIndexForKey(
                after,
                followingKey,
                &followingIndexAfter
            );
    }

    const bool expectedNeighborsPresentAfter =
        (
            precedingKey.empty() ||
            precedingFoundAfter
        ) &&
        (
            followingKey.empty() ||
            followingFoundAfter
        );

    const bool neighborConflictAfter =
        precedingFoundAfter &&
        followingFoundAfter &&
        precedingIndexAfter >=
            followingIndexAfter;

    const bool relationRestored =
        targetUniqueAfter &&
        expectedNeighborsPresentAfter &&
        !neighborConflictAfter &&
        IsCanonicalRelationSatisfied(
            after.targetIndex,
            precedingFoundAfter,
            precedingIndexAfter,
            followingFoundAfter,
            followingIndexAfter
        );

    const bool moveObserved =
        after.valid &&
        after.targetFound &&
        after.targetIndex !=
            before.targetIndex;

    if (
        moveObserved
    ) {
        g_restoreMoveObservedCount.fetch_add(
            1,
            std::memory_order_relaxed
        );
    }

    const bool verified =
        moveObserved &&
        relationRestored;

    if (
        verified
    ) {
        g_restoreMoveVerifiedCount.fetch_add(
            1,
            std::memory_order_relaxed
        );
    }

    TOR_LOG(
        L"TRAY_ORDER_LOCK_RESTORE_MOVE_COMPLETE "
        L"move=%llu "
        L"windowsIdentity=%llu "
        L"beforeTargetIndex=%u "
        L"requestedIndex=%u "
        L"afterValid=%d "
        L"afterTargetFound=%d "
        L"afterTargetIndex=%u "
        L"moveObserved=%d "
        L"precedingFoundAfter=%d "
        L"precedingIndexAfter=%u "
        L"followingFoundAfter=%d "
        L"followingIndexAfter=%u "
        L"relationRestored=%d "
        L"verified=%d",
        move,
        static_cast<unsigned long long>(
            targetMapping.windowsIdentity
        ),
        before.targetIndex,
        desiredIndex,
        after.valid
            ? 1
            : 0,
        after.targetFound
            ? 1
            : 0,
        after.targetIndex,
        moveObserved
            ? 1
            : 0,
        precedingFoundAfter
            ? 1
            : 0,
        precedingIndexAfter,
        followingFoundAfter
            ? 1
            : 0,
        followingIndexAfter,
        relationRestored
            ? 1
            : 0,
        verified
            ? 1
            : 0
    );
}

void RestoreCanonicalRelation(void* manager, void* iconImplementation) {
    if (g_internalMoveDepth != 0 || g_taskbarMoveDepth != 0) {
        return;
    }
    LiveIdentityMapping mapping;
    if (!LookupLiveMappingByImplementation(iconImplementation, &mapping)) {
        RecordRestoreObservationSkip(L"target-live-map-not-found", 0);
        return;
    }
    RestoreCanonicalRelationForMapping(manager, mapping);
}

// A bounded, event-driven second pass for icons whose individual restore
// was skipped because the other live icons were not yet in canonical order.
// Never retain ABI pointers beyond the immediate move that uses them.
void* AcquireCurrentOverflowIconAtIndex(
    unsigned int index,
    const LiveOverflowEntry& expected
) {
    void* model = g_taskbarModel6.load(std::memory_order_acquire);
    if (!model || !TaskbarModel_GetOverflowIcons_Original ||
        !g_notificationAreaIconVectorId) {
        return nullptr;
    }

    void* collectionAbi = nullptr;
    const HRESULT getterResult = static_cast<HRESULT>(
        TaskbarModel_GetOverflowIcons_Original(model, &collectionAbi)
    );
    if (FAILED(getterResult) || !collectionAbi) {
        return nullptr;
    }

    void* vectorAbi = nullptr;
    const HRESULT queryResult = reinterpret_cast<IUnknown*>(
        collectionAbi
    )->QueryInterface(*g_notificationAreaIconVectorId, &vectorAbi);

    if (FAILED(queryResult) || !vectorAbi) {
        reinterpret_cast<IUnknown*>(collectionAbi)->Release();
        return nullptr;
    }

    void* acquired = nullptr;
    void** vtable = *reinterpret_cast<void***>(vectorAbi);
    if (vtable && vtable[6] && vtable[7]) {
        const auto getAt = reinterpret_cast<Vector_GetAt_t>(vtable[6]);
        const auto getSize = reinterpret_cast<Vector_GetSize_t>(vtable[7]);
        unsigned int liveSize = 0;

        if (SUCCEEDED(getSize(vectorAbi, &liveSize)) && index < liveSize) {
            void* iconAbi = nullptr;
            if (SUCCEEDED(getAt(vectorAbi, index, &iconAbi)) && iconAbi) {
                LiveIdentityMapping mapping;
                if (LookupLiveMapping(iconAbi, &mapping) &&
                    mapping.windowsIdentity == expected.windowsIdentity &&
                    BuildLogicalKey(mapping.windowsIdentity) ==
                        expected.logicalKey) {
                    acquired = iconAbi;
                } else {
                    reinterpret_cast<IUnknown*>(iconAbi)->Release();
                }
            }
        }
    }

    reinterpret_cast<IUnknown*>(vectorAbi)->Release();
    reinterpret_cast<IUnknown*>(collectionAbi)->Release();
    return acquired;
}

// Reacquire live objects after startup deferrals; never cache their raw addresses.
void RetryDeferredLiveContinuity(void* manager) {
    if (!manager || g_internalMoveDepth != 0 || g_taskbarMoveDepth != 0 ||
        static_cast<OrderingBehavior>(g_orderingBehavior.load(
            std::memory_order_acquire)) != OrderingBehavior::PreserveManual) {
        return;
    }

    std::vector<std::uint64_t> attempted;
    for (unsigned int attempt = 0; attempt < 64; ++attempt) {
        const LiveOverflowSnapshot live = CaptureLiveOverflowSnapshot(nullptr);
        if (!live.valid || live.size > 64 ||
            live.entries.size() != live.size ||
            live.mappedEntries != live.size) {
            return;
        }

        std::vector<std::uint64_t> pending;
        {
            std::lock_guard<std::mutex> lock(g_restoreRetryMutex);
            pending = g_restoreRetryIdentities;
        }
        bool retried = false;
        for (unsigned int index = 0; index < live.size; ++index) {
            const LiveOverflowEntry& entry = live.entries[index];
            if (!entry.mapped || !entry.uniqueLogical || entry.logicalKey.empty() ||
                std::find(pending.begin(), pending.end(), entry.windowsIdentity) ==
                    pending.end() ||
                std::find(attempted.begin(), attempted.end(), entry.windowsIdentity) !=
                    attempted.end()) {
                continue;
            }

            attempted.push_back(entry.windowsIdentity);
            void* abi = AcquireCurrentOverflowIconAtIndex(index, entry);
            if (abi) {
                LiveIdentityMapping mapping;
                if (LookupLiveMapping(abi, &mapping) &&
                    mapping.windowsIdentity == entry.windowsIdentity) {
                    RestoreCanonicalRelationForMapping(manager, mapping);
                }
                reinterpret_cast<IUnknown*>(abi)->Release();
            }
            retried = true;
            break;
        }
        if (!retried) {
            return;
        }
    }
}

void ReconcileKnownLiveOverflowOrder(
    void* manager,
    unsigned long long visibleAddCall
) {
    if (!manager || !NotificationAreaIconManager_MoveIcon ||
        g_internalMoveDepth != 0 || g_taskbarMoveDepth != 0 ||
        static_cast<OrderingBehavior>(
            g_orderingBehavior.load(std::memory_order_acquire)) !=
            OrderingBehavior::PreserveManual) {
        return;
    }

    if (
        !g_liveBaselineActiveInSession.load(
            std::memory_order_acquire
        )
    ) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_LIVE_RECONCILE_SKIPPED "
            L"reason=\"canonical-live-baseline-not-established\" "
            L"call=%llu",
            visibleAddCall
        );

        return;
    }

    constexpr unsigned int kMaxSweepIcons = 64;
    const std::vector<std::wstring> canonical =
        GetCanonicalOrderSnapshot();
    const LiveOverflowSnapshot initial =
        CaptureLiveOverflowSnapshot(nullptr);

    // Never operate on unmapped, unknown, or duplicate live identities.
    // Hot reload commonly has unmapped existing objects: that is a no-op.
    if (!initial.valid || initial.size < 2 ||
        initial.size > kMaxSweepIcons ||
        initial.entries.size() != initial.size ||
        initial.mappedEntries != initial.size) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_LIVE_RECONCILE_SKIPPED "
            L"reason=\"incomplete-live-snapshot\" call=%llu "
            L"valid=%d size=%u mapped=%u",
            visibleAddCall, initial.valid ? 1 : 0,
            initial.size, initial.mappedEntries
        );
        return;
    }

    if (
        !HasSufficientTrustedLiveBaseline(
            initial.size
        )
    ) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_LIVE_RECONCILE_SKIPPED "
            L"reason=\"waiting-for-live-baseline-quorum\" "
            L"call=%llu size=%u baselineSize=%u",
            visibleAddCall,
            initial.size,
            g_liveBaselineSize.load(
                std::memory_order_acquire
            )
        );

        return;
    }

    for (const LiveOverflowEntry& entry : initial.entries) {
        if (!entry.mapped || !entry.uniqueLogical ||
            entry.logicalKey.empty() ||
            std::count(canonical.begin(), canonical.end(),
                       entry.logicalKey) != 1) {
            TOR_LOG(
                L"TRAY_ORDER_LOCK_LIVE_RECONCILE_SKIPPED "
                L"reason=\"unknown-or-nonunique-logical-key\" "
                L"call=%llu identity=%llu",
                visibleAddCall,
                static_cast<unsigned long long>(entry.windowsIdentity)
            );
            return;
        }
    }

    std::vector<LiveOverflowEntry> desired = initial.entries;
    std::sort(
        desired.begin(), desired.end(),
        [&canonical](const LiveOverflowEntry& left,
                     const LiveOverflowEntry& right) {
            return std::find(canonical.begin(), canonical.end(),
                             left.logicalKey) <
                   std::find(canonical.begin(), canonical.end(),
                             right.logicalKey);
        }
    );

    bool anyConflict = false;
    for (std::size_t i = 0; i < desired.size(); ++i) {
        if (desired[i].logicalKey != initial.entries[i].logicalKey) {
            anyConflict = true;
            break;
        }
    }
    if (!anyConflict) {
        return;
    }

    // Two concurrently live no-GUID registrations with identical metadata
    // are ambiguous even if their path-based logical keys differ.
    std::vector<ContinuityIdentityMetadata> metadata(initial.size);
    std::vector<bool> metadataValid(initial.size, false);
    for (std::size_t i = 0; i < initial.entries.size(); ++i) {
        metadataValid[i] = BuildContinuityIdentityMetadata(
            initial.entries[i].windowsIdentity, &metadata[i]
        );
    }
    for (std::size_t i = 0; i < metadata.size(); ++i) {
        if (!metadataValid[i]) {
            continue;
        }
        for (std::size_t j = i + 1; j < metadata.size(); ++j) {
            if (metadataValid[j] &&
                ContinuityIdentityMatches(metadata[i], metadata[j])) {
                TOR_LOG(
                    L"TRAY_ORDER_LOCK_LIVE_RECONCILE_SKIPPED "
                    L"reason=\"ambiguous-live-continuity\" "
                    L"call=%llu identityA=%llu identityB=%llu",
                    visibleAddCall,
                    static_cast<unsigned long long>(
                        initial.entries[i].windowsIdentity),
                    static_cast<unsigned long long>(
                        initial.entries[j].windowsIdentity)
                );
                return;
            }
        }
    }

    TOR_LOG(
        L"TRAY_ORDER_LOCK_LIVE_RECONCILE_BEGIN "
        L"call=%llu overflowSize=%u canonicalFingerprint=%016llX",
        visibleAddCall, initial.size,
        static_cast<unsigned long long>(
            DiagnosticCanonicalFingerprint(canonical))
    );

    std::vector<LiveOverflowEntry> observed = initial.entries;
    unsigned int verifiedMoves = 0;

    // Stable insertion: a maximum of size-1 verified moves, with one attempt
    // per position. If Windows disagrees with the predicted entire sequence,
    // stop immediately; do not retry or guess.
    for (std::size_t correctIndex = 0;
         correctIndex < desired.size(); ++correctIndex) {
        if (GetCanonicalOrderSnapshot() != canonical) {
            TOR_LOG(
                L"TRAY_ORDER_LOCK_LIVE_RECONCILE_STOP "
                L"reason=\"canonical-changed\" call=%llu "
                L"verifiedMoves=%u",
                visibleAddCall, verifiedMoves
            );
            return;
        }
        if (observed[correctIndex].logicalKey ==
            desired[correctIndex].logicalKey) {
            continue;
        }

        std::size_t sourceIndex = correctIndex + 1;
        while (sourceIndex < observed.size() &&
               observed[sourceIndex].logicalKey !=
                   desired[correctIndex].logicalKey) {
            ++sourceIndex;
        }
        if (sourceIndex == observed.size()) {
            TOR_LOG(
                L"TRAY_ORDER_LOCK_LIVE_RECONCILE_STOP "
                L"reason=\"desired-key-not-live\" call=%llu "
                L"verifiedMoves=%u",
                visibleAddCall, verifiedMoves
            );
            return;
        }

        void* liveAbi = AcquireCurrentOverflowIconAtIndex(
            static_cast<unsigned int>(sourceIndex), observed[sourceIndex]
        );
        if (!liveAbi) {
            TOR_LOG(
                L"TRAY_ORDER_LOCK_LIVE_RECONCILE_STOP "
                L"reason=\"live-abi-not-confirmed\" call=%llu "
                L"identity=%llu verifiedMoves=%u",
                visibleAddCall,
                static_cast<unsigned long long>(
                    observed[sourceIndex].windowsIdentity),
                verifiedMoves
            );
            return;
        }

        const std::uint64_t movedIdentity =
            observed[sourceIndex].windowsIdentity;
        std::vector<LiveOverflowEntry> predicted = observed;
        std::rotate(predicted.begin() + correctIndex,
                    predicted.begin() + sourceIndex,
                    predicted.begin() + sourceIndex + 1);

        void* iconArgumentStorage = liveAbi;
        g_internalMoveDepth++;
        NotificationAreaIconManager_MoveIcon(
            manager, &iconArgumentStorage, kOverflowLocation,
            static_cast<unsigned int>(correctIndex)
        );
        g_internalMoveDepth--;
        reinterpret_cast<IUnknown*>(liveAbi)->Release();

        const LiveOverflowSnapshot after =
            CaptureLiveOverflowSnapshot(nullptr);
        bool verified = after.valid &&
            after.size == initial.size &&
            after.mappedEntries == after.size &&
            after.entries.size() == predicted.size();
        if (verified) {
            for (std::size_t i = 0; i < predicted.size(); ++i) {
                if (!after.entries[i].mapped ||
                    !after.entries[i].uniqueLogical ||
                    after.entries[i].windowsIdentity !=
                        predicted[i].windowsIdentity ||
                    after.entries[i].logicalKey !=
                        predicted[i].logicalKey) {
                    verified = false;
                    break;
                }
            }
        }

        TOR_LOG(
            L"TRAY_ORDER_LOCK_LIVE_RECONCILE_MOVE_COMPLETE "
            L"call=%llu identity=%llu fromIndex=%u toIndex=%u "
            L"verified=%d",
            visibleAddCall,
            static_cast<unsigned long long>(movedIdentity),
            static_cast<unsigned int>(sourceIndex),
            static_cast<unsigned int>(correctIndex),
            verified ? 1 : 0
        );
        if (!verified) {
            TOR_LOG(
                L"TRAY_ORDER_LOCK_LIVE_RECONCILE_STOP "
                L"reason=\"move-not-verified\" call=%llu "
                L"verifiedMoves=%u",
                visibleAddCall, verifiedMoves
            );
            return;
        }

        observed = after.entries;
        ++verifiedMoves;
    }

    TOR_LOG(
        L"TRAY_ORDER_LOCK_LIVE_RECONCILE_COMPLETE "
        L"call=%llu verifiedMoves=%u overflowSize=%u",
        visibleAddCall, verifiedMoves, initial.size
    );
}
void __cdecl
NotificationAreaIconManager_AddVisible_Hook(
    void* pThis,
    void* iconImplementation
) {
    const unsigned long long callNumber =
        g_visibleAddCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    NotificationAreaIconManager_AddVisible_Original(
        pThis,
        iconImplementation
    );

    const bool internalMove =
        g_internalMoveDepth !=
        0;

    const bool taskbarMove =
        g_taskbarMoveDepth !=
        0;

    TOR_LOG(
        L"TRAY_ORDER_LOCK_VISIBLE_ADD "
        L"call=%llu "
        L"manager=%p "
        L"implementation=%p "
        L"internalMove=%d "
        L"taskbarMove=%d",
        callNumber,
        pThis,
        iconImplementation,
        internalMove
            ? 1
            : 0,
        taskbarMove
            ? 1
            : 0
    );

    if (
        taskbarMove
    ) {
        const unsigned long long suppressed =
            g_restoreSuppressedTaskbarMoveCount.fetch_add(
                1,
                std::memory_order_relaxed
            ) +
            1;

        TOR_LOG(
            L"TRAY_ORDER_LOCK_RESTORE_SUPPRESSED "
            L"suppressed=%llu "
            L"reason=\"taskbar-move-in-progress\" "
            L"manager=%p "
            L"implementation=%p",
            suppressed,
            pThis,
            iconImplementation
        );

        return;
    }

    RestoreCanonicalRelation(
        pThis,
        iconImplementation
    );

    RetryDeferredLiveContinuity(pThis);

    ReconcileKnownLiveOverflowOrder(
        pThis,
        callNumber
    );
}
int __cdecl
TaskbarModel_GetOverflowIcons_Hook(
    void* pThis,
    void** result
) {
    g_overflowGetterCount.fetch_add(
        1,
        std::memory_order_relaxed
    );

    const int originalResult =
        TaskbarModel_GetOverflowIcons_Original(
            pThis,
            result
        );

    if (
        SUCCEEDED(
            static_cast<HRESULT>(
                originalResult
            )
        ) &&
        result &&
        *result
    ) {
        CacheTaskbarModel6(
            pThis
        );
    }

    return originalResult;
}
void __cdecl
NotificationAreaIcon2_Constructor_Hook(
    void* pThis,
    void* identityRvalueReference,
    void* settingsPairReference
) {
    const unsigned long long callNumber =
        g_liveConstructorCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    std::uint64_t windowsIdentity =
        0;

    if (
        settingsPairReference
    ) {
        std::memcpy(
            &windowsIdentity,
            settingsPairReference,
            sizeof(
                windowsIdentity
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
        bool safeToCall = true;
        void* queryObject = pThis;

        if (g_queryInterfaceUsesDefaultAbi) {
            safeToCall = false;

            const auto isReadablePointer = [](const void* address) -> bool {
                if (!address) {
                    return false;
                }

                MEMORY_BASIC_INFORMATION info{};

                if (
                    VirtualQuery(address, &info, sizeof(info)) != sizeof(info) ||
                    info.State != MEM_COMMIT ||
                    (info.Protect & (PAGE_GUARD | PAGE_NOACCESS))
                ) {
                    return false;
                }

                const DWORD protection = info.Protect & 0xFF;

                if (
                    protection != PAGE_READONLY &&
                    protection != PAGE_READWRITE &&
                    protection != PAGE_WRITECOPY &&
                    protection != PAGE_EXECUTE_READ &&
                    protection != PAGE_EXECUTE_READWRITE &&
                    protection != PAGE_EXECUTE_WRITECOPY
                ) {
                    return false;
                }

                const auto position =
                    reinterpret_cast<std::uintptr_t>(address);

                const auto regionStart =
                    reinterpret_cast<std::uintptr_t>(info.BaseAddress);

                const auto regionEnd =
                    regionStart + info.RegionSize;

                return
                    position >= regionStart &&
                    position <= regionEnd &&
                    regionEnd - position >= sizeof(void*);
            };

            unsigned int matches = 0;
            std::size_t matchedOffset = 0;

            const auto objectAddress =
                reinterpret_cast<std::uintptr_t>(pThis);

            for (std::size_t slot = 0; slot < 16; ++slot) {
                const std::size_t offset = slot * sizeof(void*);
                const auto address = objectAddress + offset;

                if (
                    !isReadablePointer(
                        reinterpret_cast<const void*>(address)
                    )
                ) {
                    continue;
                }

                void* const* candidateVtable = nullptr;

                std::memcpy(
                    &candidateVtable,
                    reinterpret_cast<const void*>(address),
                    sizeof(candidateVtable)
                );

                if (
                    !candidateVtable ||
                    reinterpret_cast<std::uintptr_t>(candidateVtable) %
                        alignof(void*) != 0 ||
                    !isReadablePointer(candidateVtable)
                ) {
                    continue;
                }

                void* firstMethod = nullptr;

                std::memcpy(
                    &firstMethod,
                    candidateVtable,
                    sizeof(firstMethod)
                );

                TOR_LOG(
                    L"TRAY_ORDER_LOCK_QI_ABI_SLOT "
                    L"slot=%llu offset=%llu firstMethod=%p",
                    static_cast<unsigned long long>(slot),
                    static_cast<unsigned long long>(offset),
                    firstMethod
                );

                if (
                    firstMethod ==
                    reinterpret_cast<void*>(
                        NotificationAreaIcon_QueryInterface
                    )
                ) {
                    matches++;
                    matchedOffset = offset;
                }
            }

            if (
                matches == 1 &&
                matchedOffset == 2 * sizeof(void*)
            ) {
                queryObject =
                    reinterpret_cast<void*>(
                        objectAddress + matchedOffset
                    );

                safeToCall = true;
            }

            TOR_LOG(
                L"TRAY_ORDER_LOCK_QI_ABI_SCAN "
                L"implementation=%p matches=%u matchedOffset=%llu "
                L"resolvedQuery=%p callAllowed=%d",
                pThis,
                matches,
                static_cast<unsigned long long>(matchedOffset),
                NotificationAreaIcon_QueryInterface,
                safeToCall ? 1 : 0
            );
        }
        if (safeToCall) {
            queryResult =
                static_cast<HRESULT>(
                    NotificationAreaIcon_QueryInterface(
                        queryObject,
                        *g_notificationAreaIconInterfaceId,
                        &queriedAbi
                    )
                );
        }
    }

    const UIOrderSnapshot current =
        CaptureUIOrderSnapshot();

    const unsigned int identityOccurrences =
        CountIdentity(
            current,
            windowsIdentity
        );

    const std::wstring logicalKey =
        windowsIdentity !=
                0
            ? BuildLogicalKey(
                  windowsIdentity
              )
            : L"";

    TOR_LOG(
        L"TRAY_ORDER_LOCK_LIVE_IDENTITY_CONSTRUCTED "
        L"call=%llu "
        L"implementation=%p "
        L"abi=%p "
        L"windowsIdentity=%llu "
        L"queryResult=0x%08X "
        L"uiOrderOccurrences=%u "
        L"logicalSupported=%d",
        callNumber,
        pThis,
        queriedAbi,
        static_cast<unsigned long long>(
            windowsIdentity
        ),
        static_cast<unsigned int>(
            queryResult
        ),
        identityOccurrences,
        logicalKey.empty()
            ? 0
            : 1
    );

    if (
        SUCCEEDED(
            queryResult
        ) &&
        queriedAbi &&
        windowsIdentity !=
            0
    ) {
        LiveIdentityMapping mapping;

        mapping.implementation =
            pThis;

        mapping.abi =
            queriedAbi;

        mapping.windowsIdentity =
            windowsIdentity;

        StoreLiveMapping(
            mapping
        );

        const unsigned long long mapped =
            g_liveMappingCount.fetch_add(
                1,
                std::memory_order_relaxed
            ) +
            1;

        TOR_LOG(
            L"TRAY_ORDER_LOCK_LIVE_IDENTITY_MAP "
            L"mapped=%llu "
            L"implementation=%p "
            L"abi=%p "
            L"windowsIdentity=%llu "
            L"uiOrderOccurrences=%u "
            L"logicalSupported=%d",
            mapped,
            pThis,
            queriedAbi,
            static_cast<unsigned long long>(
                windowsIdentity
            ),
            identityOccurrences,
            logicalKey.empty()
                ? 0
                : 1
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

OrderingBehavior GetOrderingBehavior() {
    return
        static_cast<OrderingBehavior>(
            g_orderingBehavior.load(
                std::memory_order_acquire
            )
        );
}

void LoadSettings() {
    PCWSTR orderingSetting =
        Wh_GetStringSetting(
            L"orderingBehavior"
        );

    OrderingBehavior behavior =
        OrderingBehavior::LockAll;

    if (
        orderingSetting &&
        _wcsicmp(
            orderingSetting,
            L"preserveManual"
        ) ==
            0
    ) {
        behavior =
            OrderingBehavior::PreserveManual;
    }

    Wh_FreeStringSetting(
        orderingSetting
    );

    PCWSTR newIconSetting =
        Wh_GetStringSetting(
            L"newIconBehavior"
        );

    NewIconBehavior newIconBehavior =
        NewIconBehavior::WindowsDefault;

    if (
        newIconSetting &&
        _wcsicmp(
            newIconSetting,
            L"placeAtEnd"
        ) ==
            0
    ) {
        newIconBehavior =
            NewIconBehavior::PlaceAtEnd;
    }

    Wh_FreeStringSetting(
        newIconSetting
    );

    g_orderingBehavior.store(
        static_cast<int>(
            behavior
        ),
        std::memory_order_release
    );

    g_newIconBehavior.store(
        static_cast<int>(
            newIconBehavior
        ),
        std::memory_order_release
    );

    TOR_LOG(
        L"TRAY_ORDER_LOCK_SETTINGS "
        L"orderingBehavior=%s "
        L"newIconBehavior=%s",
        behavior ==
                OrderingBehavior::PreserveManual
            ? L"preserveManual"
            : L"lockAll",
        newIconBehavior ==
                NewIconBehavior::PlaceAtEnd
            ? L"placeAtEnd"
            : L"windowsDefault"
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
        g_internalMoveDepth !=
        0
    ) {
        const unsigned long long forwarded =
            g_internalForwardedMoveCount.fetch_add(
                1,
                std::memory_order_relaxed
            ) +
            1;

        TOR_LOG(
            L"TRAY_ORDER_LOCK_INTERNAL_TASKBAR_MOVE_FORWARDED "
            L"move=%llu "
            L"iconAbi=%p "
            L"location=%d "
            L"index=%u",
            forwarded,
            notificationAreaIconAbi,
            location,
            index
        );

        return
            TaskbarModel_MoveNotificationAreaIcon_Original(
                pThis,
                notificationAreaIconAbi,
                location,
                index
            );
    }

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

        TOR_LOG(
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

    LiveIdentityMapping liveMapping;

    const bool liveMapped =
        LookupLiveMapping(
            notificationAreaIconAbi,
            &liveMapping
        );

    const UIOrderSnapshot before =
        CaptureUIOrderSnapshot();

    const unsigned int liveIdentityOccurrencesBefore =
        liveMapped
            ? CountIdentity(
                  before,
                  liveMapping.windowsIdentity
              )
            : 0;

    const unsigned long long moveNumber =
        g_allowedMoveCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    TOR_LOG(
        L"TRAY_ORDER_LOCK_MOVE_ALLOWED "
        L"move=%llu "
        L"iconAbi=%p "
        L"liveMapped=%d "
        L"liveWindowsIdentity=%llu "
        L"liveIdentityOccurrencesBefore=%u "
        L"location=%d "
        L"index=%u "
        L"beforeValid=%d "
        L"beforeEntries=%llu",
        moveNumber,
        notificationAreaIconAbi,
        liveMapped
            ? 1
            : 0,
        static_cast<unsigned long long>(
            liveMapped
                ? liveMapping.windowsIdentity
                : 0
        ),
        liveIdentityOccurrencesBefore,
        location,
        index,
        before.valid
            ? 1
            : 0,
        static_cast<unsigned long long>(
            before.entries.size()
        )
    );

    g_taskbarMoveDepth++;

    const int result =
        TaskbarModel_MoveNotificationAreaIcon_Original(
            pThis,
            notificationAreaIconAbi,
            location,
            index
        );

    g_taskbarMoveDepth--;

    const UIOrderSnapshot after =
        CaptureUIOrderSnapshot();

    const bool orderChanged =
        before.valid &&
        after.valid &&
        before.entries !=
            after.entries;

    TOR_LOG(
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
        orderChanged
            ? 1
            : 0
    );

    if (
        !SUCCEEDED(
            static_cast<HRESULT>(
                result
            )
        ) ||
        !orderChanged
    ) {
        return result;
    }

    std::uint64_t movedIdentity =
        0;

    const wchar_t* identitySource =
        L"unresolved";

    if (
        liveMapped &&
        liveMapping.windowsIdentity !=
            0 &&
        CountIdentity(
            after,
            liveMapping.windowsIdentity
        ) ==
            1
    ) {
        movedIdentity =
            liveMapping.windowsIdentity;

        identitySource =
            L"live-map";

        g_liveMappedMoveCount.fetch_add(
            1,
            std::memory_order_relaxed
        );
    } else {
        movedIdentity =
            FindSingleMovedIdentity(
                before,
                after
            );

        if (
            movedIdentity !=
            0
        ) {
            identitySource =
                L"registry-diff";

            g_registryFallbackMoveCount.fetch_add(
                1,
                std::memory_order_relaxed
            );
        }
    }

    TOR_LOG(
        L"TRAY_ORDER_LOCK_MANUAL_IDENTITY "
        L"move=%llu "
        L"identity=%llu "
        L"source=%s "
        L"liveMapped=%d "
        L"liveWindowsIdentity=%llu",
        moveNumber,
        static_cast<unsigned long long>(
            movedIdentity
        ),
        identitySource,
        liveMapped
            ? 1
            : 0,
        static_cast<unsigned long long>(
            liveMapped
                ? liveMapping.windowsIdentity
                : 0
        )
    );

    LearnManualMove(
        after,
        movedIdentity,
        identitySource,
        location,
        index
    );

    return result;
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

bool IsNotificationAreaIconVectorIidSymbol(
    const wchar_t* symbol
) {
    constexpr wchar_t expected[] =
        L"struct guid::guid const "
        L"winrt::impl::guid_v<struct "
        L"winrt::Windows::Foundation::Collections::"
        L"IVector<struct "
        L"winrt::WindowsUdk::UI::Shell::"
        L"NotificationAreaIcon> >";

    return
        symbol &&
        std::wcscmp(
            symbol,
            expected
        ) ==
            0;
}

bool IsNotificationAreaIconManagerMoveIconSymbol(
    const wchar_t* symbol
) {
    constexpr wchar_t expected[] =
        L"public: void __cdecl "
        L"NotificationAreaIconManager2::MoveIcon("
        L"struct winrt::WindowsUdk::UI::Shell::"
        L"NotificationAreaIcon,"
        L"enum winrt::WindowsUdk::UI::Shell::"
        L"NotificationAreaIconLocation,"
        L"unsigned int)";

    return
        symbol &&
        std::wcscmp(
            symbol,
            expected
        ) ==
            0;
}

bool ResolveLiveIdentitySymbols(
    HMODULE taskbarModule
) {
    NotificationAreaIcon2_Constructor_Target =
        nullptr;

    NotificationAreaIcon_QueryInterface =
        nullptr;

    g_queryInterfaceUsesDefaultAbi = false;

    NotificationAreaIconManager_MoveIcon =
        nullptr;

    g_notificationAreaIconInterfaceId =
        nullptr;

    g_notificationAreaIconVectorId =
        nullptr;

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

    if (
        !search
    ) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_LIVE_IDENTITY_SYMBOL_ENUMERATION_FAILED "
            L"lastError=%lu",
            GetLastError()
        );

        return false;
    }

    unsigned int constructorMatches =
        0;

    unsigned int queryInterfaceMatches =
        0;

    unsigned int defaultAbiQueryMatches = 0;
    NotificationAreaIcon_QueryInterface_t defaultAbiQuery = nullptr;

    unsigned int iidMatches =
        0;

    unsigned int vectorIidMatches =
        0;

    unsigned int managerMoveMatches =
        0;

    unsigned int icon2SymbolNames = 0;
    unsigned int queryInterfaceSymbolNames = 0;
    unsigned int qiCandidateCount = 0;

    do {
        const bool mentionsIcon2 =
            ContainsText(symbol.symbol, L"NotificationAreaIcon2");

        const bool mentionsQueryInterface =
            ContainsText(symbol.symbol, L"query_interface") ||
            ContainsText(symbol.symbol, L"QueryInterface");

        if (mentionsIcon2) {
            icon2SymbolNames++;
        }

        if (mentionsQueryInterface) {
            queryInterfaceSymbolNames++;
        }

        if (mentionsIcon2 && mentionsQueryInterface) {
            qiCandidateCount++;

            if (qiCandidateCount <= 24) {
                TOR_LOG(
                    L"TRAY_ORDER_LOCK_QI_SYMBOL_CANDIDATE "
                    L"index=%u address=%p name=\"%s\"",
                    qiCandidateCount,
                    symbol.address,
                    symbol.symbol
                );
            }
        }

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
            }
        }

        if (
            symbol.symbol &&
            std::wcscmp(
                symbol.symbol,
                LR"(public: virtual int __cdecl winrt::impl::produce_base<struct winrt::WindowsUdk::UI::Shell::implementation::NotificationAreaIcon2,struct winrt::WindowsUdk::UI::Shell::INotificationAreaIcon,void>::QueryInterface(struct winrt::guid const &,void * *))"
            ) == 0
        ) {
            defaultAbiQueryMatches++;

            if (!defaultAbiQuery) {
                defaultAbiQuery =
                    reinterpret_cast<NotificationAreaIcon_QueryInterface_t>(
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
                    reinterpret_cast<
                        const GUID*
                    >(
                        symbol.address
                    );
            }
        }

        if (
            IsNotificationAreaIconVectorIidSymbol(
                symbol.symbol
            )
        ) {
            vectorIidMatches++;

            if (
                !g_notificationAreaIconVectorId
            ) {
                g_notificationAreaIconVectorId =
                    reinterpret_cast<
                        const GUID*
                    >(
                        symbol.address
                    );
            }
        }

        if (
            IsNotificationAreaIconManagerMoveIconSymbol(
                symbol.symbol
            )
        ) {
            managerMoveMatches++;

            if (
                !NotificationAreaIconManager_MoveIcon
            ) {
                NotificationAreaIconManager_MoveIcon =
                    reinterpret_cast<
                        NotificationAreaIconManager_MoveIcon_t
                    >(
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

    TOR_LOG(
        L"TRAY_ORDER_LOCK_SYMBOL_SCAN "
        L"icon2Names=%u queryInterfaceNames=%u "
        L"qiCandidates=%u",
        icon2SymbolNames,
        queryInterfaceSymbolNames,
        qiCandidateCount
    );

    if (
        !NotificationAreaIcon_QueryInterface &&
        defaultAbiQueryMatches == 1
    ) {
        NotificationAreaIcon_QueryInterface = defaultAbiQuery;
        g_queryInterfaceUsesDefaultAbi = true;
    }

    TOR_LOG(
        L"TRAY_ORDER_LOCK_QI_SOURCE "
        L"rootMatches=%u defaultAbiMatches=%u selected=%s",
        queryInterfaceMatches,
        defaultAbiQueryMatches,
        g_queryInterfaceUsesDefaultAbi
            ? L"default-interface-abi"
            : (NotificationAreaIcon_QueryInterface
                ? L"root-implements"
                : L"unavailable")
    );

    TOR_LOG(
        L"TRAY_ORDER_LOCK_LIVE_IDENTITY_SYMBOLS "
        L"constructorMatches=%u "
        L"queryInterfaceMatches=%u "
        L"iidMatches=%u "
        L"vectorIidMatches=%u "
        L"managerMoveMatches=%u "
        L"constructor=%p "
        L"queryInterface=%p "
        L"interfaceId=%p "
        L"vectorInterfaceId=%p "
        L"managerMove=%p",
        constructorMatches,
        queryInterfaceMatches,
        iidMatches,
        vectorIidMatches,
        managerMoveMatches,
        NotificationAreaIcon2_Constructor_Target,
        NotificationAreaIcon_QueryInterface,
        g_notificationAreaIconInterfaceId,
        g_notificationAreaIconVectorId,
        NotificationAreaIconManager_MoveIcon
    );

    if (
        constructorMatches !=
            1 ||
        managerMoveMatches !=
            1 ||
        !NotificationAreaIcon2_Constructor_Target ||
        !NotificationAreaIcon_QueryInterface ||
        !NotificationAreaIconManager_MoveIcon ||
        !g_notificationAreaIconInterfaceId ||
        !g_notificationAreaIconVectorId
    ) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_LIVE_IDENTITY_SYMBOLS_UNAVAILABLE"
        );

        return false;
    }

    return true;
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
        length ==
            0 ||
        length >=
            ARRAYSIZE(
                modulePath
            )
    ) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_TASKBAR_MODULE "
            L"address=%p "
            L"path=\"<unavailable>\"",
            module
        );

        return;
    }

    TOR_LOG(
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
    if (
        !ResolveLiveIdentitySymbols(
            taskbarModule
        )
    ) {
        return false;
    }

    if (
        !WindhawkUtils::SetFunctionHook(
            NotificationAreaIcon2_Constructor_Target,
            NotificationAreaIcon2_Constructor_Hook,
            &NotificationAreaIcon2_Constructor_Original
        )
    ) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_LIVE_IDENTITY_CONSTRUCTOR_HOOK_FAILED"
        );

        return false;
    }

    WindhawkUtils::SYMBOL_HOOK
        symbolHooks[] = {
            {
                {
                    LR"(private: void __cdecl NotificationAreaIconManager2::AddIconToVisibleCollection(struct winrt::WindowsUdk::UI::Shell::implementation::NotificationAreaIcon2 *))"
                },
                &NotificationAreaIconManager_AddVisible_Original,
                NotificationAreaIconManager_AddVisible_Hook,
            },
            {
                {
                    LR"(public: virtual int __cdecl winrt::impl::produce<struct winrt::WindowsUdk::UI::Shell::implementation::TaskbarModel,struct winrt::WindowsUdk::UI::Shell::ITaskbarModel6>::get_NotificationAreaOverflowIcons(void * *))"
                },
                &TaskbarModel_GetOverflowIcons_Original,
                TaskbarModel_GetOverflowIcons_Hook,
            },
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
        TOR_LOG(
            L"TRAY_ORDER_LOCK_TASKBAR_HOOK_REGISTRATION_FAILED"
        );

        return false;
    }

    LogTaskbarModuleInformation(
        taskbarModule
    );

    TOR_LOG(
        L"TRAY_ORDER_LOCK_LIVE_IDENTITY_HOOK_REGISTERED "
        L"constructor=%p "
        L"automaticRestore=1",
        NotificationAreaIcon2_Constructor_Target
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

std::size_t GetLiveMappingSize() {
    std::lock_guard<std::mutex> lock(
        g_liveMappingMutex
    );

    return
        g_liveMappings.size();
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

    const std::size_t liveMappings =
        GetLiveMappingSize();

    if (
        GetOrderingBehavior() ==
        OrderingBehavior::PreserveManual
    ) {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_READY "
            L"processId=%lu "
            L"taskbarHooksInitialized=%d "
            L"orderingBehavior=preserveManual "
            L"canonicalEntries=%llu "
            L"canonicalLoadedFromStorage=%d "
            L"liveMappings=%llu",
            GetCurrentProcessId(),
            g_taskbarHooksInitialized.load(
                std::memory_order_acquire
            )
                ? 1
                : 0,
            static_cast<unsigned long long>(
                canonicalEntries
            ),
            loadedFromStorage
                ? 1
                : 0,
            static_cast<unsigned long long>(
                liveMappings
            )
        );
    } else {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_READY "
            L"processId=%lu "
            L"taskbarHooksInitialized=%d "
            L"orderingBehavior=lockAll "
            L"canonicalEntries=%llu "
            L"canonicalLoadedFromStorage=%d "
            L"liveMappings=%llu",
            GetCurrentProcessId(),
            g_taskbarHooksInitialized.load(
                std::memory_order_acquire
            )
                ? 1
                : 0,
            static_cast<unsigned long long>(
                canonicalEntries
            ),
            loadedFromStorage
                ? 1
                : 0,
            static_cast<unsigned long long>(
                liveMappings
            )
        );
    }
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
        TOR_LOG(
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
            TOR_LOG(
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
        TOR_LOG(
            L"TRAY_ORDER_LOCK_TASKBAR_HOOKS_READY "
            L"processId=%lu "
            L"applyImmediately=1 "
            L"liveIdentityMapping=1",
            GetCurrentProcessId()
        );
    } else {
        TOR_LOG(
            L"TRAY_ORDER_LOCK_TASKBAR_HOOKS_REGISTERED "
            L"processId=%lu "
            L"applyImmediately=0 "
            L"liveIdentityMapping=1",
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

    TOR_LOG(
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
    TOR_LOG(
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

    g_liveConstructorCount.store(
        0,
        std::memory_order_release
    );

    g_liveMappingCount.store(
        0,
        std::memory_order_release
    );

    g_liveMappedMoveCount.store(
        0,
        std::memory_order_release
    );

    g_registryFallbackMoveCount.store(
        0,
        std::memory_order_release
    );

    g_visibleAddCount.store(
        0,
        std::memory_order_release
    );

    g_overflowGetterCount.store(
        0,
        std::memory_order_release
    );

    g_restoreObservationCount.store(
        0,
        std::memory_order_release
    );

    g_restoreKnownCandidateCount.store(
        0,
        std::memory_order_release
    );

    g_restoreNewIconCount.store(
        0,
        std::memory_order_release
    );

    g_restoreSkipCount.store(
        0,
        std::memory_order_release
    );

    g_restoreMoveAttemptCount.store(
        0,
        std::memory_order_release
    );

    g_restoreMoveObservedCount.store(
        0,
        std::memory_order_release
    );

    g_restoreMoveVerifiedCount.store(
        0,
        std::memory_order_release
    );

    g_internalForwardedMoveCount.store(
        0,
        std::memory_order_release
    );

    g_restoreSuppressedTaskbarMoveCount.store(
        0,
        std::memory_order_release
    );

    {
        std::lock_guard<std::mutex> lock(
            g_liveMappingMutex
        );

        g_liveMappings.clear();
    }

    {
        std::lock_guard<std::mutex> lock(g_restoreRetryMutex);
        g_restoreRetryIdentities.clear();
    }

    LoadSettings();

    InitializeCanonicalState();

    if (
        !WindhawkUtils::SetFunctionHook(
            CreateWindowExW,
            CreateWindowExW_Hook,
            &CreateWindowExW_Original
        )
    ) {
        TOR_LOG(
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
        TOR_LOG(
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
        TOR_LOG(
            L"TRAY_ORDER_LOCK_TASKBAR_HOOKS_DEFERRED "
            L"processId=%lu "
            L"reason=\"Shell_TrayWnd-not-created-yet\"",
            GetCurrentProcessId()
        );
    }

    TOR_LOG(
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
    ReleaseCachedTaskbarModel6();

    std::size_t canonicalEntries =
        0;

    {
        std::lock_guard<std::mutex> lock(
            g_canonicalMutex
        );

        canonicalEntries =
            g_canonicalOrder.size();
    }

    const std::size_t liveMappings =
        GetLiveMappingSize();

    TOR_LOG(
        L"Tray Order Lock stopped; "
        L"processId=%lu "
        L"blockedMoves=%llu "
        L"allowedMoves=%llu "
        L"learnedMoves=%llu "
        L"skippedLearning=%llu "
        L"liveConstructors=%llu "
        L"liveMappingsObserved=%llu "
        L"liveMappingsStored=%llu "
        L"liveMappedMoves=%llu "
        L"registryFallbackMoves=%llu "
        L"restoreMoveAttempts=%llu "
        L"restoreMovesObserved=%llu "
        L"restoreMovesVerified=%llu "
        L"internalForwardedMoves=%llu "
        L"restoreSuppressedTaskbarMoves=%llu "
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
        g_liveConstructorCount.load(
            std::memory_order_relaxed
        ),
        g_liveMappingCount.load(
            std::memory_order_relaxed
        ),
        static_cast<unsigned long long>(
            liveMappings
        ),
        g_liveMappedMoveCount.load(
            std::memory_order_relaxed
        ),
        g_registryFallbackMoveCount.load(
            std::memory_order_relaxed
        ),
        g_restoreMoveAttemptCount.load(
            std::memory_order_relaxed
        ),
        g_restoreMoveObservedCount.load(
            std::memory_order_relaxed
        ),
        g_restoreMoveVerifiedCount.load(
            std::memory_order_relaxed
        ),
        g_internalForwardedMoveCount.load(
            std::memory_order_relaxed
        ),
        g_restoreSuppressedTaskbarMoveCount.load(
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

    ClosePersistentDevelopmentLog();
}
