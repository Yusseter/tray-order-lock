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
    L"0.2.0-dev-order-drift-restore-guard";

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

std::mutex g_liveMappingMutex;

std::vector<LiveIdentityMapping> g_liveMappings;

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

    TOR_LOG(
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

    MergeLiveKeysLocked(
        logicalAfter
    );

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
        RecordLearningSkip(
            L"canonical-neighbor-not-found",
            movedIdentity,
            identitySource
        );

        return;
    }

    const bool persisted =
        PersistCanonicalOrderLocked();

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

    if (persisted) {
        *persisted =
            writeSucceeded;
    }

    return true;
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

    if (persisted) {
        *persisted =
            writeSucceeded;
    }

    return true;
}

bool AdoptNewIconFromUiOrder(
    const std::wstring& targetKey,
    std::uint64_t windowsIdentity,
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

    const std::vector<std::wstring> canonical =
        GetCanonicalOrderSnapshot();

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

    if (persisted) {
        *persisted =
            writeSucceeded;
    }

    return true;
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

void RestoreCanonicalRelation(
    void* manager,
    void* iconImplementation
) {
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

    LiveIdentityMapping targetMapping;

    if (
        !LookupLiveMappingByImplementation(
            iconImplementation,
            &targetMapping
        )
    ) {
        RecordRestoreObservationSkip(
            L"target-live-map-not-found",
            0
        );

        return;
    }

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

    const std::vector<std::wstring> canonical =
        GetCanonicalOrderSnapshot();

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
        queryResult =
            static_cast<HRESULT>(
                NotificationAreaIcon_QueryInterface(
                    pThis,
                    *g_notificationAreaIconInterfaceId,
                    &queriedAbi
                )
            );
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

    unsigned int iidMatches =
        0;

    unsigned int vectorIidMatches =
        0;

    unsigned int managerMoveMatches =
        0;

    do {
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
