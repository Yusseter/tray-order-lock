// ==WindhawkMod==
// @id              system-tray-index-analyzer
// @name            System Tray Index Analyzer
// @description     Logs tray order additions, removals, reorders and their likely source.
// @version         0.8.0
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
# System Tray Index Analyzer

A read-only diagnostic mod for researching automatic Windows 11 notification
area reordering.

Version 0.8.0:

- Allows tray icon move requests to continue normally.
- Records every `ITaskbarModel5::MoveNotificationAreaIcon` request.
- Watches `NotifyIconSettings\UIOrderList`.
- Detects IDs added to or removed from the order.
- Detects pure reorder operations.
- Logs registry identity information for affected entries.
- Normalizes versioned WindowsApps paths into a stable package family.
- Correlates registry changes with recent move requests.

The mod does not block moves, modify `UIOrderList`, or write to the registry.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <windhawk_utils.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

constexpr wchar_t kNotifyIconSettingsPath[] =
    L"Control Panel\\NotifyIconSettings";

constexpr wchar_t kUIOrderListValueName[] =
    L"UIOrderList";

constexpr ULONGLONG kMoveCorrelationWindowMs =
    1500;

std::atomic<bool> g_taskbarModuleHooked =
    false;

std::atomic<unsigned long long> g_moveRequestCount =
    0;

std::atomic<unsigned long long> g_registryChangeCount =
    0;

std::atomic<unsigned long long> g_lastMoveSequence =
    0;

std::atomic<ULONGLONG> g_lastMoveTick =
    0;

HANDLE g_registryStopEvent =
    nullptr;

HANDLE g_registryChangeEvent =
    nullptr;

HANDLE g_registryThread =
    nullptr;

HKEY g_registryKey =
    nullptr;

struct OrderSnapshot {
    LONG status =
        ERROR_SUCCESS;

    std::vector<std::uint64_t> order;

    bool valid =
        false;
};

struct EntryMetadata {
    bool keyExists =
        false;

    std::wstring executablePath;
    std::wstring stableFamily;
    std::wstring iconGuid;
    std::wstring initialTooltip;
    std::wstring publisher;

    bool hasUid =
        false;

    std::uint64_t uid =
        0;
};

std::mutex g_snapshotMutex;

OrderSnapshot g_lastSnapshot;

using TaskbarModel_MoveNotificationAreaIcon_t =
    int(__cdecl*)(
        void* pThis,
        void* notificationAreaIconAbi,
        int location,
        unsigned int index
    );

TaskbarModel_MoveNotificationAreaIcon_t
    TaskbarModel_MoveNotificationAreaIcon_Original =
        nullptr;

std::wstring ToLowerInvariant(
    std::wstring value
) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](wchar_t character) {
            return
                static_cast<wchar_t>(
                    std::towlower(character)
                );
        }
    );

    return value;
}

std::wstring EscapeLogText(
    const std::wstring& value
) {
    std::wstring escaped;

    escaped.reserve(
        value.size()
    );

    for (wchar_t character : value) {
        switch (character) {
            case L'\\':
                escaped +=
                    L"\\\\";
                break;

            case L'"':
                escaped +=
                    L"\\\"";
                break;

            case L'\r':
                escaped +=
                    L"\\r";
                break;

            case L'\n':
                escaped +=
                    L"\\n";
                break;

            case L'\t':
                escaped +=
                    L"\\t";
                break;

            default:
                escaped +=
                    character;
                break;
        }
    }

    constexpr std::size_t kMaximumLength =
        512;

    if (
        escaped.size() >
        kMaximumLength
    ) {
        escaped.resize(
            kMaximumLength
        );

        escaped +=
            L"...";
    }

    return escaped;
}

bool ReadRegistryString(
    HKEY key,
    const wchar_t* valueName,
    std::wstring& value
) {
    value.clear();

    DWORD type =
        REG_NONE;

    DWORD requiredBytes =
        0;

    LONG status =
        RegQueryValueExW(
            key,
            valueName,
            nullptr,
            &type,
            nullptr,
            &requiredBytes
        );

    if (
        status != ERROR_SUCCESS ||
        (
            type != REG_SZ &&
            type != REG_EXPAND_SZ
        )
    ) {
        return false;
    }

    if (
        requiredBytes == 0
    ) {
        return true;
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
        RegQueryValueExW(
            key,
            valueName,
            nullptr,
            &type,
            reinterpret_cast<BYTE*>(
                buffer.data()
            ),
            &actualBytes
        );

    if (
        status != ERROR_SUCCESS
    ) {
        return false;
    }

    buffer.back() =
        L'\0';

    value.assign(
        buffer.data()
    );

    return true;
}

bool ReadRegistryInteger(
    HKEY key,
    const wchar_t* valueName,
    std::uint64_t& value
) {
    value =
        0;

    DWORD type =
        REG_NONE;

    BYTE data[
        sizeof(std::uint64_t)
    ]{};

    DWORD dataSize =
        sizeof(data);

    LONG status =
        RegQueryValueExW(
            key,
            valueName,
            nullptr,
            &type,
            data,
            &dataSize
        );

    if (
        status != ERROR_SUCCESS
    ) {
        return false;
    }

    if (
        type == REG_DWORD &&
        dataSize == sizeof(DWORD)
    ) {
        DWORD dwordValue =
            0;

        std::memcpy(
            &dwordValue,
            data,
            sizeof(dwordValue)
        );

        value =
            dwordValue;

        return true;
    }

    if (
        type == REG_QWORD &&
        dataSize == sizeof(std::uint64_t)
    ) {
        std::memcpy(
            &value,
            data,
            sizeof(value)
        );

        return true;
    }

    return false;
}

std::wstring BuildStableFamily(
    const std::wstring& executablePath
) {
    std::wstring normalizedPath =
        ToLowerInvariant(
            executablePath
        );

    std::replace(
        normalizedPath.begin(),
        normalizedPath.end(),
        L'/',
        L'\\'
    );

    constexpr wchar_t kWindowsAppsMarker[] =
        L"\\windowsapps\\";

    const std::size_t markerPosition =
        normalizedPath.find(
            kWindowsAppsMarker
        );

    if (
        markerPosition ==
        std::wstring::npos
    ) {
        return normalizedPath;
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
        std::wstring::npos
    ) {
        return normalizedPath;
    }

    const std::wstring packageDirectory =
        normalizedPath.substr(
            packageStart,
            packageEnd -
                packageStart
        );

    const std::wstring relativePath =
        normalizedPath.substr(
            packageEnd +
            1
        );

    const std::size_t publisherSeparator =
        packageDirectory.rfind(
            L'_'
        );

    if (
        publisherSeparator ==
        std::wstring::npos ||
        publisherSeparator == 0
    ) {
        return normalizedPath;
    }

    const std::size_t resourceSeparator =
        packageDirectory.rfind(
            L'_',
            publisherSeparator -
                1
        );

    if (
        resourceSeparator ==
        std::wstring::npos ||
        resourceSeparator == 0
    ) {
        return normalizedPath;
    }

    const std::size_t architectureSeparator =
        packageDirectory.rfind(
            L'_',
            resourceSeparator -
                1
        );

    if (
        architectureSeparator ==
        std::wstring::npos ||
        architectureSeparator == 0
    ) {
        return normalizedPath;
    }

    const std::size_t versionSeparator =
        packageDirectory.rfind(
            L'_',
            architectureSeparator -
                1
        );

    if (
        versionSeparator ==
        std::wstring::npos ||
        versionSeparator == 0
    ) {
        return normalizedPath;
    }

    const std::wstring packageName =
        packageDirectory.substr(
            0,
            versionSeparator
        );

    const std::wstring publisherId =
        packageDirectory.substr(
            publisherSeparator +
            1
        );

    return
        packageName +
        L"|" +
        publisherId +
        L"|" +
        relativePath;
}

EntryMetadata QueryEntryMetadata(
    std::uint64_t identifier
) {
    EntryMetadata metadata;

    const std::wstring subKeyPath =
        std::wstring(
            kNotifyIconSettingsPath
        ) +
        L"\\" +
        std::to_wstring(
            identifier
        );

    HKEY key =
        nullptr;

    const LONG openStatus =
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subKeyPath.c_str(),
            0,
            KEY_QUERY_VALUE,
            &key
        );

    if (
        openStatus != ERROR_SUCCESS
    ) {
        return metadata;
    }

    metadata.keyExists =
        true;

    ReadRegistryString(
        key,
        L"ExecutablePath",
        metadata.executablePath
    );

    ReadRegistryString(
        key,
        L"IconGuid",
        metadata.iconGuid
    );

    ReadRegistryString(
        key,
        L"InitialTooltip",
        metadata.initialTooltip
    );

    ReadRegistryString(
        key,
        L"Publisher",
        metadata.publisher
    );

    metadata.hasUid =
        ReadRegistryInteger(
            key,
            L"UID",
            metadata.uid
        );

    RegCloseKey(
        key
    );

    metadata.stableFamily =
        BuildStableFamily(
            metadata.executablePath
        );

    return metadata;
}

OrderSnapshot CaptureOrderSnapshot() {
    OrderSnapshot snapshot;

    for (
        int attempt = 0;
        attempt < 3;
        attempt++
    ) {
        DWORD type =
            REG_NONE;

        DWORD requiredBytes =
            0;

        LONG status =
            RegGetValueW(
                HKEY_CURRENT_USER,
                kNotifyIconSettingsPath,
                kUIOrderListValueName,
                RRF_RT_REG_BINARY,
                &type,
                nullptr,
                &requiredBytes
            );

        if (
            status != ERROR_SUCCESS
        ) {
            snapshot.status =
                status;

            return snapshot;
        }

        if (
            requiredBytes %
                sizeof(std::uint64_t) !=
            0
        ) {
            snapshot.status =
                ERROR_INVALID_DATA;

            return snapshot;
        }

        std::vector<BYTE> rawData(
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
                &type,
                rawData.empty()
                    ? nullptr
                    : rawData.data(),
                &actualBytes
            );

        if (
            status == ERROR_MORE_DATA
        ) {
            continue;
        }

        if (
            status != ERROR_SUCCESS
        ) {
            snapshot.status =
                status;

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

        rawData.resize(
            actualBytes
        );

        const std::size_t entryCount =
            actualBytes /
            sizeof(std::uint64_t);

        snapshot.order.resize(
            entryCount
        );

        if (
            actualBytes > 0
        ) {
            std::memcpy(
                snapshot.order.data(),
                rawData.data(),
                actualBytes
            );
        }

        snapshot.status =
            ERROR_SUCCESS;

        snapshot.valid =
            true;

        return snapshot;
    }

    snapshot.status =
        ERROR_MORE_DATA;

    return snapshot;
}

std::size_t FindPosition(
    const std::vector<std::uint64_t>& order,
    std::uint64_t identifier
) {
    const auto iterator =
        std::find(
            order.begin(),
            order.end(),
            identifier
        );

    if (
        iterator ==
        order.end()
    ) {
        return 0;
    }

    return
        static_cast<std::size_t>(
            std::distance(
                order.begin(),
                iterator
            )
        ) +
        1;
}

void LogEntryMetadata(
    const wchar_t* eventType,
    std::uint64_t identifier,
    std::size_t position
) {
    const EntryMetadata metadata =
        QueryEntryMetadata(
            identifier
        );

    Wh_Log(
        L"TRAY_ENTRY "
        L"event=%s "
        L"id=%llu "
        L"position=%llu "
        L"keyExists=%d "
        L"hasGuid=%d "
        L"guid=\"%s\" "
        L"hasUid=%d "
        L"uid=%llu "
        L"stableFamily=\"%s\" "
        L"path=\"%s\" "
        L"tooltip=\"%s\" "
        L"publisher=\"%s\"",
        eventType,
        static_cast<unsigned long long>(
            identifier
        ),
        static_cast<unsigned long long>(
            position
        ),
        metadata.keyExists
            ? 1
            : 0,
        metadata.iconGuid.empty()
            ? 0
            : 1,
        EscapeLogText(
            metadata.iconGuid
        ).c_str(),
        metadata.hasUid
            ? 1
            : 0,
        static_cast<unsigned long long>(
            metadata.uid
        ),
        EscapeLogText(
            metadata.stableFamily
        ).c_str(),
        EscapeLogText(
            metadata.executablePath
        ).c_str(),
        EscapeLogText(
            metadata.initialTooltip
        ).c_str(),
        EscapeLogText(
            metadata.publisher
        ).c_str()
    );
}

bool LogOrderDifference(
    const wchar_t* source,
    unsigned long long correlation,
    const OrderSnapshot& before,
    const OrderSnapshot& after
) {
    if (
        !before.valid ||
        !after.valid
    ) {
        Wh_Log(
            L"ORDER_DIFF_FAILED "
            L"source=%s "
            L"correlation=%llu "
            L"beforeValid=%d "
            L"beforeStatus=%ld "
            L"afterValid=%d "
            L"afterStatus=%ld",
            source,
            correlation,
            before.valid
                ? 1
                : 0,
            before.status,
            after.valid
                ? 1
                : 0,
            after.status
        );

        return false;
    }

    if (
        before.order ==
        after.order
    ) {
        return false;
    }

    const std::unordered_set<std::uint64_t>
        beforeIdentifiers(
            before.order.begin(),
            before.order.end()
        );

    const std::unordered_set<std::uint64_t>
        afterIdentifiers(
            after.order.begin(),
            after.order.end()
        );

    std::vector<std::uint64_t> added;

    std::vector<std::uint64_t> removed;

    for (
        std::uint64_t identifier :
        after.order
    ) {
        if (
            beforeIdentifiers.find(
                identifier
            ) ==
            beforeIdentifiers.end()
        ) {
            added.push_back(
                identifier
            );
        }
    }

    for (
        std::uint64_t identifier :
        before.order
    ) {
        if (
            afterIdentifiers.find(
                identifier
            ) ==
            afterIdentifiers.end()
        ) {
            removed.push_back(
                identifier
            );
        }
    }

    const bool pureReorder =
        added.empty() &&
        removed.empty();

    Wh_Log(
        L"ORDER_CHANGED "
        L"source=%s "
        L"correlation=%llu "
        L"beforeCount=%llu "
        L"afterCount=%llu "
        L"added=%llu "
        L"removed=%llu "
        L"pureReorder=%d",
        source,
        correlation,
        static_cast<unsigned long long>(
            before.order.size()
        ),
        static_cast<unsigned long long>(
            after.order.size()
        ),
        static_cast<unsigned long long>(
            added.size()
        ),
        static_cast<unsigned long long>(
            removed.size()
        ),
        pureReorder
            ? 1
            : 0
    );

    for (
        std::uint64_t identifier :
        added
    ) {
        LogEntryMetadata(
            L"added",
            identifier,
            FindPosition(
                after.order,
                identifier
            )
        );
    }

    for (
        std::uint64_t identifier :
        removed
    ) {
        LogEntryMetadata(
            L"removed",
            identifier,
            FindPosition(
                before.order,
                identifier
            )
        );
    }

    if (
        pureReorder
    ) {
        constexpr std::size_t kMaximumChangedEntries =
            24;

        std::size_t loggedEntries =
            0;

        for (
            std::size_t oldIndex = 0;
            oldIndex < before.order.size();
            oldIndex++
        ) {
            const std::uint64_t identifier =
                before.order[
                    oldIndex
                ];

            const std::size_t newPosition =
                FindPosition(
                    after.order,
                    identifier
                );

            const std::size_t oldPosition =
                oldIndex +
                1;

            if (
                newPosition == 0 ||
                newPosition == oldPosition
            ) {
                continue;
            }

            Wh_Log(
                L"ORDER_POSITION_CHANGED "
                L"source=%s "
                L"correlation=%llu "
                L"id=%llu "
                L"oldPosition=%llu "
                L"newPosition=%llu",
                source,
                correlation,
                static_cast<unsigned long long>(
                    identifier
                ),
                static_cast<unsigned long long>(
                    oldPosition
                ),
                static_cast<unsigned long long>(
                    newPosition
                )
            );

            loggedEntries++;

            if (
                loggedEntries >=
                kMaximumChangedEntries
            ) {
                Wh_Log(
                    L"ORDER_POSITION_CHANGED_TRUNCATED "
                    L"source=%s "
                    L"correlation=%llu "
                    L"limit=%llu",
                    source,
                    correlation,
                    static_cast<unsigned long long>(
                        kMaximumChangedEntries
                    )
                );

                break;
            }
        }
    }

    return true;
}

void SetSharedSnapshot(
    const OrderSnapshot& snapshot
) {
    if (
        !snapshot.valid
    ) {
        return;
    }

    std::lock_guard<std::mutex> lock(
        g_snapshotMutex
    );

    g_lastSnapshot =
        snapshot;
}

OrderSnapshot GetSharedSnapshot() {
    std::lock_guard<std::mutex> lock(
        g_snapshotMutex
    );

    return g_lastSnapshot;
}

void HandleRegistryChange() {
    const unsigned long long changeNumber =
        g_registryChangeCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    Sleep(
        35
    );

    const OrderSnapshot before =
        GetSharedSnapshot();

    const OrderSnapshot after =
        CaptureOrderSnapshot();

    const ULONGLONG currentTick =
        GetTickCount64();

    const ULONGLONG lastMoveTick =
        g_lastMoveTick.load(
            std::memory_order_acquire
        );

    const unsigned long long
        lastMoveSequence =
            g_lastMoveSequence.load(
                std::memory_order_acquire
            );

    const bool moveCorrelated =
        lastMoveTick != 0 &&
        currentTick >= lastMoveTick &&
        currentTick - lastMoveTick <=
            kMoveCorrelationWindowMs;

    LogOrderDifference(
        moveCorrelated
            ? L"registry-after-move"
            : L"registry-without-move",
        moveCorrelated
            ? lastMoveSequence
            : changeNumber,
        before,
        after
    );

    SetSharedSnapshot(
        after
    );
}

DWORD WINAPI RegistryWatcherThread(
    void*
) {
    Wh_Log(
        L"UIOrderList registry watcher started"
    );

    while (true) {
        const LONG notifyStatus =
            RegNotifyChangeKeyValue(
                g_registryKey,
                TRUE,
                REG_NOTIFY_CHANGE_NAME |
                    REG_NOTIFY_CHANGE_LAST_SET,
                g_registryChangeEvent,
                TRUE
            );

        if (
            notifyStatus != ERROR_SUCCESS
        ) {
            Wh_Log(
                L"RegNotifyChangeKeyValue failed; "
                L"status=%ld",
                notifyStatus
            );

            break;
        }

        HANDLE handles[] = {
            g_registryStopEvent,
            g_registryChangeEvent,
        };

        const DWORD waitResult =
            WaitForMultipleObjects(
                ARRAYSIZE(
                    handles
                ),
                handles,
                FALSE,
                INFINITE
            );

        if (
            waitResult ==
            WAIT_OBJECT_0
        ) {
            break;
        }

        if (
            waitResult ==
            WAIT_OBJECT_0 + 1
        ) {
            HandleRegistryChange();
            continue;
        }

        Wh_Log(
            L"Registry watcher wait failed; "
            L"result=%lu",
            waitResult
        );

        break;
    }

    Wh_Log(
        L"UIOrderList registry watcher stopped"
    );

    return 0;
}

bool StartRegistryWatcher() {
    const LONG openStatus =
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            kNotifyIconSettingsPath,
            0,
            KEY_NOTIFY |
                KEY_QUERY_VALUE,
            &g_registryKey
        );

    if (
        openStatus != ERROR_SUCCESS
    ) {
        Wh_Log(
            L"Failed to open NotifyIconSettings; "
            L"status=%ld",
            openStatus
        );

        return false;
    }

    const OrderSnapshot initialSnapshot =
        CaptureOrderSnapshot();

    if (
        !initialSnapshot.valid
    ) {
        Wh_Log(
            L"Failed to capture initial UIOrderList; "
            L"status=%ld",
            initialSnapshot.status
        );

        RegCloseKey(
            g_registryKey
        );

        g_registryKey =
            nullptr;

        return false;
    }

    SetSharedSnapshot(
        initialSnapshot
    );

    Wh_Log(
        L"INITIAL_ORDER "
        L"entries=%llu "
        L"firstId=%llu "
        L"lastId=%llu",
        static_cast<unsigned long long>(
            initialSnapshot.order.size()
        ),
        initialSnapshot.order.empty()
            ? 0ULL
            : static_cast<unsigned long long>(
                  initialSnapshot.order.front()
              ),
        initialSnapshot.order.empty()
            ? 0ULL
            : static_cast<unsigned long long>(
                  initialSnapshot.order.back()
              )
    );

    g_registryStopEvent =
        CreateEventW(
            nullptr,
            TRUE,
            FALSE,
            nullptr
        );

    g_registryChangeEvent =
        CreateEventW(
            nullptr,
            FALSE,
            FALSE,
            nullptr
        );

    if (
        !g_registryStopEvent ||
        !g_registryChangeEvent
    ) {
        Wh_Log(
            L"Failed to create registry watcher events; "
            L"error=%lu",
            GetLastError()
        );

        return false;
    }

    g_registryThread =
        CreateThread(
            nullptr,
            0,
            RegistryWatcherThread,
            nullptr,
            0,
            nullptr
        );

    if (
        !g_registryThread
    ) {
        Wh_Log(
            L"Failed to create registry watcher thread; "
            L"error=%lu",
            GetLastError()
        );

        return false;
    }

    return true;
}

void StopRegistryWatcher() {
    if (
        g_registryStopEvent
    ) {
        SetEvent(
            g_registryStopEvent
        );
    }

    if (
        g_registryThread
    ) {
        WaitForSingleObject(
            g_registryThread,
            5000
        );

        CloseHandle(
            g_registryThread
        );

        g_registryThread =
            nullptr;
    }

    if (
        g_registryChangeEvent
    ) {
        CloseHandle(
            g_registryChangeEvent
        );

        g_registryChangeEvent =
            nullptr;
    }

    if (
        g_registryStopEvent
    ) {
        CloseHandle(
            g_registryStopEvent
        );

        g_registryStopEvent =
            nullptr;
    }

    if (
        g_registryKey
    ) {
        RegCloseKey(
            g_registryKey
        );

        g_registryKey =
            nullptr;
    }
}

int __cdecl
TaskbarModel_MoveNotificationAreaIcon_Hook(
    void* pThis,
    void* notificationAreaIconAbi,
    int location,
    unsigned int index
) {
    const unsigned long long sequence =
        g_moveRequestCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    const DWORD threadId =
        GetCurrentThreadId();

    const OrderSnapshot before =
        CaptureOrderSnapshot();

    g_lastMoveSequence.store(
        sequence,
        std::memory_order_release
    );

    g_lastMoveTick.store(
        GetTickCount64(),
        std::memory_order_release
    );

    Wh_Log(
        L"MOVE_REQUEST "
        L"sequence=%llu "
        L"thread=%lu "
        L"this=%p "
        L"icon=%p "
        L"location=%d "
        L"index=%u",
        sequence,
        threadId,
        pThis,
        notificationAreaIconAbi,
        location,
        index
    );

    const int result =
        TaskbarModel_MoveNotificationAreaIcon_Original(
            pThis,
            notificationAreaIconAbi,
            location,
            index
        );

    const OrderSnapshot after =
        CaptureOrderSnapshot();

    Wh_Log(
        L"MOVE_RETURN "
        L"sequence=%llu "
        L"result=0x%08X",
        sequence,
        static_cast<unsigned int>(
            result
        )
    );

    LogOrderDifference(
        L"move-return",
        sequence,
        before,
        after
    );

    SetSharedSnapshot(
        after
    );

    return result;
}

void LogTaskbarModuleInformation(
    HMODULE module
) {
    wchar_t modulePath[
        MAX_PATH
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
            L"taskbar.dll module=%p; "
            L"path unavailable",
            module
        );

        return;
    }

    Wh_Log(
        L"taskbar.dll module=%p; "
        L"path=\"%s\"",
        module,
        modulePath
    );
}

bool HookTaskbarSymbols(
    HMODULE module
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
            module,
            symbolHooks,
            ARRAYSIZE(
                symbolHooks
            )
        )
    ) {
        Wh_Log(
            L"Failed to locate or hook "
            L"ITaskbarModel5::"
            L"MoveNotificationAreaIcon"
        );

        return false;
    }

    LogTaskbarModuleInformation(
        module
    );

    Wh_Log(
        L"Tray move observation hook installed"
    );

    return true;
}

HMODULE GetTaskbarModuleHandle() {
    return
        GetModuleHandleW(
            L"taskbar.dll"
        );
}

bool TryHookTaskbarModule(
    HMODULE module,
    bool applyHookOperations
) {
    if (
        !module
    ) {
        return false;
    }

    if (
        g_taskbarModuleHooked.load(
            std::memory_order_acquire
        )
    ) {
        return true;
    }

    bool expected =
        false;

    if (
        !g_taskbarModuleHooked
             .compare_exchange_strong(
                 expected,
                 true,
                 std::memory_order_acq_rel
             )
    ) {
        return true;
    }

    if (
        !HookTaskbarSymbols(
            module
        )
    ) {
        g_taskbarModuleHooked.store(
            false,
            std::memory_order_release
        );

        return false;
    }

    if (
        applyHookOperations
    ) {
        Wh_ApplyHookOperations();
    }

    return true;
}

void HandleLoadedModule(
    HMODULE module,
    LPCWSTR requestedPath
) {
    if (
        !module ||
        g_taskbarModuleHooked.load(
            std::memory_order_acquire
        )
    ) {
        return;
    }

    HMODULE taskbarModule =
        GetTaskbarModuleHandle();

    if (
        !taskbarModule ||
        taskbarModule != module
    ) {
        return;
    }

    Wh_Log(
        L"Detected taskbar.dll load; "
        L"requestedPath=\"%s\"",
        requestedPath
            ? requestedPath
            : L"<null>"
    );

    TryHookTaskbarModule(
        module,
        true
    );
}

using LoadLibraryExW_t =
    decltype(
        &LoadLibraryExW
    );

LoadLibraryExW_t LoadLibraryExW_Original =
    nullptr;

HMODULE WINAPI LoadLibraryExW_Hook(
    LPCWSTR libraryPath,
    HANDLE file,
    DWORD flags
) {
    HMODULE module =
        LoadLibraryExW_Original(
            libraryPath,
            file,
            flags
        );

    if (
        module
    ) {
        HandleLoadedModule(
            module,
            libraryPath
        );
    }

    return module;
}

bool HookModuleLoader() {
    HMODULE kernelBase =
        GetModuleHandleW(
            L"kernelbase.dll"
        );

    if (
        !kernelBase
    ) {
        Wh_Log(
            L"kernelbase.dll is unavailable"
        );

        return false;
    }

    auto loadLibraryExW =
        reinterpret_cast<
            LoadLibraryExW_t
        >(
            GetProcAddress(
                kernelBase,
                "LoadLibraryExW"
            )
        );

    if (
        !loadLibraryExW
    ) {
        Wh_Log(
            L"LoadLibraryExW is unavailable"
        );

        return false;
    }

    if (
        !WindhawkUtils::Wh_SetFunctionHookT(
            loadLibraryExW,
            LoadLibraryExW_Hook,
            &LoadLibraryExW_Original
        )
    ) {
        Wh_Log(
            L"Failed to hook LoadLibraryExW"
        );

        return false;
    }

    Wh_Log(
        L"taskbar.dll is not loaded yet; "
        L"waiting for module load"
    );

    return true;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"System Tray Index Analyzer "
        L"0.8.0 initializing"
    );

    g_taskbarModuleHooked.store(
        false,
        std::memory_order_release
    );

    g_moveRequestCount.store(
        0,
        std::memory_order_release
    );

    g_registryChangeCount.store(
        0,
        std::memory_order_release
    );

    g_lastMoveSequence.store(
        0,
        std::memory_order_release
    );

    g_lastMoveTick.store(
        0,
        std::memory_order_release
    );

    if (
        !StartRegistryWatcher()
    ) {
        StopRegistryWatcher();

        return FALSE;
    }

    HMODULE taskbarModule =
        GetTaskbarModuleHandle();

    if (
        taskbarModule
    ) {
        if (
            TryHookTaskbarModule(
                taskbarModule,
                false
            )
        ) {
            return TRUE;
        }

        StopRegistryWatcher();

        return FALSE;
    }

    if (
        HookModuleLoader()
    ) {
        return TRUE;
    }

    StopRegistryWatcher();

    return FALSE;
}

void Wh_ModAfterInit() {
    if (
        g_taskbarModuleHooked.load(
            std::memory_order_acquire
        )
    ) {
        return;
    }

    HMODULE taskbarModule =
        GetTaskbarModuleHandle();

    if (
        taskbarModule
    ) {
        TryHookTaskbarModule(
            taskbarModule,
            true
        );
    }
}

void Wh_ModUninit() {
    StopRegistryWatcher();

    Wh_Log(
        L"System Tray Index Analyzer stopped; "
        L"moveRequests=%llu "
        L"registryChanges=%llu",
        g_moveRequestCount.load(
            std::memory_order_relaxed
        ),
        g_registryChangeCount.load(
            std::memory_order_relaxed
        )
    );
}
