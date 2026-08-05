// ==WindhawkMod==
// @id              system-tray-index-analyzer
// @name            System Tray Index Analyzer
// @description     Tests whether suppressing one ITaskbarModel5::MoveNotificationAreaIcon request prevents a visible tray reorder.
// @version         0.6.0
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

A temporary diagnostic mod for researching Windows 11 notification-area icon
ordering.

Version 0.6.0 performs a single controlled behavior test:

- It hooks the ABI-facing `ITaskbarModel5::MoveNotificationAreaIcon` producer in
  `taskbar.dll` using the exact public symbol recovered from Microsoft symbols.
- The first move request after the mod is loaded returns `S_OK` without calling
  the original producer, so the lower `NotificationAreaIconManager2::MoveIcon`
  function is never entered.
- Every later move request is passed through unchanged.
- `NtSetValueKey` is still observed for exact `UIOrderList` writes, but no
  registry write is suppressed in this version.

The test determines whether suppressing the move request above `MoveIcon` stops
both the live collection update and the persistent `UIOrderList` update.

The mod also records:

- Move requests, arguments, and whether the request was suppressed
- Exact `UIOrderList` write attempts and read-only before/after snapshots
- Read-only last-set notifications for `NotifyIconSettings`
- `StackViewModel::UpdateIconIndexes` calls and read-only before/after snapshots
- Correlation counters for moves, writes, notifications, and index updates

This is an experimental diagnostic version. It intentionally suppresses the
first `ITaskbarModel5::MoveNotificationAreaIcon` request after the mod is loaded.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <winternl.h>
#include <windhawk_utils.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <string>
#include <vector>

namespace {

constexpr wchar_t kNotifyIconSettingsPath[] =
    L"Control Panel\\NotifyIconSettings";

constexpr wchar_t kNotifyIconSettingsSuffix[] =
    L"\\Control Panel\\NotifyIconSettings";

constexpr wchar_t kUIOrderListValueName[] =
    L"UIOrderList";

constexpr std::uint64_t kFnv1aOffsetBasis =
    14695981039346656037ULL;

constexpr std::uint64_t kFnv1aPrime =
    1099511628211ULL;

constexpr ULONG kKeyNameInformationClass =
    3;

std::atomic<bool> g_taskbarModuleHooked =
    false;

std::atomic<bool> g_systemTrayModuleHooked =
    false;

std::atomic<bool> g_firstMoveRequestSuppressed =
    false;

std::atomic<unsigned long long>
    g_moveRequestCallCount =
        0;

std::atomic<unsigned long long>
    g_moveRequestSuppressedCount =
        0;

std::atomic<unsigned long long>
    g_updateCallCount =
        0;

std::atomic<unsigned long long>
    g_registryNotificationCount =
        0;

std::atomic<unsigned long long>
    g_uiOrderWriteAttemptCount =
        0;

HANDLE g_registryWatcherStopEvent =
    nullptr;

HANDLE g_registryWatcherChangeEvent =
    nullptr;

HANDLE g_registryWatcherThread =
    nullptr;

HKEY g_registryWatcherKey =
    nullptr;

thread_local bool
    g_insideNtSetValueKeyHook =
        false;

struct UIOrderSnapshot {
    LONG status =
        ERROR_SUCCESS;

    DWORD registryType =
        REG_NONE;

    DWORD byteLength =
        0;

    unsigned long long entryCount =
        0;

    bool lengthAligned =
        false;

    std::uint64_t hash =
        0;

    bool valid =
        false;
};

struct NativeKeyNameInformation {
    ULONG nameLength;
    WCHAR name[1];
};

class NtSetValueKeyHookGuard {
public:
    explicit NtSetValueKeyHookGuard(
        bool& insideFlag
    )
        : insideFlag_(
              insideFlag
          ) {
        insideFlag_ =
            true;
    }

    ~NtSetValueKeyHookGuard() {
        insideFlag_ =
            false;
    }

    NtSetValueKeyHookGuard(
        const NtSetValueKeyHookGuard&
    ) = delete;

    NtSetValueKeyHookGuard& operator=(
        const NtSetValueKeyHookGuard&
    ) = delete;

private:
    bool& insideFlag_;
};

using TaskbarModel_MoveNotificationAreaIcon_t =
    int(__cdecl*)(
        void* pThis,
        void* notificationAreaIconAbi,
        int location,
        unsigned int index
    );

using StackViewModel_UpdateIconIndexes_t =
    void(WINAPI*)(
        void* pThis
    );

using NtSetValueKey_t =
    NTSTATUS(NTAPI*)(
        HANDLE keyHandle,
        PUNICODE_STRING valueName,
        ULONG titleIndex,
        ULONG type,
        PVOID data,
        ULONG dataSize
    );

using NtQueryKey_t =
    NTSTATUS(NTAPI*)(
        HANDLE keyHandle,
        ULONG keyInformationClass,
        PVOID keyInformation,
        ULONG length,
        PULONG resultLength
    );

TaskbarModel_MoveNotificationAreaIcon_t
    TaskbarModel_MoveNotificationAreaIcon_Original =
        nullptr;

StackViewModel_UpdateIconIndexes_t
    StackViewModel_UpdateIconIndexes_Original =
        nullptr;

NtSetValueKey_t
    NtSetValueKey_Original =
        nullptr;

NtQueryKey_t
    NtQueryKey_Function =
        nullptr;

std::uint64_t CalculateFnv1aHash(
    const BYTE* data,
    DWORD length
) {
    std::uint64_t hash =
        kFnv1aOffsetBasis;

    for (
        DWORD index = 0;
        index < length;
        index++
    ) {
        hash ^=
            data[index];

        hash *=
            kFnv1aPrime;
    }

    return hash;
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

        if (
            status !=
            ERROR_SUCCESS
        ) {
            snapshot.status =
                status;

            snapshot.registryType =
                registryType;

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

        snapshot.registryType =
            registryType;

        if (
            status !=
            ERROR_SUCCESS
        ) {
            return snapshot;
        }

        data.resize(
            actualBytes
        );

        snapshot.byteLength =
            actualBytes;

        snapshot.entryCount =
            actualBytes /
            sizeof(
                std::uint64_t
            );

        snapshot.lengthAligned =
            actualBytes %
                sizeof(
                    std::uint64_t
                ) ==
            0;

        snapshot.hash =
            CalculateFnv1aHash(
                data.empty()
                    ? nullptr
                    : data.data(),
                actualBytes
            );

        snapshot.valid =
            true;

        return snapshot;
    }

    snapshot.status =
        ERROR_MORE_DATA;

    return snapshot;
}

bool AreSnapshotsEqual(
    const UIOrderSnapshot& first,
    const UIOrderSnapshot& second
) {
    return
        first.valid &&
        second.valid &&
        first.registryType ==
            second.registryType &&
        first.byteLength ==
            second.byteLength &&
        first.hash ==
            second.hash;
}

void LogUIOrderSnapshot(
    const wchar_t* phase,
    const wchar_t* source,
    unsigned long long callNumber,
    const UIOrderSnapshot& snapshot
) {
    Wh_Log(
        L"UIORDER_SNAPSHOT "
        L"phase=%s "
        L"source=%s "
        L"call=%llu "
        L"valid=%d "
        L"status=%ld "
        L"type=%lu "
        L"bytes=%lu "
        L"entries=%llu "
        L"aligned=%d "
        L"hash=0x%016llX",
        phase,
        source,
        callNumber,
        snapshot.valid
            ? 1
            : 0,
        snapshot.status,
        snapshot.registryType,
        snapshot.byteLength,
        snapshot.entryCount,
        snapshot.lengthAligned
            ? 1
            : 0,
        static_cast<
            unsigned long long
        >(
            snapshot.hash
        )
    );
}

bool IsUIOrderListValueName(
    const UNICODE_STRING* valueName
) {
    if (
        !valueName ||
        !valueName->Buffer ||
        valueName->Length %
                sizeof(
                    wchar_t
                ) !=
            0
    ) {
        return false;
    }

    const int valueNameLength =
        static_cast<int>(
            valueName->Length /
            sizeof(
                wchar_t
            )
        );

    return
        CompareStringOrdinal(
            valueName->Buffer,
            valueNameLength,
            kUIOrderListValueName,
            ARRAYSIZE(
                kUIOrderListValueName
            ) - 1,
            TRUE
        ) ==
        CSTR_EQUAL;
}

bool EndsWithOrdinalIgnoreCase(
    const std::wstring& value,
    const wchar_t* suffix
) {
    const int suffixLength =
        static_cast<int>(
            std::wcslen(
                suffix
            )
        );

    if (
        value.size() <
        static_cast<
            std::size_t
        >(
            suffixLength
        )
    ) {
        return false;
    }

    const wchar_t* valueSuffix =
        value.data() +
        value.size() -
        suffixLength;

    return
        CompareStringOrdinal(
            valueSuffix,
            suffixLength,
            suffix,
            suffixLength,
            TRUE
        ) ==
        CSTR_EQUAL;
}

bool QueryNativeRegistryKeyPath(
    HANDLE keyHandle,
    std::wstring& keyPath,
    NTSTATUS& queryStatus
) {
    keyPath.clear();

    queryStatus =
        static_cast<NTSTATUS>(
            0xC0000001L
        );

    if (
        !NtQueryKey_Function ||
        !keyHandle
    ) {
        return false;
    }

    ULONG requiredLength =
        0;

    queryStatus =
        NtQueryKey_Function(
            keyHandle,
            kKeyNameInformationClass,
            nullptr,
            0,
            &requiredLength
        );

    if (
        requiredLength <
        sizeof(
            ULONG
        )
    ) {
        return false;
    }

    std::vector<BYTE> buffer(
        static_cast<
            std::size_t
        >(
            requiredLength
        ) +
        sizeof(
            wchar_t
        )
    );

    queryStatus =
        NtQueryKey_Function(
            keyHandle,
            kKeyNameInformationClass,
            buffer.data(),
            requiredLength,
            &requiredLength
        );

    if (
        queryStatus <
        0
    ) {
        return false;
    }

    const auto* information =
        reinterpret_cast<
            const NativeKeyNameInformation*
        >(
            buffer.data()
        );

    if (
        information->nameLength %
                sizeof(
                    wchar_t
                ) !=
            0 ||
        information->nameLength >
            requiredLength -
                sizeof(
                    ULONG
                )
    ) {
        return false;
    }

    keyPath.assign(
        information->name,
        information->nameLength /
            sizeof(
                wchar_t
            )
    );

    return true;
}

NTSTATUS NTAPI NtSetValueKey_Hook(
    HANDLE keyHandle,
    PUNICODE_STRING valueName,
    ULONG titleIndex,
    ULONG type,
    PVOID data,
    ULONG dataSize
) {
    if (
        g_insideNtSetValueKeyHook ||
        !IsUIOrderListValueName(
            valueName
        )
    ) {
        return
            NtSetValueKey_Original(
                keyHandle,
                valueName,
                titleIndex,
                type,
                data,
                dataSize
            );
    }

    NtSetValueKeyHookGuard
        hookGuard(
            g_insideNtSetValueKeyHook
        );

    std::wstring keyPath;

    NTSTATUS keyQueryStatus =
        0;

    const bool keyPathResolved =
        QueryNativeRegistryKeyPath(
            keyHandle,
            keyPath,
            keyQueryStatus
        );

    const bool exactTarget =
        keyPathResolved &&
        type ==
            REG_BINARY &&
        EndsWithOrdinalIgnoreCase(
            keyPath,
            kNotifyIconSettingsSuffix
        );

    if (
        !exactTarget
    ) {
        if (
            !keyPathResolved
        ) {
            Wh_Log(
                L"UIORDER_WRITE_PASSTHROUGH "
                L"reason=key-unresolved "
                L"keyQueryStatus=0x%08lX "
                L"type=%lu "
                L"bytes=%lu",
                static_cast<ULONG>(
                    keyQueryStatus
                ),
                type,
                dataSize
            );
        }

        return
            NtSetValueKey_Original(
                keyHandle,
                valueName,
                titleIndex,
                type,
                data,
                dataSize
            );
    }

    const unsigned long long
        attemptNumber =
            g_uiOrderWriteAttemptCount
                .fetch_add(
                    1,
                    std::memory_order_relaxed
                ) +
            1;

    const DWORD threadId =
        GetCurrentThreadId();

    const unsigned long long
        moveRequestsBefore =
            g_moveRequestCallCount
                .load(
                    std::memory_order_acquire
                );

    const unsigned long long
        suppressedMoveRequestsBefore =
            g_moveRequestSuppressedCount
                .load(
                    std::memory_order_acquire
                );

    const unsigned long long
        updateCallsBefore =
            g_updateCallCount
                .load(
                    std::memory_order_acquire
                );

    const UIOrderSnapshot
        beforeSnapshot =
            CaptureUIOrderSnapshot();

    Wh_Log(
        L"UIORDER_WRITE_BEGIN "
        L"attempt=%llu "
        L"thread=%lu "
        L"key=\"%s\" "
        L"value=\"UIOrderList\" "
        L"type=%lu "
        L"bytes=%lu "
        L"moveRequestsObserved=%llu "
        L"suppressedMoveRequestsObserved=%llu "
        L"updateCallsObserved=%llu "
        L"beforeValid=%d "
        L"beforeBytes=%lu "
        L"beforeHash=0x%016llX",
        attemptNumber,
        threadId,
        keyPath.c_str(),
        type,
        dataSize,
        moveRequestsBefore,
        suppressedMoveRequestsBefore,
        updateCallsBefore,
        beforeSnapshot.valid
            ? 1
            : 0,
        beforeSnapshot.byteLength,
        static_cast<
            unsigned long long
        >(
            beforeSnapshot.hash
        )
    );

    const NTSTATUS status =
        NtSetValueKey_Original(
            keyHandle,
            valueName,
            titleIndex,
            type,
            data,
            dataSize
        );

    const UIOrderSnapshot
        afterSnapshot =
            CaptureUIOrderSnapshot();

    const int comparable =
        beforeSnapshot.valid &&
        afterSnapshot.valid
            ? 1
            : 0;

    const int changed =
        comparable &&
        !AreSnapshotsEqual(
            beforeSnapshot,
            afterSnapshot
        )
            ? 1
            : 0;

    Wh_Log(
        L"UIORDER_WRITE_END "
        L"attempt=%llu "
        L"thread=%lu "
        L"ntstatus=0x%08lX "
        L"comparable=%d "
        L"changed=%d "
        L"afterValid=%d "
        L"afterBytes=%lu "
        L"afterHash=0x%016llX "
        L"moveRequestsBefore=%llu "
        L"moveRequestsAfter=%llu "
        L"suppressedMoveRequestsBefore=%llu "
        L"suppressedMoveRequestsAfter=%llu "
        L"updateCallsBefore=%llu "
        L"updateCallsAfter=%llu",
        attemptNumber,
        threadId,
        static_cast<ULONG>(
            status
        ),
        comparable,
        changed,
        afterSnapshot.valid
            ? 1
            : 0,
        afterSnapshot.byteLength,
        static_cast<
            unsigned long long
        >(
            afterSnapshot.hash
        ),
        moveRequestsBefore,
        g_moveRequestCallCount
            .load(
                std::memory_order_acquire
            ),
        suppressedMoveRequestsBefore,
        g_moveRequestSuppressedCount
            .load(
                std::memory_order_acquire
            ),
        updateCallsBefore,
        g_updateCallCount
            .load(
                std::memory_order_acquire
            )
    );

    return status;
}

bool HookNativeRegistryWrites() {
    HMODULE ntdll =
        GetModuleHandleW(
            L"ntdll.dll"
        );

    if (
        !ntdll
    ) {
        Wh_Log(
            L"ntdll.dll is unavailable"
        );

        return false;
    }

    auto ntSetValueKey =
        reinterpret_cast<
            NtSetValueKey_t
        >(
            GetProcAddress(
                ntdll,
                "NtSetValueKey"
            )
        );

    NtQueryKey_Function =
        reinterpret_cast<
            NtQueryKey_t
        >(
            GetProcAddress(
                ntdll,
                "NtQueryKey"
            )
        );

    if (
        !ntSetValueKey ||
        !NtQueryKey_Function
    ) {
        Wh_Log(
            L"NtSetValueKey or NtQueryKey "
            L"is unavailable"
        );

        return false;
    }

    if (
        !WindhawkUtils::
            Wh_SetFunctionHookT(
                ntSetValueKey,
                NtSetValueKey_Hook,
                &NtSetValueKey_Original
            )
    ) {
        Wh_Log(
            L"Failed to hook NtSetValueKey"
        );

        return false;
    }

    Wh_Log(
        L"NtSetValueKey hook installed; "
        L"UIOrderList writes are observation-only"
    );

    return true;
}

void LogUIOrderRegistryWatcherSnapshot(
    const wchar_t* phase,
    unsigned long long notificationNumber,
    const UIOrderSnapshot* previousSnapshot,
    const UIOrderSnapshot& currentSnapshot
) {
    const int comparable =
        previousSnapshot &&
        previousSnapshot->valid &&
        currentSnapshot.valid
            ? 1
            : 0;

    const int changedFromPrevious =
        comparable &&
        !AreSnapshotsEqual(
            *previousSnapshot,
            currentSnapshot
        )
            ? 1
            : 0;

    const unsigned long long
        previousHash =
            previousSnapshot
                ? static_cast<
                      unsigned long long
                  >(
                      previousSnapshot->hash
                  )
                : 0;

    Wh_Log(
        L"UIORDER_WATCH "
        L"phase=%s "
        L"notification=%llu "
        L"moveRequestsObserved=%llu "
        L"suppressedMoveRequestsObserved=%llu "
        L"updateCallsObserved=%llu "
        L"writeAttemptsObserved=%llu "
        L"valid=%d "
        L"status=%ld "
        L"type=%lu "
        L"bytes=%lu "
        L"entries=%llu "
        L"aligned=%d "
        L"hash=0x%016llX "
        L"comparable=%d "
        L"changedFromPrevious=%d "
        L"previousHash=0x%016llX",
        phase,
        notificationNumber,
        g_moveRequestCallCount
            .load(
                std::memory_order_acquire
            ),
        g_moveRequestSuppressedCount
            .load(
                std::memory_order_acquire
            ),
        g_updateCallCount
            .load(
                std::memory_order_acquire
            ),
        g_uiOrderWriteAttemptCount
            .load(
                std::memory_order_acquire
            ),
        currentSnapshot.valid
            ? 1
            : 0,
        currentSnapshot.status,
        currentSnapshot.registryType,
        currentSnapshot.byteLength,
        currentSnapshot.entryCount,
        currentSnapshot.lengthAligned
            ? 1
            : 0,
        static_cast<
            unsigned long long
        >(
            currentSnapshot.hash
        ),
        comparable,
        changedFromPrevious,
        previousHash
    );
}

LONG ArmUIOrderRegistryNotification() {
    return
        RegNotifyChangeKeyValue(
            g_registryWatcherKey,
            FALSE,
            REG_NOTIFY_CHANGE_LAST_SET,
            g_registryWatcherChangeEvent,
            TRUE
        );
}

DWORD WINAPI
UIOrderRegistryWatcherThreadProc(
    LPVOID
) {
    Wh_Log(
        L"UIOrderList registry watcher "
        L"started; thread=%lu",
        GetCurrentThreadId()
    );

    LONG notifyStatus =
        ArmUIOrderRegistryNotification();

    if (
        notifyStatus !=
        ERROR_SUCCESS
    ) {
        Wh_Log(
            L"Initial registry notification "
            L"registration failed; status=%ld",
            notifyStatus
        );

        return 0;
    }

    UIOrderSnapshot previousSnapshot =
        CaptureUIOrderSnapshot();

    LogUIOrderRegistryWatcherSnapshot(
        L"baseline",
        0,
        nullptr,
        previousSnapshot
    );

    HANDLE waitHandles[] = {
        g_registryWatcherStopEvent,
        g_registryWatcherChangeEvent,
    };

    for (;;) {
        const DWORD waitResult =
            WaitForMultipleObjects(
                ARRAYSIZE(
                    waitHandles
                ),
                waitHandles,
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
            notifyStatus =
                ArmUIOrderRegistryNotification();

            if (
                notifyStatus !=
                ERROR_SUCCESS
            ) {
                Wh_Log(
                    L"Registry notification "
                    L"re-registration failed; "
                    L"status=%ld",
                    notifyStatus
                );

                break;
            }

            UIOrderSnapshot
                currentSnapshot =
                    CaptureUIOrderSnapshot();

            const unsigned long long
                notificationNumber =
                    g_registryNotificationCount
                        .fetch_add(
                            1,
                            std::memory_order_relaxed
                        ) +
                    1;

            LogUIOrderRegistryWatcherSnapshot(
                L"change",
                notificationNumber,
                &previousSnapshot,
                currentSnapshot
            );

            previousSnapshot =
                currentSnapshot;

            continue;
        }

        if (
            waitResult ==
            WAIT_FAILED
        ) {
            Wh_Log(
                L"Registry watcher wait failed; "
                L"error=%lu",
                GetLastError()
            );
        }
        else {
            Wh_Log(
                L"Registry watcher received "
                L"unexpected wait result=%lu",
                waitResult
            );
        }

        break;
    }

    Wh_Log(
        L"UIOrderList registry watcher "
        L"stopped; thread=%lu "
        L"notifications=%llu",
        GetCurrentThreadId(),
        g_registryNotificationCount
            .load(
                std::memory_order_relaxed
            )
    );

    return 0;
}

bool StartUIOrderRegistryWatcher() {
    if (
        g_registryWatcherThread
    ) {
        return true;
    }

    LONG openStatus =
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            kNotifyIconSettingsPath,
            0,
            KEY_NOTIFY,
            &g_registryWatcherKey
        );

    if (
        openStatus !=
        ERROR_SUCCESS
    ) {
        Wh_Log(
            L"Failed to open NotifyIconSettings "
            L"for notifications; status=%ld",
            openStatus
        );

        return false;
    }

    g_registryWatcherStopEvent =
        CreateEventW(
            nullptr,
            TRUE,
            FALSE,
            nullptr
        );

    if (
        !g_registryWatcherStopEvent
    ) {
        const DWORD error =
            GetLastError();

        RegCloseKey(
            g_registryWatcherKey
        );

        g_registryWatcherKey =
            nullptr;

        Wh_Log(
            L"Failed to create registry watcher "
            L"stop event; error=%lu",
            error
        );

        return false;
    }

    g_registryWatcherChangeEvent =
        CreateEventW(
            nullptr,
            FALSE,
            FALSE,
            nullptr
        );

    if (
        !g_registryWatcherChangeEvent
    ) {
        const DWORD error =
            GetLastError();

        CloseHandle(
            g_registryWatcherStopEvent
        );

        g_registryWatcherStopEvent =
            nullptr;

        RegCloseKey(
            g_registryWatcherKey
        );

        g_registryWatcherKey =
            nullptr;

        Wh_Log(
            L"Failed to create registry watcher "
            L"change event; error=%lu",
            error
        );

        return false;
    }

    g_registryWatcherThread =
        CreateThread(
            nullptr,
            0,
            UIOrderRegistryWatcherThreadProc,
            nullptr,
            0,
            nullptr
        );

    if (
        !g_registryWatcherThread
    ) {
        const DWORD error =
            GetLastError();

        CloseHandle(
            g_registryWatcherChangeEvent
        );

        g_registryWatcherChangeEvent =
            nullptr;

        CloseHandle(
            g_registryWatcherStopEvent
        );

        g_registryWatcherStopEvent =
            nullptr;

        RegCloseKey(
            g_registryWatcherKey
        );

        g_registryWatcherKey =
            nullptr;

        Wh_Log(
            L"Failed to create registry watcher "
            L"thread; error=%lu",
            error
        );

        return false;
    }

    return true;
}

void StopUIOrderRegistryWatcher() {
    if (
        g_registryWatcherStopEvent
    ) {
        SetEvent(
            g_registryWatcherStopEvent
        );
    }

    if (
        g_registryWatcherThread
    ) {
        const DWORD waitResult =
            WaitForSingleObject(
                g_registryWatcherThread,
                INFINITE
            );

        if (
            waitResult !=
            WAIT_OBJECT_0
        ) {
            Wh_Log(
                L"Waiting for registry watcher "
                L"failed; result=%lu error=%lu",
                waitResult,
                GetLastError()
            );
        }

        CloseHandle(
            g_registryWatcherThread
        );

        g_registryWatcherThread =
            nullptr;
    }

    if (
        g_registryWatcherKey
    ) {
        RegCloseKey(
            g_registryWatcherKey
        );

        g_registryWatcherKey =
            nullptr;
    }

    if (
        g_registryWatcherChangeEvent
    ) {
        CloseHandle(
            g_registryWatcherChangeEvent
        );

        g_registryWatcherChangeEvent =
            nullptr;
    }

    if (
        g_registryWatcherStopEvent
    ) {
        CloseHandle(
            g_registryWatcherStopEvent
        );

        g_registryWatcherStopEvent =
            nullptr;
    }

    Wh_Log(
        L"UIOrderList registry watcher "
        L"cleanup complete"
    );
}

void LogModuleInformation(
    const wchar_t* role,
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
            L"%s module=%p path unavailable",
            role,
            module
        );

        return;
    }

    Wh_Log(
        L"%s module=%p path=\"%s\"",
        role,
        module,
        modulePath
    );
}

int __cdecl
TaskbarModel_MoveNotificationAreaIcon_Hook(
    void* pThis,
    void* notificationAreaIconAbi,
    int location,
    unsigned int index
) {
    const unsigned long long
        callNumber =
            g_moveRequestCallCount
                .fetch_add(
                    1,
                    std::memory_order_relaxed
                ) +
            1;

    bool expected =
        false;

    const bool suppressCall =
        g_firstMoveRequestSuppressed
            .compare_exchange_strong(
                expected,
                true,
                std::memory_order_acq_rel
            );

    if (
        suppressCall
    ) {
        g_moveRequestSuppressedCount
            .fetch_add(
                1,
                std::memory_order_relaxed
            );
    }

    const DWORD threadId =
        GetCurrentThreadId();

    const unsigned long long
        writesBefore =
            g_uiOrderWriteAttemptCount
                .load(
                    std::memory_order_acquire
                );

    const unsigned long long
        notificationsBefore =
            g_registryNotificationCount
                .load(
                    std::memory_order_acquire
                );

    const unsigned long long
        updatesBefore =
            g_updateCallCount
                .load(
                    std::memory_order_acquire
                );

    const UIOrderSnapshot
        beforeSnapshot =
            CaptureUIOrderSnapshot();

    Wh_Log(
        L"MOVE_REQUEST_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"this=%p "
        L"iconAbi=%p "
        L"location=%d "
        L"index=%u "
        L"suppress=%d "
        L"writeAttemptsObserved=%llu "
        L"registryNotificationsObserved=%llu "
        L"updateCallsObserved=%llu "
        L"beforeValid=%d "
        L"beforeBytes=%lu "
        L"beforeHash=0x%016llX",
        callNumber,
        threadId,
        pThis,
        notificationAreaIconAbi,
        location,
        index,
        suppressCall
            ? 1
            : 0,
        writesBefore,
        notificationsBefore,
        updatesBefore,
        beforeSnapshot.valid
            ? 1
            : 0,
        beforeSnapshot.byteLength,
        static_cast<
            unsigned long long
        >(
            beforeSnapshot.hash
        )
    );

    int result =
        0;

    if (
        suppressCall
    ) {
        Wh_Log(
            L"MOVE_REQUEST_SUPPRESSED "
            L"call=%llu "
            L"thread=%lu "
            L"this=%p "
            L"iconAbi=%p "
            L"location=%d "
            L"index=%u "
            L"returnedHresult=0x00000000",
            callNumber,
            threadId,
            pThis,
            notificationAreaIconAbi,
            location,
            index
        );
    }
    else {
        result =
            TaskbarModel_MoveNotificationAreaIcon_Original(
                pThis,
                notificationAreaIconAbi,
                location,
                index
            );
    }

    const UIOrderSnapshot
        afterSnapshot =
            CaptureUIOrderSnapshot();

    const int comparable =
        beforeSnapshot.valid &&
        afterSnapshot.valid
            ? 1
            : 0;

    const int changed =
        comparable &&
        !AreSnapshotsEqual(
            beforeSnapshot,
            afterSnapshot
        )
            ? 1
            : 0;

    Wh_Log(
        L"MOVE_REQUEST_END "
        L"call=%llu "
        L"thread=%lu "
        L"suppressed=%d "
        L"hresult=0x%08lX "
        L"comparable=%d "
        L"changed=%d "
        L"afterValid=%d "
        L"afterBytes=%lu "
        L"afterHash=0x%016llX "
        L"writeAttemptsBefore=%llu "
        L"writeAttemptsAfter=%llu "
        L"registryNotificationsBefore=%llu "
        L"registryNotificationsAfter=%llu "
        L"updateCallsBefore=%llu "
        L"updateCallsAfter=%llu",
        callNumber,
        threadId,
        suppressCall
            ? 1
            : 0,
        static_cast<ULONG>(
            result
        ),
        comparable,
        changed,
        afterSnapshot.valid
            ? 1
            : 0,
        afterSnapshot.byteLength,
        static_cast<
            unsigned long long
        >(
            afterSnapshot.hash
        ),
        writesBefore,
        g_uiOrderWriteAttemptCount
            .load(
                std::memory_order_acquire
            ),
        notificationsBefore,
        g_registryNotificationCount
            .load(
                std::memory_order_acquire
            ),
        updatesBefore,
        g_updateCallCount
            .load(
                std::memory_order_acquire
            )
    );

    return result;
}

void WINAPI
StackViewModel_UpdateIconIndexes_Hook(
    void* pThis
) {
    const unsigned long long
        callNumber =
            g_updateCallCount
                .fetch_add(
                    1,
                    std::memory_order_relaxed
                ) +
            1;

    const DWORD threadId =
        GetCurrentThreadId();

    Wh_Log(
        L"INDEX_UPDATE_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"this=%p "
        L"moveRequestsObserved=%llu "
        L"suppressedMoveRequestsObserved=%llu "
        L"writeAttemptsObserved=%llu",
        callNumber,
        threadId,
        pThis,
        g_moveRequestCallCount
            .load(
                std::memory_order_acquire
            ),
        g_moveRequestSuppressedCount
            .load(
                std::memory_order_acquire
            ),
        g_uiOrderWriteAttemptCount
            .load(
                std::memory_order_acquire
            )
    );

    const UIOrderSnapshot
        beforeSnapshot =
            CaptureUIOrderSnapshot();

    LogUIOrderSnapshot(
        L"before",
        L"index-update",
        callNumber,
        beforeSnapshot
    );

    StackViewModel_UpdateIconIndexes_Original(
        pThis
    );

    const UIOrderSnapshot
        afterSnapshot =
            CaptureUIOrderSnapshot();

    LogUIOrderSnapshot(
        L"after",
        L"index-update",
        callNumber,
        afterSnapshot
    );

    const int comparable =
        beforeSnapshot.valid &&
        afterSnapshot.valid
            ? 1
            : 0;

    const int changed =
        comparable &&
        !AreSnapshotsEqual(
            beforeSnapshot,
            afterSnapshot
        )
            ? 1
            : 0;

    Wh_Log(
        L"UIORDER_COMPARE "
        L"source=index-update "
        L"call=%llu "
        L"comparable=%d "
        L"changed=%d "
        L"beforeBytes=%lu "
        L"afterBytes=%lu "
        L"beforeHash=0x%016llX "
        L"afterHash=0x%016llX",
        callNumber,
        comparable,
        changed,
        beforeSnapshot.byteLength,
        afterSnapshot.byteLength,
        static_cast<
            unsigned long long
        >(
            beforeSnapshot.hash
        ),
        static_cast<
            unsigned long long
        >(
            afterSnapshot.hash
        )
    );

    Wh_Log(
        L"INDEX_UPDATE_END "
        L"call=%llu "
        L"thread=%lu "
        L"this=%p "
        L"moveRequestsObserved=%llu "
        L"suppressedMoveRequestsObserved=%llu "
        L"writeAttemptsObserved=%llu",
        callNumber,
        threadId,
        pThis,
        g_moveRequestCallCount
            .load(
                std::memory_order_acquire
            ),
        g_moveRequestSuppressedCount
            .load(
                std::memory_order_acquire
            ),
        g_uiOrderWriteAttemptCount
            .load(
                std::memory_order_acquire
            )
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

    LogModuleInformation(
        L"Taskbar",
        module
    );

    Wh_Log(
        L"ITaskbarModel5::"
        L"MoveNotificationAreaIcon "
        L"hook installed; "
        L"one-shot suppression armed"
    );

    return true;
}

bool HookSystemTraySymbols(
    HMODULE module
) {
    WindhawkUtils::SYMBOL_HOOK
        symbolHooks[] = {
            {
                {
                    LR"(private: void __cdecl winrt::SystemTray::implementation::StackViewModel::UpdateIconIndexes(void))"
                },
                &StackViewModel_UpdateIconIndexes_Original,
                StackViewModel_UpdateIconIndexes_Hook,
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
            L"StackViewModel::"
            L"UpdateIconIndexes"
        );

        return false;
    }

    LogModuleInformation(
        L"System tray",
        module
    );

    Wh_Log(
        L"StackViewModel::"
        L"UpdateIconIndexes "
        L"hook installed"
    );

    return true;
}

HMODULE GetTaskbarModuleHandle() {
    return
        GetModuleHandleW(
            L"taskbar.dll"
        );
}

HMODULE GetSystemTrayModuleHandle() {
    HMODULE module =
        GetModuleHandleW(
            L"SystemTray.dll"
        );

    if (
        module
    ) {
        return module;
    }

    return
        GetModuleHandleW(
            L"Taskbar.View.dll"
        );
}

bool TryHookTaskbarModule(
    HMODULE module,
    bool applyHooks
) {
    if (
        !module ||
        g_taskbarModuleHooked
            .load(
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
        g_taskbarModuleHooked
            .store(
                false,
                std::memory_order_release
            );

        return false;
    }

    if (
        applyHooks
    ) {
        Wh_ApplyHookOperations();
    }

    return true;
}

bool TryHookSystemTrayModule(
    HMODULE module,
    bool applyHooks
) {
    if (
        !module ||
        g_systemTrayModuleHooked
            .load(
                std::memory_order_acquire
            )
    ) {
        return true;
    }

    bool expected =
        false;

    if (
        !g_systemTrayModuleHooked
             .compare_exchange_strong(
                 expected,
                 true,
                 std::memory_order_acq_rel
             )
    ) {
        return true;
    }

    if (
        !HookSystemTraySymbols(
            module
        )
    ) {
        g_systemTrayModuleHooked
            .store(
                false,
                std::memory_order_release
            );

        return false;
    }

    if (
        applyHooks
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
        !module
    ) {
        return;
    }

    bool installedAnyHook =
        false;

    HMODULE taskbarModule =
        GetTaskbarModuleHandle();

    if (
        taskbarModule ==
            module &&
        !g_taskbarModuleHooked
             .load(
                 std::memory_order_acquire
             )
    ) {
        Wh_Log(
            L"Detected taskbar module load: "
            L"requestedPath=\"%s\"",
            requestedPath
                ? requestedPath
                : L"<null>"
        );

        if (
            TryHookTaskbarModule(
                module,
                false
            )
        ) {
            installedAnyHook =
                true;
        }
    }

    HMODULE systemTrayModule =
        GetSystemTrayModuleHandle();

    if (
        systemTrayModule ==
            module &&
        !g_systemTrayModuleHooked
             .load(
                 std::memory_order_acquire
             )
    ) {
        Wh_Log(
            L"Detected system tray module load: "
            L"requestedPath=\"%s\"",
            requestedPath
                ? requestedPath
                : L"<null>"
        );

        if (
            TryHookSystemTrayModule(
                module,
                false
            )
        ) {
            installedAnyHook =
                true;
        }
    }

    if (
        installedAnyHook
    ) {
        Wh_ApplyHookOperations();
    }
}

using LoadLibraryExW_t =
    decltype(
        &LoadLibraryExW
    );

LoadLibraryExW_t
    LoadLibraryExW_Original =
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
        !WindhawkUtils::
            Wh_SetFunctionHookT(
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
        L"Module loader hook installed"
    );

    return true;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"System Tray Index Analyzer "
        L"0.6.0 initializing; "
        L"one-shot move-request "
        L"suppression armed"
    );

    g_taskbarModuleHooked
        .store(
            false,
            std::memory_order_release
        );

    g_systemTrayModuleHooked
        .store(
            false,
            std::memory_order_release
        );

    g_firstMoveRequestSuppressed
        .store(
            false,
            std::memory_order_release
        );

    g_moveRequestCallCount
        .store(
            0,
            std::memory_order_release
        );

    g_moveRequestSuppressedCount
        .store(
            0,
            std::memory_order_release
        );

    g_updateCallCount
        .store(
            0,
            std::memory_order_release
        );

    g_registryNotificationCount
        .store(
            0,
            std::memory_order_release
        );

    g_uiOrderWriteAttemptCount
        .store(
            0,
            std::memory_order_release
        );

    if (
        !HookNativeRegistryWrites()
    ) {
        return FALSE;
    }

    if (
        !StartUIOrderRegistryWatcher()
    ) {
        return FALSE;
    }

    HMODULE taskbarModule =
        GetTaskbarModuleHandle();

    HMODULE systemTrayModule =
        GetSystemTrayModuleHandle();

    if (
        taskbarModule &&
        !TryHookTaskbarModule(
            taskbarModule,
            false
        )
    ) {
        StopUIOrderRegistryWatcher();

        return FALSE;
    }

    if (
        systemTrayModule &&
        !TryHookSystemTrayModule(
            systemTrayModule,
            false
        )
    ) {
        StopUIOrderRegistryWatcher();

        return FALSE;
    }

    if (
        !taskbarModule ||
        !systemTrayModule
    ) {
        Wh_Log(
            L"One or more tray modules "
            L"are not loaded yet; "
            L"waiting for module load"
        );

        if (
            !HookModuleLoader()
        ) {
            StopUIOrderRegistryWatcher();

            return FALSE;
        }
    }

    return TRUE;
}

void Wh_ModAfterInit() {
    bool installedAnyHook =
        false;

    HMODULE taskbarModule =
        GetTaskbarModuleHandle();

    if (
        taskbarModule &&
        !g_taskbarModuleHooked
             .load(
                 std::memory_order_acquire
             )
    ) {
        if (
            TryHookTaskbarModule(
                taskbarModule,
                false
            )
        ) {
            installedAnyHook =
                true;
        }
    }

    HMODULE systemTrayModule =
        GetSystemTrayModuleHandle();

    if (
        systemTrayModule &&
        !g_systemTrayModuleHooked
             .load(
                 std::memory_order_acquire
             )
    ) {
        if (
            TryHookSystemTrayModule(
                systemTrayModule,
                false
            )
        ) {
            installedAnyHook =
                true;
        }
    }

    if (
        installedAnyHook
    ) {
        Wh_ApplyHookOperations();
    }
}

void Wh_ModUninit() {
    StopUIOrderRegistryWatcher();

    Wh_Log(
        L"System Tray Index Analyzer stopped; "
        L"moveRequests=%llu "
        L"suppressedMoveRequests=%llu "
        L"capturedCalls=%llu "
        L"registryNotifications=%llu "
        L"uiOrderWriteAttempts=%llu",
        g_moveRequestCallCount
            .load(
                std::memory_order_relaxed
            ),
        g_moveRequestSuppressedCount
            .load(
                std::memory_order_relaxed
            ),
        g_updateCallCount
            .load(
                std::memory_order_relaxed
            ),
        g_registryNotificationCount
            .load(
                std::memory_order_relaxed
            ),
        g_uiOrderWriteAttemptCount
            .load(
                std::memory_order_relaxed
            )
    );
}
