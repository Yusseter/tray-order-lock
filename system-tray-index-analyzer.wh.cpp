// ==WindhawkMod==
// @id              system-tray-index-analyzer
// @name            System Tray Index Analyzer
// @description     Tests whether suppressing one UIOrderList write also prevents the visible tray reorder.
// @version         0.5.0
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

Version 0.5.0 performs a single controlled behavior test:

- It watches for NtSetValueKey calls targeting the REG_BINARY UIOrderList value
  under HKCU\\Control Panel\\NotifyIconSettings.
- The first exact matching write is suppressed and STATUS_SUCCESS is returned to
  the caller.
- Every later matching write is passed to the original NtSetValueKey function.
- Writes with an unresolved key path, a different key, a different value name or
  a different registry type are never suppressed.

The one-shot suppression makes it possible to test whether preventing the
registry write also prevents the visible tray reorder. A second drag remains
available for restoring and persisting the original icon position.

The mod also records:

- Matching UIOrderList write attempts and whether each one was suppressed
- Read-only UIOrderList snapshots before and after each matching attempt
- Read-only last-set notifications for the NotifyIconSettings registry key
- StackViewModel::UpdateIconIndexes calls and read-only before/after snapshots
- Correlation counters for write attempts, suppressed writes, registry
  notifications and index updates

This is an experimental diagnostic version. It intentionally changes the first
exact matching UIOrderList write after the mod is loaded.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <winternl.h>
#include <windhawk_utils.h>

#include <atomic>
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

constexpr ULONG kKeyNameInformationClass = 3;
constexpr NTSTATUS kStatusSuccess =
    static_cast<NTSTATUS>(0);

std::atomic<bool> g_systemTrayModuleHooked = false;
std::atomic<bool> g_firstMatchingWriteSuppressed = false;

std::atomic<unsigned long long>
    g_updateCallCount = 0;

std::atomic<unsigned long long>
    g_registryNotificationCount = 0;

std::atomic<unsigned long long>
    g_uiOrderWriteAttemptCount = 0;

std::atomic<unsigned long long>
    g_uiOrderSuppressedWriteCount = 0;

HANDLE g_registryWatcherStopEvent = nullptr;
HANDLE g_registryWatcherChangeEvent = nullptr;
HANDLE g_registryWatcherThread = nullptr;
HKEY g_registryWatcherKey = nullptr;

thread_local bool g_insideNtSetValueKeyHook = false;

struct UIOrderSnapshot {
    LONG status = ERROR_SUCCESS;
    DWORD registryType = REG_NONE;
    DWORD byteLength = 0;
    unsigned long long entryCount = 0;
    bool lengthAligned = false;
    std::uint64_t hash = 0;
    bool valid = false;
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
        : insideFlag_(insideFlag) {
        insideFlag_ = true;
    }

    ~NtSetValueKeyHookGuard() {
        insideFlag_ = false;
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

using StackViewModel_UpdateIconIndexes_t =
    void(WINAPI*)(void* pThis);

using NtSetValueKey_t = NTSTATUS(NTAPI*)(
    HANDLE keyHandle,
    PUNICODE_STRING valueName,
    ULONG titleIndex,
    ULONG type,
    PVOID data,
    ULONG dataSize
);

using NtQueryKey_t = NTSTATUS(NTAPI*)(
    HANDLE keyHandle,
    ULONG keyInformationClass,
    PVOID keyInformation,
    ULONG length,
    PULONG resultLength
);

StackViewModel_UpdateIconIndexes_t
    StackViewModel_UpdateIconIndexes_Original =
        nullptr;

NtSetValueKey_t NtSetValueKey_Original =
    nullptr;

NtQueryKey_t NtQueryKey_Function =
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
        hash ^= data[index];
        hash *= kFnv1aPrime;
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
            static_cast<
                unsigned long long
            >(
                actualBytes /
                sizeof(
                    std::uint64_t
                )
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
    if (
        !first.valid ||
        !second.valid
    ) {
        return false;
    }

    return
        first.registryType ==
            second.registryType &&
        first.byteLength ==
            second.byteLength &&
        first.hash ==
            second.hash;
}

void LogUIOrderSnapshot(
    const wchar_t* phase,
    unsigned long long callNumber,
    const UIOrderSnapshot& snapshot
) {
    Wh_Log(
        L"UIORDER_SNAPSHOT "
        L"phase=%s "
        L"call=%llu "
        L"valid=%d "
        L"status=%ld "
        L"type=%lu "
        L"bytes=%lu "
        L"entries=%llu "
        L"aligned=%d "
        L"hash=0x%016llX",
        phase,
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
        queryStatus < 0
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

    NtSetValueKeyHookGuard hookGuard(
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

    bool expected =
        false;

    const bool suppressWrite =
        g_firstMatchingWriteSuppressed
            .compare_exchange_strong(
                expected,
                true,
                std::memory_order_acq_rel
            );

    if (
        suppressWrite
    ) {
        g_uiOrderSuppressedWriteCount
            .fetch_add(
                1,
                std::memory_order_relaxed
            );
    }

    const DWORD threadId =
        GetCurrentThreadId();

    const unsigned long long
        updateCallsBefore =
            g_updateCallCount.load(
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
        L"suppress=%d "
        L"updateCallsObserved=%llu "
        L"beforeValid=%d "
        L"beforeBytes=%lu "
        L"beforeHash=0x%016llX",
        attemptNumber,
        threadId,
        keyPath.c_str(),
        type,
        dataSize,
        suppressWrite
            ? 1
            : 0,
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

    NTSTATUS status =
        kStatusSuccess;

    if (
        suppressWrite
    ) {
        Wh_Log(
            L"UIORDER_WRITE_SUPPRESSED "
            L"attempt=%llu "
            L"thread=%lu "
            L"returnedStatus=0x%08lX",
            attemptNumber,
            threadId,
            static_cast<ULONG>(
                kStatusSuccess
            )
        );
    }
    else {
        status =
            NtSetValueKey_Original(
                keyHandle,
                valueName,
                titleIndex,
                type,
                data,
                dataSize
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

    const unsigned long long
        updateCallsAfter =
            g_updateCallCount.load(
                std::memory_order_acquire
            );

    Wh_Log(
        L"UIORDER_WRITE_END "
        L"attempt=%llu "
        L"thread=%lu "
        L"suppressed=%d "
        L"ntstatus=0x%08lX "
        L"comparable=%d "
        L"changed=%d "
        L"afterValid=%d "
        L"afterBytes=%lu "
        L"afterHash=0x%016llX "
        L"updateCallsBefore=%llu "
        L"updateCallsAfter=%llu",
        attemptNumber,
        threadId,
        suppressWrite
            ? 1
            : 0,
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
        updateCallsBefore,
        updateCallsAfter
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
        !ntSetValueKey
    ) {
        Wh_Log(
            L"NtSetValueKey is unavailable"
        );

        return false;
    }

    if (
        !NtQueryKey_Function
    ) {
        Wh_Log(
            L"NtQueryKey is unavailable"
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
        L"one-shot UIOrderList "
        L"suppression armed"
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
                      previousSnapshot
                          ->hash
                  )
                : 0;

    Wh_Log(
        L"UIORDER_WATCH "
        L"phase=%s "
        L"notification=%llu "
        L"updateCallsObserved=%llu "
        L"writeAttemptsObserved=%llu "
        L"suppressedWritesObserved=%llu "
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
        g_updateCallCount.load(
            std::memory_order_acquire
        ),
        g_uiOrderWriteAttemptCount.load(
            std::memory_order_acquire
        ),
        g_uiOrderSuppressedWriteCount.load(
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
        DWORD waitResult =
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
                L"Registry watcher wait "
                L"failed; error=%lu",
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
        g_registryNotificationCount.load(
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

    g_registryNotificationCount.store(
        0,
        std::memory_order_release
    );

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
            L"Failed to open "
            L"NotifyIconSettings for "
            L"notifications; status=%ld",
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
            L"Failed to create registry "
            L"watcher stop event; error=%lu",
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
            L"Failed to create registry "
            L"watcher change event; "
            L"error=%lu",
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
            L"Failed to create registry "
            L"watcher thread; error=%lu",
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
                L"Waiting for registry "
                L"watcher failed; result=%lu "
                L"error=%lu",
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
            L"System tray module=%p, "
            L"path unavailable",
            module
        );

        return;
    }

    Wh_Log(
        L"System tray module=%p, "
        L"path=\"%s\"",
        module,
        modulePath
    );
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
        L"writeAttemptsObserved=%llu "
        L"suppressedWritesObserved=%llu",
        callNumber,
        threadId,
        pThis,
        g_uiOrderWriteAttemptCount.load(
            std::memory_order_acquire
        ),
        g_uiOrderSuppressedWriteCount.load(
            std::memory_order_acquire
        )
    );

    const UIOrderSnapshot
        beforeSnapshot =
            CaptureUIOrderSnapshot();

    LogUIOrderSnapshot(
        L"before",
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
        L"writeAttemptsObserved=%llu "
        L"suppressedWritesObserved=%llu",
        callNumber,
        threadId,
        pThis,
        g_uiOrderWriteAttemptCount.load(
            std::memory_order_acquire
        ),
        g_uiOrderSuppressedWriteCount.load(
            std::memory_order_acquire
        )
    );
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
        module
    );

    Wh_Log(
        L"StackViewModel::"
        L"UpdateIconIndexes "
        L"hook installed"
    );

    return true;
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

void HandleLoadedModule(
    HMODULE module,
    LPCWSTR requestedPath
) {
    if (
        !module ||
        g_systemTrayModuleHooked.load(
            std::memory_order_acquire
        )
    ) {
        return;
    }

    HMODULE systemTrayModule =
        GetSystemTrayModuleHandle();

    if (
        !systemTrayModule ||
        systemTrayModule !=
            module
    ) {
        return;
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
        return;
    }

    Wh_Log(
        L"Detected system tray module "
        L"load: requestedPath=\"%s\"",
        requestedPath
            ? requestedPath
            : L"<null>"
    );

    if (
        !HookSystemTraySymbols(
            module
        )
    ) {
        g_systemTrayModuleHooked.store(
            false,
            std::memory_order_release
        );

        return;
    }

    Wh_ApplyHookOperations();
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
            L"kernelbase.dll "
            L"is unavailable"
        );

        return false;
    }

    auto loadLibraryExW =
        reinterpret_cast<
            decltype(
                &LoadLibraryExW
            )
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
            L"LoadLibraryExW "
            L"is unavailable"
        );

        return false;
    }

    return
        WindhawkUtils::
            Wh_SetFunctionHookT(
                loadLibraryExW,
                LoadLibraryExW_Hook,
                &LoadLibraryExW_Original
            );
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"System Tray Index Analyzer "
        L"0.5.0 initializing; "
        L"one-shot suppression armed"
    );

    g_systemTrayModuleHooked.store(
        false,
        std::memory_order_release
    );

    g_firstMatchingWriteSuppressed.store(
        false,
        std::memory_order_release
    );

    g_updateCallCount.store(
        0,
        std::memory_order_release
    );

    g_registryNotificationCount.store(
        0,
        std::memory_order_release
    );

    g_uiOrderWriteAttemptCount.store(
        0,
        std::memory_order_release
    );

    g_uiOrderSuppressedWriteCount.store(
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

    HMODULE module =
        GetSystemTrayModuleHandle();

    if (
        module
    ) {
        g_systemTrayModuleHooked.store(
            true,
            std::memory_order_release
        );

        if (
            !HookSystemTraySymbols(
                module
            )
        ) {
            g_systemTrayModuleHooked.store(
                false,
                std::memory_order_release
            );

            StopUIOrderRegistryWatcher();

            return FALSE;
        }

        return TRUE;
    }

    Wh_Log(
        L"SystemTray.dll is not "
        L"loaded yet; waiting for "
        L"module load"
    );

    if (
        !HookModuleLoader()
    ) {
        StopUIOrderRegistryWatcher();

        return FALSE;
    }

    return TRUE;
}

void Wh_ModAfterInit() {
    if (
        g_systemTrayModuleHooked.load(
            std::memory_order_acquire
        )
    ) {
        return;
    }

    HMODULE module =
        GetSystemTrayModuleHandle();

    if (
        !module
    ) {
        return;
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
        return;
    }

    Wh_Log(
        L"System tray module found "
        L"after initialization"
    );

    if (
        HookSystemTraySymbols(
            module
        )
    ) {
        Wh_ApplyHookOperations();
    }
    else {
        g_systemTrayModuleHooked.store(
            false,
            std::memory_order_release
        );
    }
}

void Wh_ModUninit() {
    StopUIOrderRegistryWatcher();

    Wh_Log(
        L"System Tray Index Analyzer "
        L"stopped; "
        L"capturedCalls=%llu "
        L"registryNotifications=%llu "
        L"uiOrderWriteAttempts=%llu "
        L"suppressedWrites=%llu",
        g_updateCallCount.load(
            std::memory_order_relaxed
        ),
        g_registryNotificationCount.load(
            std::memory_order_relaxed
        ),
        g_uiOrderWriteAttemptCount.load(
            std::memory_order_relaxed
        ),
        g_uiOrderSuppressedWriteCount.load(
            std::memory_order_relaxed
        )
    );
}
