// ==WindhawkMod==
// @id              system-tray-index-analyzer
// @name            System Tray Index Analyzer
// @description     Logs SystemTray index updates, delayed snapshots and read-only UIOrderList registry notifications.
// @version         0.3.0
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

The mod hooks:

    winrt::SystemTray::implementation::StackViewModel::UpdateIconIndexes()

The mod records:

- Call number
- Thread ID
- StackViewModel address
- UIOrderList byte length, entry count and 64-bit FNV-1a hash immediately before
  and after the original function
- Whether the immediate before and after snapshots differ
- Read-only delayed snapshots 10, 50, 250, 1000, 1500, 2000, 2500, 3000,
  5000 and 10000 milliseconds after the immediate after snapshot
- Requested delay, actual elapsed time and whether each delayed snapshot differs
  from the immediate after snapshot
- Read-only last-set notifications for the NotifyIconSettings registry key
- The UIOrderList snapshot observed after each notification, compared with the
  previous watcher snapshot
- The number of UpdateIconIndexes calls observed when the notification is
  processed

Delayed reads are scheduled on one background worker. Pending delayed reads are
cancelled when the mod is unloaded, and the worker is stopped before the module
can be released.

Registry notifications are key-wide and can be caused by values other than
UIOrderList. Every notification is therefore followed by a read-only
UIOrderList snapshot and comparison. Notifications can be coalesced by Windows.

The mod only reads:

    HKCU\\Control Panel\\NotifyIconSettings\\UIOrderList

It does not modify tray icons, tray ordering, registry values, XAML elements,
function arguments or original return behavior.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <windhawk_utils.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <queue>
#include <vector>

namespace {

constexpr wchar_t kNotifyIconSettingsPath[] =
    L"Control Panel\\NotifyIconSettings";

constexpr wchar_t kUIOrderListValueName[] =
    L"UIOrderList";

constexpr std::uint64_t kFnv1aOffsetBasis =
    14695981039346656037ULL;

constexpr std::uint64_t kFnv1aPrime =
    1099511628211ULL;

constexpr DWORD kDelayedSnapshotDelaysMs[] = {
    10,
    50,
    250,
    1000,
    1500,
    2000,
    2500,
    3000,
    5000,
    10000,
};

std::atomic<bool> g_systemTrayModuleHooked = false;
std::atomic<unsigned long long> g_updateCallCount = 0;

struct UIOrderSnapshot {
    LONG status = ERROR_SUCCESS;
    DWORD registryType = REG_NONE;
    DWORD byteLength = 0;
    unsigned long long entryCount = 0;
    bool lengthAligned = false;
    std::uint64_t hash = 0;
    bool valid = false;
};

struct DelayedSnapshotJob {
    std::chrono::steady_clock::time_point dueTime;
    std::chrono::steady_clock::time_point baseTime;
    unsigned long long callNumber = 0;
    DWORD requestedDelayMs = 0;
    unsigned long long sequence = 0;
    UIOrderSnapshot immediateAfterSnapshot;
};

struct DelayedSnapshotJobCompare {
    bool operator()(
        const DelayedSnapshotJob& left,
        const DelayedSnapshotJob& right
    ) const {
        if (left.dueTime != right.dueTime) {
            return left.dueTime > right.dueTime;
        }

        return left.sequence > right.sequence;
    }
};

using DelayedSnapshotQueue = std::priority_queue<
    DelayedSnapshotJob,
    std::vector<DelayedSnapshotJob>,
    DelayedSnapshotJobCompare
>;

SRWLOCK g_delayedJobsLock = SRWLOCK_INIT;
DelayedSnapshotQueue g_delayedJobs;
std::atomic<bool> g_delayedWorkerStopping = false;
std::atomic<bool> g_acceptDelayedJobs = false;
std::atomic<unsigned long long> g_delayedJobSequence = 0;
HANDLE g_delayedWorkerWakeEvent = nullptr;
HANDLE g_delayedWorkerThread = nullptr;

std::atomic<unsigned long long>
    g_registryNotificationCount = 0;

HANDLE g_registryWatcherStopEvent = nullptr;
HANDLE g_registryWatcherChangeEvent = nullptr;
HANDLE g_registryWatcherThread = nullptr;
HKEY g_registryWatcherKey = nullptr;

using StackViewModel_UpdateIconIndexes_t =
    void(WINAPI*)(void* pThis);

StackViewModel_UpdateIconIndexes_t
    StackViewModel_UpdateIconIndexes_Original = nullptr;

std::uint64_t CalculateFnv1aHash(
    const BYTE* data,
    DWORD length
) {
    std::uint64_t hash = kFnv1aOffsetBasis;

    for (DWORD index = 0; index < length; index++) {
        hash ^= data[index];
        hash *= kFnv1aPrime;
    }

    return hash;
}

UIOrderSnapshot CaptureUIOrderSnapshot() {
    UIOrderSnapshot snapshot;

    /*
    UIOrderList can theoretically change between the size query and the data
    query. Retry a small number of times when that happens.
    */
    for (int attempt = 0; attempt < 3; attempt++) {
        DWORD registryType = REG_NONE;
        DWORD requiredBytes = 0;

        LONG status = RegGetValueW(
            HKEY_CURRENT_USER,
            kNotifyIconSettingsPath,
            kUIOrderListValueName,
            RRF_RT_REG_BINARY,
            &registryType,
            nullptr,
            &requiredBytes
        );

        if (status != ERROR_SUCCESS) {
            snapshot.status = status;
            snapshot.registryType = registryType;
            return snapshot;
        }

        std::vector<BYTE> data(requiredBytes);

        DWORD actualBytes = requiredBytes;

        status = RegGetValueW(
            HKEY_CURRENT_USER,
            kNotifyIconSettingsPath,
            kUIOrderListValueName,
            RRF_RT_REG_BINARY,
            &registryType,
            data.empty() ? nullptr : data.data(),
            &actualBytes
        );

        if (status == ERROR_MORE_DATA) {
            continue;
        }

        snapshot.status = status;
        snapshot.registryType = registryType;

        if (status != ERROR_SUCCESS) {
            return snapshot;
        }

        data.resize(actualBytes);

        snapshot.byteLength = actualBytes;
        snapshot.entryCount =
            static_cast<unsigned long long>(
                actualBytes / sizeof(std::uint64_t)
            );

        snapshot.lengthAligned =
            actualBytes % sizeof(std::uint64_t) == 0;

        snapshot.hash = CalculateFnv1aHash(
            data.empty() ? nullptr : data.data(),
            actualBytes
        );

        snapshot.valid = true;
        return snapshot;
    }

    snapshot.status = ERROR_MORE_DATA;
    return snapshot;
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
        snapshot.valid ? 1 : 0,
        snapshot.status,
        snapshot.registryType,
        snapshot.byteLength,
        snapshot.entryCount,
        snapshot.lengthAligned ? 1 : 0,
        static_cast<unsigned long long>(snapshot.hash)
    );
}

bool AreSnapshotsEqual(
    const UIOrderSnapshot& first,
    const UIOrderSnapshot& second
) {
    if (!first.valid || !second.valid) {
        return false;
    }

    return
        first.registryType == second.registryType &&
        first.byteLength == second.byteLength &&
        first.hash == second.hash;
}

void LogDelayedUIOrderSnapshot(
    const DelayedSnapshotJob& job,
    unsigned long long actualElapsedMs,
    const UIOrderSnapshot& delayedSnapshot
) {
    int comparable =
        job.immediateAfterSnapshot.valid &&
        delayedSnapshot.valid
            ? 1
            : 0;

    int changedFromImmediateAfter =
        comparable &&
        !AreSnapshotsEqual(
            job.immediateAfterSnapshot,
            delayedSnapshot
        )
            ? 1
            : 0;

    Wh_Log(
        L"UIORDER_DELAYED "
        L"call=%llu "
        L"requestedDelayMs=%lu "
        L"actualElapsedMs=%llu "
        L"valid=%d "
        L"status=%ld "
        L"type=%lu "
        L"bytes=%lu "
        L"entries=%llu "
        L"aligned=%d "
        L"hash=0x%016llX "
        L"comparable=%d "
        L"changedFromImmediateAfter=%d "
        L"immediateAfterHash=0x%016llX",
        job.callNumber,
        job.requestedDelayMs,
        actualElapsedMs,
        delayedSnapshot.valid ? 1 : 0,
        delayedSnapshot.status,
        delayedSnapshot.registryType,
        delayedSnapshot.byteLength,
        delayedSnapshot.entryCount,
        delayedSnapshot.lengthAligned ? 1 : 0,
        static_cast<unsigned long long>(delayedSnapshot.hash),
        comparable,
        changedFromImmediateAfter,
        static_cast<unsigned long long>(
            job.immediateAfterSnapshot.hash
        )
    );
}

DWORD WINAPI DelayedSnapshotWorkerThreadProc(
    LPVOID
) {
    Wh_Log(
        L"Delayed snapshot worker started; thread=%lu",
        GetCurrentThreadId()
    );

    for (;;) {
        DelayedSnapshotJob job;
        bool haveJob = false;
        DWORD waitMilliseconds = INFINITE;

        bool shouldStop = false;

        AcquireSRWLockExclusive(
            &g_delayedJobsLock
        );

        if (
            g_delayedWorkerStopping.load(
                std::memory_order_acquire
            )
        ) {
            shouldStop = true;
        }
        else if (!g_delayedJobs.empty()) {
            const auto now =
                std::chrono::steady_clock::now();

            const DelayedSnapshotJob& nextJob =
                g_delayedJobs.top();

            if (nextJob.dueTime <= now) {
                job = nextJob;
                g_delayedJobs.pop();
                haveJob = true;
            }
            else {
                const auto remaining =
                    std::chrono::ceil<
                        std::chrono::milliseconds
                    >(
                        nextJob.dueTime - now
                    );

                const auto remainingCount =
                    remaining.count();

                waitMilliseconds =
                    remainingCount >=
                            static_cast<long long>(INFINITE)
                        ? INFINITE - 1
                        : static_cast<DWORD>(
                              remainingCount
                          );
            }
        }

        ReleaseSRWLockExclusive(
            &g_delayedJobsLock
        );

        if (shouldStop) {
            break;
        }

        if (haveJob) {
            UIOrderSnapshot delayedSnapshot =
                CaptureUIOrderSnapshot();

            const auto completedAt =
                std::chrono::steady_clock::now();

            const auto actualElapsed =
                std::chrono::duration_cast<
                    std::chrono::milliseconds
                >(
                    completedAt - job.baseTime
                );

            LogDelayedUIOrderSnapshot(
                job,
                static_cast<unsigned long long>(
                    actualElapsed.count()
                ),
                delayedSnapshot
            );

            continue;
        }

        DWORD waitResult = WaitForSingleObject(
            g_delayedWorkerWakeEvent,
            waitMilliseconds
        );

        if (waitResult == WAIT_FAILED) {
            DWORD error = GetLastError();

            g_acceptDelayedJobs.store(
                false,
                std::memory_order_release
            );

            Wh_Log(
                L"Delayed snapshot worker wait failed; error=%lu",
                error
            );

            break;
        }
    }

    Wh_Log(
        L"Delayed snapshot worker stopped; thread=%lu",
        GetCurrentThreadId()
    );

    return 0;
}

bool StartDelayedSnapshotWorker() {
    if (g_delayedWorkerThread) {
        return true;
    }

    g_delayedWorkerStopping.store(
        false,
        std::memory_order_release
    );

    g_acceptDelayedJobs.store(
        false,
        std::memory_order_release
    );

    g_delayedWorkerWakeEvent = CreateEventW(
        nullptr,
        FALSE,
        FALSE,
        nullptr
    );

    if (!g_delayedWorkerWakeEvent) {
        Wh_Log(
            L"Failed to create delayed snapshot wake event; error=%lu",
            GetLastError()
        );

        return false;
    }

    g_delayedWorkerThread = CreateThread(
        nullptr,
        0,
        DelayedSnapshotWorkerThreadProc,
        nullptr,
        0,
        nullptr
    );

    if (!g_delayedWorkerThread) {
        DWORD error = GetLastError();

        CloseHandle(g_delayedWorkerWakeEvent);
        g_delayedWorkerWakeEvent = nullptr;

        Wh_Log(
            L"Failed to create delayed snapshot worker; error=%lu",
            error
        );

        return false;
    }

    g_acceptDelayedJobs.store(
        true,
        std::memory_order_release
    );

    return true;
}

void QueueDelayedSnapshots(
    unsigned long long callNumber,
    const UIOrderSnapshot& immediateAfterSnapshot,
    std::chrono::steady_clock::time_point baseTime
) {
    if (
        !g_acceptDelayedJobs.load(
            std::memory_order_acquire
        )
    ) {
        return;
    }

    AcquireSRWLockExclusive(
        &g_delayedJobsLock
    );

    if (
        !g_acceptDelayedJobs.load(
            std::memory_order_acquire
        )
    ) {
        ReleaseSRWLockExclusive(
            &g_delayedJobsLock
        );

        return;
    }

    for (DWORD delayMilliseconds :
         kDelayedSnapshotDelaysMs) {
        DelayedSnapshotJob job;

        job.dueTime =
            baseTime +
            std::chrono::milliseconds(
                delayMilliseconds
            );

        job.baseTime = baseTime;
        job.callNumber = callNumber;
        job.requestedDelayMs = delayMilliseconds;
        job.sequence =
            g_delayedJobSequence.fetch_add(
                1,
                std::memory_order_relaxed
            );

        job.immediateAfterSnapshot =
            immediateAfterSnapshot;

        g_delayedJobs.push(job);
    }

    SetEvent(g_delayedWorkerWakeEvent);

    ReleaseSRWLockExclusive(
        &g_delayedJobsLock
    );
}

void StopDelayedSnapshotWorker() {
    g_acceptDelayedJobs.store(
        false,
        std::memory_order_release
    );

    std::size_t cancelledJobs = 0;

    AcquireSRWLockExclusive(
        &g_delayedJobsLock
    );

    g_delayedWorkerStopping.store(
        true,
        std::memory_order_release
    );

    cancelledJobs = g_delayedJobs.size();

    while (!g_delayedJobs.empty()) {
        g_delayedJobs.pop();
    }

    ReleaseSRWLockExclusive(
        &g_delayedJobsLock
    );

    if (g_delayedWorkerWakeEvent) {
        SetEvent(g_delayedWorkerWakeEvent);
    }

    if (g_delayedWorkerThread) {
        DWORD waitResult = WaitForSingleObject(
            g_delayedWorkerThread,
            INFINITE
        );

        if (waitResult != WAIT_OBJECT_0) {
            Wh_Log(
                L"Waiting for delayed snapshot worker failed; result=%lu error=%lu",
                waitResult,
                GetLastError()
            );
        }

        CloseHandle(g_delayedWorkerThread);
        g_delayedWorkerThread = nullptr;
    }

    if (g_delayedWorkerWakeEvent) {
        CloseHandle(g_delayedWorkerWakeEvent);
        g_delayedWorkerWakeEvent = nullptr;
    }

    Wh_Log(
        L"Delayed snapshot worker cleanup complete; cancelledJobs=%llu",
        static_cast<unsigned long long>(cancelledJobs)
    );
}


void LogUIOrderRegistryWatcherSnapshot(
    const wchar_t* phase,
    unsigned long long notificationNumber,
    const UIOrderSnapshot* previousSnapshot,
    const UIOrderSnapshot& currentSnapshot
) {
    int comparable =
        previousSnapshot &&
        previousSnapshot->valid &&
        currentSnapshot.valid
            ? 1
            : 0;

    int changedFromPrevious =
        comparable &&
        !AreSnapshotsEqual(
            *previousSnapshot,
            currentSnapshot
        )
            ? 1
            : 0;

    unsigned long long previousHash =
        previousSnapshot
            ? static_cast<unsigned long long>(
                  previousSnapshot->hash
              )
            : 0;

    Wh_Log(
        L"UIORDER_WATCH "
        L"phase=%s "
        L"notification=%llu "
        L"updateCallsObserved=%llu "
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
        currentSnapshot.valid ? 1 : 0,
        currentSnapshot.status,
        currentSnapshot.registryType,
        currentSnapshot.byteLength,
        currentSnapshot.entryCount,
        currentSnapshot.lengthAligned ? 1 : 0,
        static_cast<unsigned long long>(
            currentSnapshot.hash
        ),
        comparable,
        changedFromPrevious,
        previousHash
    );
}

LONG ArmUIOrderRegistryNotification() {
    return RegNotifyChangeKeyValue(
        g_registryWatcherKey,
        FALSE,
        REG_NOTIFY_CHANGE_LAST_SET,
        g_registryWatcherChangeEvent,
        TRUE
    );
}

DWORD WINAPI UIOrderRegistryWatcherThreadProc(
    LPVOID
) {
    Wh_Log(
        L"UIOrderList registry watcher started; "
        L"thread=%lu",
        GetCurrentThreadId()
    );

    LONG notifyStatus =
        ArmUIOrderRegistryNotification();

    if (notifyStatus != ERROR_SUCCESS) {
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
        DWORD waitResult = WaitForMultipleObjects(
            ARRAYSIZE(waitHandles),
            waitHandles,
            FALSE,
            INFINITE
        );

        if (waitResult == WAIT_OBJECT_0) {
            break;
        }

        if (waitResult == WAIT_OBJECT_0 + 1) {
            /*
            RegNotifyChangeKeyValue is one-shot. Re-arm it before
            reading UIOrderList so a change that occurs during the
            registry read can still signal the event.
            */
            notifyStatus =
                ArmUIOrderRegistryNotification();

            if (notifyStatus != ERROR_SUCCESS) {
                Wh_Log(
                    L"Registry notification "
                    L"re-registration failed; "
                    L"status=%ld",
                    notifyStatus
                );

                break;
            }

            UIOrderSnapshot currentSnapshot =
                CaptureUIOrderSnapshot();

            unsigned long long notificationNumber =
                g_registryNotificationCount.fetch_add(
                    1,
                    std::memory_order_relaxed
                ) + 1;

            LogUIOrderRegistryWatcherSnapshot(
                L"change",
                notificationNumber,
                &previousSnapshot,
                currentSnapshot
            );

            previousSnapshot = currentSnapshot;
            continue;
        }

        if (waitResult == WAIT_FAILED) {
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
        L"UIOrderList registry watcher stopped; "
        L"thread=%lu notifications=%llu",
        GetCurrentThreadId(),
        g_registryNotificationCount.load(
            std::memory_order_relaxed
        )
    );

    return 0;
}

bool StartUIOrderRegistryWatcher() {
    if (g_registryWatcherThread) {
        return true;
    }

    g_registryNotificationCount.store(
        0,
        std::memory_order_release
    );

    LONG openStatus = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        kNotifyIconSettingsPath,
        0,
        KEY_NOTIFY,
        &g_registryWatcherKey
    );

    if (openStatus != ERROR_SUCCESS) {
        Wh_Log(
            L"Failed to open NotifyIconSettings "
            L"for notifications; status=%ld",
            openStatus
        );

        return false;
    }

    g_registryWatcherStopEvent = CreateEventW(
        nullptr,
        TRUE,
        FALSE,
        nullptr
    );

    if (!g_registryWatcherStopEvent) {
        DWORD error = GetLastError();

        RegCloseKey(g_registryWatcherKey);
        g_registryWatcherKey = nullptr;

        Wh_Log(
            L"Failed to create registry watcher "
            L"stop event; error=%lu",
            error
        );

        return false;
    }

    g_registryWatcherChangeEvent = CreateEventW(
        nullptr,
        FALSE,
        FALSE,
        nullptr
    );

    if (!g_registryWatcherChangeEvent) {
        DWORD error = GetLastError();

        CloseHandle(g_registryWatcherStopEvent);
        g_registryWatcherStopEvent = nullptr;

        RegCloseKey(g_registryWatcherKey);
        g_registryWatcherKey = nullptr;

        Wh_Log(
            L"Failed to create registry watcher "
            L"change event; error=%lu",
            error
        );

        return false;
    }

    g_registryWatcherThread = CreateThread(
        nullptr,
        0,
        UIOrderRegistryWatcherThreadProc,
        nullptr,
        0,
        nullptr
    );

    if (!g_registryWatcherThread) {
        DWORD error = GetLastError();

        CloseHandle(g_registryWatcherChangeEvent);
        g_registryWatcherChangeEvent = nullptr;

        CloseHandle(g_registryWatcherStopEvent);
        g_registryWatcherStopEvent = nullptr;

        RegCloseKey(g_registryWatcherKey);
        g_registryWatcherKey = nullptr;

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
    if (g_registryWatcherStopEvent) {
        SetEvent(g_registryWatcherStopEvent);
    }

    if (g_registryWatcherThread) {
        DWORD waitResult = WaitForSingleObject(
            g_registryWatcherThread,
            INFINITE
        );

        if (waitResult != WAIT_OBJECT_0) {
            Wh_Log(
                L"Waiting for registry watcher "
                L"failed; result=%lu error=%lu",
                waitResult,
                GetLastError()
            );
        }

        CloseHandle(g_registryWatcherThread);
        g_registryWatcherThread = nullptr;
    }

    if (g_registryWatcherKey) {
        RegCloseKey(g_registryWatcherKey);
        g_registryWatcherKey = nullptr;
    }

    if (g_registryWatcherChangeEvent) {
        CloseHandle(g_registryWatcherChangeEvent);
        g_registryWatcherChangeEvent = nullptr;
    }

    if (g_registryWatcherStopEvent) {
        CloseHandle(g_registryWatcherStopEvent);
        g_registryWatcherStopEvent = nullptr;
    }

    Wh_Log(
        L"UIOrderList registry watcher "
        L"cleanup complete"
    );
}

void LogModuleInformation(HMODULE module) {
    wchar_t modulePath[MAX_PATH]{};

    DWORD length = GetModuleFileNameW(
        module,
        modulePath,
        ARRAYSIZE(modulePath)
    );

    if (length == 0 || length >= ARRAYSIZE(modulePath)) {
        Wh_Log(
            L"System tray module=%p, path unavailable",
            module
        );

        return;
    }

    Wh_Log(
        L"System tray module=%p, path=\"%s\"",
        module,
        modulePath
    );
}

void WINAPI StackViewModel_UpdateIconIndexes_Hook(
    void* pThis
) {
    unsigned long long callNumber =
        g_updateCallCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) + 1;

    DWORD threadId = GetCurrentThreadId();

    Wh_Log(
        L"INDEX_UPDATE_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"this=%p",
        callNumber,
        threadId,
        pThis
    );

    UIOrderSnapshot beforeSnapshot =
        CaptureUIOrderSnapshot();

    LogUIOrderSnapshot(
        L"before",
        callNumber,
        beforeSnapshot
    );

    StackViewModel_UpdateIconIndexes_Original(
        pThis
    );

    UIOrderSnapshot afterSnapshot =
        CaptureUIOrderSnapshot();

    const auto afterSnapshotTime =
        std::chrono::steady_clock::now();

    LogUIOrderSnapshot(
        L"after",
        callNumber,
        afterSnapshot
    );

    int comparable =
        beforeSnapshot.valid &&
        afterSnapshot.valid
            ? 1
            : 0;

    int changed =
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
        static_cast<unsigned long long>(
            beforeSnapshot.hash
        ),
        static_cast<unsigned long long>(
            afterSnapshot.hash
        )
    );

    QueueDelayedSnapshots(
        callNumber,
        afterSnapshot,
        afterSnapshotTime
    );

    Wh_Log(
        L"INDEX_UPDATE_END "
        L"call=%llu "
        L"thread=%lu "
        L"this=%p",
        callNumber,
        threadId,
        pThis
    );
}

bool HookSystemTraySymbols(HMODULE module) {
    WindhawkUtils::SYMBOL_HOOK symbolHooks[] = {
        {
            {
                LR"(private: void __cdecl winrt::SystemTray::implementation::StackViewModel::UpdateIconIndexes(void))"
            },
            &StackViewModel_UpdateIconIndexes_Original,
            StackViewModel_UpdateIconIndexes_Hook,
        },
    };

    if (!WindhawkUtils::HookSymbols(
            module,
            symbolHooks,
            ARRAYSIZE(symbolHooks)
        )) {
        Wh_Log(
            L"Failed to locate or hook "
            L"StackViewModel::UpdateIconIndexes"
        );

        return false;
    }

    LogModuleInformation(module);

    Wh_Log(
        L"StackViewModel::UpdateIconIndexes "
        L"hook installed"
    );

    return true;
}

HMODULE GetSystemTrayModuleHandle() {
    HMODULE module =
        GetModuleHandleW(
            L"SystemTray.dll"
        );

    if (module) {
        return module;
    }

    return GetModuleHandleW(
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
        systemTrayModule != module
    ) {
        return;
    }

    bool expected = false;

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
        L"Detected system tray module load: "
        L"requestedPath=\"%s\"",
        requestedPath
            ? requestedPath
            : L"<null>"
    );

    if (!HookSystemTraySymbols(module)) {
        g_systemTrayModuleHooked.store(
            false,
            std::memory_order_release
        );

        return;
    }

    Wh_ApplyHookOperations();
}

using LoadLibraryExW_t =
    decltype(&LoadLibraryExW);

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

    if (module) {
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

    if (!kernelBase) {
        Wh_Log(
            L"kernelbase.dll is unavailable"
        );

        return false;
    }

    auto loadLibraryExW =
        reinterpret_cast<
            decltype(&LoadLibraryExW)
        >(
            GetProcAddress(
                kernelBase,
                "LoadLibraryExW"
            )
        );

    if (!loadLibraryExW) {
        Wh_Log(
            L"LoadLibraryExW is unavailable"
        );

        return false;
    }

    return WindhawkUtils::Wh_SetFunctionHookT(
        loadLibraryExW,
        LoadLibraryExW_Hook,
        &LoadLibraryExW_Original
    );
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"System Tray Index Analyzer 0.3.0 "
        L"initializing"
    );

    if (!StartDelayedSnapshotWorker()) {
        return FALSE;
    }

    if (!StartUIOrderRegistryWatcher()) {
        StopDelayedSnapshotWorker();
        return FALSE;
    }

    HMODULE module =
        GetSystemTrayModuleHandle();

    if (module) {
        g_systemTrayModuleHooked.store(
            true,
            std::memory_order_release
        );

        if (!HookSystemTraySymbols(module)) {
            g_systemTrayModuleHooked.store(
                false,
                std::memory_order_release
            );

            StopUIOrderRegistryWatcher();
            StopDelayedSnapshotWorker();
            return FALSE;
        }

        return TRUE;
    }

    Wh_Log(
        L"SystemTray.dll is not loaded yet; "
        L"waiting for module load"
    );

    if (!HookModuleLoader()) {
        StopUIOrderRegistryWatcher();
        StopDelayedSnapshotWorker();
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

    if (!module) {
        return;
    }

    bool expected = false;

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

    if (HookSystemTraySymbols(module)) {
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
    StopDelayedSnapshotWorker();
    StopUIOrderRegistryWatcher();

    Wh_Log(
        L"System Tray Index Analyzer stopped; "
        L"capturedCalls=%llu "
        L"registryNotifications=%llu",
        g_updateCallCount.load(
            std::memory_order_relaxed
        ),
        g_registryNotificationCount.load(
            std::memory_order_relaxed
        )
    );
}
