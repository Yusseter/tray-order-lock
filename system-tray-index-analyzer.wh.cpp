// ==WindhawkMod==
// @id              system-tray-index-analyzer
// @name            System Tray Index Analyzer
// @description     Logs UIOrderList registry writes and correlates them with SystemTray index updates.
// @version         0.4.0
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
    ntdll!NtSetValueKey

It records:

- UpdateIconIndexes call number, thread ID and StackViewModel address
- Read-only UIOrderList snapshots immediately before and after each
  UpdateIconIndexes call
- Read-only last-set notifications for the NotifyIconSettings registry key
- NtSetValueKey calls that target the UIOrderList value under
  NotifyIconSettings
- The native registry key path, value type, data size and NTSTATUS result
- UIOrderList snapshots immediately before and after each matching write
- A captured call stack with module names and relative offsets for each write
- The number of UpdateIconIndexes calls observed at each registry event

Registry notifications are key-wide and can be caused by values other than
UIOrderList. Every notification is therefore followed by a read-only
UIOrderList snapshot and comparison. Notifications can be coalesced by Windows.

The NtSetValueKey hook only observes matching UIOrderList writes. The original
function is always called with its original arguments and its return value is
preserved.

The analyzer itself does not modify tray icons, tray ordering, registry values,
XAML elements, function arguments or original return behavior.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <winternl.h>
#include <windhawk_utils.h>

#include <atomic>
#include <cstdint>
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
constexpr USHORT kMaximumCapturedStackFrames = 32;
constexpr ULONG kStackFramesToSkip = 1;

std::atomic<bool> g_systemTrayModuleHooked = false;
std::atomic<unsigned long long> g_updateCallCount = 0;
std::atomic<unsigned long long> g_registryNotificationCount = 0;
std::atomic<unsigned long long> g_uiOrderWriteCount = 0;

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

struct CapturedStack {
    USHORT frameCount = 0;
    void* frames[kMaximumCapturedStackFrames]{};
};

struct NativeKeyNameInformation {
    ULONG nameLength;
    WCHAR name[1];
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
    StackViewModel_UpdateIconIndexes_Original = nullptr;

NtSetValueKey_t NtSetValueKey_Original = nullptr;
NtQueryKey_t NtQueryKey_Function = nullptr;

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

bool IsUIOrderListValueName(
    const UNICODE_STRING* valueName
) {
    if (
        !valueName ||
        !valueName->Buffer ||
        valueName->Length % sizeof(wchar_t) != 0
    ) {
        return false;
    }

    const int valueNameLength =
        static_cast<int>(
            valueName->Length / sizeof(wchar_t)
        );

    return CompareStringOrdinal(
        valueName->Buffer,
        valueNameLength,
        kUIOrderListValueName,
        ARRAYSIZE(kUIOrderListValueName) - 1,
        TRUE
    ) == CSTR_EQUAL;
}

bool EndsWithOrdinalIgnoreCase(
    const std::wstring& value,
    const wchar_t* suffix
) {
    const int suffixLength =
        static_cast<int>(wcslen(suffix));

    if (
        suffixLength < 0 ||
        value.size() < static_cast<std::size_t>(suffixLength)
    ) {
        return false;
    }

    const wchar_t* valueSuffix =
        value.data() + value.size() - suffixLength;

    return CompareStringOrdinal(
        valueSuffix,
        suffixLength,
        suffix,
        suffixLength,
        TRUE
    ) == CSTR_EQUAL;
}

bool QueryNativeRegistryKeyPath(
    HANDLE keyHandle,
    std::wstring& keyPath,
    NTSTATUS& queryStatus
) {
    keyPath.clear();
    queryStatus = static_cast<NTSTATUS>(0xC0000001L);

    if (!NtQueryKey_Function || !keyHandle) {
        return false;
    }

    ULONG requiredLength = 0;

    queryStatus = NtQueryKey_Function(
        keyHandle,
        kKeyNameInformationClass,
        nullptr,
        0,
        &requiredLength
    );

    if (requiredLength < sizeof(ULONG)) {
        return false;
    }

    std::vector<BYTE> buffer(
        static_cast<std::size_t>(requiredLength) +
        sizeof(wchar_t)
    );

    queryStatus = NtQueryKey_Function(
        keyHandle,
        kKeyNameInformationClass,
        buffer.data(),
        requiredLength,
        &requiredLength
    );

    if (queryStatus < 0) {
        return false;
    }

    const auto* information =
        reinterpret_cast<const NativeKeyNameInformation*>(
            buffer.data()
        );

    if (
        information->nameLength % sizeof(wchar_t) != 0 ||
        information->nameLength >
            requiredLength - sizeof(ULONG)
    ) {
        return false;
    }

    keyPath.assign(
        information->name,
        information->nameLength / sizeof(wchar_t)
    );

    return true;
}

CapturedStack CaptureCurrentCallStack() {
    CapturedStack stack;

    stack.frameCount = CaptureStackBackTrace(
        kStackFramesToSkip,
        kMaximumCapturedStackFrames,
        stack.frames,
        nullptr
    );

    return stack;
}

void LogCapturedStack(
    unsigned long long writeNumber,
    const CapturedStack& stack
) {
    Wh_Log(
        L"UIORDER_WRITE_STACK_BEGIN "
        L"write=%llu frames=%hu",
        writeNumber,
        stack.frameCount
    );

    for (USHORT index = 0; index < stack.frameCount; index++) {
        void* frameAddress = stack.frames[index];
        HMODULE module = nullptr;

        BOOL moduleResolved = GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(frameAddress),
            &module
        );

        wchar_t modulePath[1024]{};
        DWORD modulePathLength = 0;

        if (moduleResolved && module) {
            modulePathLength = GetModuleFileNameW(
                module,
                modulePath,
                ARRAYSIZE(modulePath)
            );
        }

        const unsigned long long moduleOffset =
            module
                ? static_cast<unsigned long long>(
                      reinterpret_cast<std::uintptr_t>(frameAddress) -
                      reinterpret_cast<std::uintptr_t>(module)
                  )
                : 0;

        if (
            moduleResolved &&
            module &&
            modulePathLength > 0 &&
            modulePathLength < ARRAYSIZE(modulePath)
        ) {
            Wh_Log(
                L"UIORDER_WRITE_STACK "
                L"write=%llu "
                L"frame=%hu "
                L"address=%p "
                L"moduleBase=%p "
                L"offset=0x%llX "
                L"module=\"%s\"",
                writeNumber,
                index,
                frameAddress,
                module,
                moduleOffset,
                modulePath
            );
        }
        else {
            Wh_Log(
                L"UIORDER_WRITE_STACK "
                L"write=%llu "
                L"frame=%hu "
                L"address=%p "
                L"moduleBase=%p "
                L"offset=0x%llX "
                L"module=\"<unresolved>\"",
                writeNumber,
                index,
                frameAddress,
                module,
                moduleOffset
            );
        }
    }

    Wh_Log(
        L"UIORDER_WRITE_STACK_END write=%llu",
        writeNumber
    );
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
        !IsUIOrderListValueName(valueName)
    ) {
        return NtSetValueKey_Original(
            keyHandle,
            valueName,
            titleIndex,
            type,
            data,
            dataSize
        );
    }

    g_insideNtSetValueKeyHook = true;

    std::wstring keyPath;
    NTSTATUS keyQueryStatus = 0;

    const bool keyPathResolved =
        QueryNativeRegistryKeyPath(
            keyHandle,
            keyPath,
            keyQueryStatus
        );

    if (
        keyPathResolved &&
        !EndsWithOrdinalIgnoreCase(
            keyPath,
            kNotifyIconSettingsSuffix
        )
    ) {
        g_insideNtSetValueKeyHook = false;

        return NtSetValueKey_Original(
            keyHandle,
            valueName,
            titleIndex,
            type,
            data,
            dataSize
        );
    }

    const unsigned long long writeNumber =
        g_uiOrderWriteCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) + 1;

    const DWORD threadId = GetCurrentThreadId();
    const unsigned long long updateCallsBefore =
        g_updateCallCount.load(
            std::memory_order_acquire
        );

    const UIOrderSnapshot beforeSnapshot =
        CaptureUIOrderSnapshot();

    const CapturedStack stack =
        CaptureCurrentCallStack();

    Wh_Log(
        L"UIORDER_WRITE_BEGIN "
        L"write=%llu "
        L"thread=%lu "
        L"keyResolved=%d "
        L"keyQueryStatus=0x%08lX "
        L"key=\"%s\" "
        L"value=\"UIOrderList\" "
        L"type=%lu "
        L"bytes=%lu "
        L"updateCallsObserved=%llu "
        L"beforeValid=%d "
        L"beforeBytes=%lu "
        L"beforeHash=0x%016llX",
        writeNumber,
        threadId,
        keyPathResolved ? 1 : 0,
        static_cast<ULONG>(keyQueryStatus),
        keyPathResolved
            ? keyPath.c_str()
            : L"<unresolved>",
        type,
        dataSize,
        updateCallsBefore,
        beforeSnapshot.valid ? 1 : 0,
        beforeSnapshot.byteLength,
        static_cast<unsigned long long>(
            beforeSnapshot.hash
        )
    );

    const NTSTATUS status = NtSetValueKey_Original(
        keyHandle,
        valueName,
        titleIndex,
        type,
        data,
        dataSize
    );

    const UIOrderSnapshot afterSnapshot =
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

    const unsigned long long updateCallsAfter =
        g_updateCallCount.load(
            std::memory_order_acquire
        );

    Wh_Log(
        L"UIORDER_WRITE_END "
        L"write=%llu "
        L"thread=%lu "
        L"ntstatus=0x%08lX "
        L"comparable=%d "
        L"changed=%d "
        L"afterValid=%d "
        L"afterBytes=%lu "
        L"afterHash=0x%016llX "
        L"updateCallsBefore=%llu "
        L"updateCallsAfter=%llu",
        writeNumber,
        threadId,
        static_cast<ULONG>(status),
        comparable,
        changed,
        afterSnapshot.valid ? 1 : 0,
        afterSnapshot.byteLength,
        static_cast<unsigned long long>(
            afterSnapshot.hash
        ),
        updateCallsBefore,
        updateCallsAfter
    );

    LogCapturedStack(
        writeNumber,
        stack
    );

    g_insideNtSetValueKeyHook = false;
    return status;
}

bool HookNativeRegistryWrites() {
    HMODULE ntdll = GetModuleHandleW(
        L"ntdll.dll"
    );

    if (!ntdll) {
        Wh_Log(
            L"ntdll.dll is unavailable"
        );

        return false;
    }

    auto ntSetValueKey =
        reinterpret_cast<NtSetValueKey_t>(
            GetProcAddress(
                ntdll,
                "NtSetValueKey"
            )
        );

    NtQueryKey_Function =
        reinterpret_cast<NtQueryKey_t>(
            GetProcAddress(
                ntdll,
                "NtQueryKey"
            )
        );

    if (!ntSetValueKey) {
        Wh_Log(
            L"NtSetValueKey is unavailable"
        );

        return false;
    }

    if (!NtQueryKey_Function) {
        Wh_Log(
            L"NtQueryKey is unavailable"
        );

        return false;
    }

    if (!WindhawkUtils::Wh_SetFunctionHookT(
            ntSetValueKey,
            NtSetValueKey_Hook,
            &NtSetValueKey_Original
        )) {
        Wh_Log(
            L"Failed to hook NtSetValueKey"
        );

        return false;
    }

    Wh_Log(
        L"NtSetValueKey hook installed"
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

    const unsigned long long previousHash =
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
        L"writesObserved=%llu "
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
        g_uiOrderWriteCount.load(
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
            RegNotifyChangeKeyValue is one-shot. Re-arm it before reading
            UIOrderList so a change during the read can still signal the event.
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

            const unsigned long long notificationNumber =
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
        const DWORD error = GetLastError();

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
        const DWORD error = GetLastError();

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
        const DWORD error = GetLastError();

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
        const DWORD waitResult = WaitForSingleObject(
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

    const DWORD length = GetModuleFileNameW(
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
    const unsigned long long callNumber =
        g_updateCallCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) + 1;

    const DWORD threadId = GetCurrentThreadId();

    Wh_Log(
        L"INDEX_UPDATE_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"this=%p "
        L"writesObserved=%llu",
        callNumber,
        threadId,
        pThis,
        g_uiOrderWriteCount.load(
            std::memory_order_acquire
        )
    );

    const UIOrderSnapshot beforeSnapshot =
        CaptureUIOrderSnapshot();

    LogUIOrderSnapshot(
        L"before",
        callNumber,
        beforeSnapshot
    );

    StackViewModel_UpdateIconIndexes_Original(
        pThis
    );

    const UIOrderSnapshot afterSnapshot =
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
        static_cast<unsigned long long>(
            beforeSnapshot.hash
        ),
        static_cast<unsigned long long>(
            afterSnapshot.hash
        )
    );

    Wh_Log(
        L"INDEX_UPDATE_END "
        L"call=%llu "
        L"thread=%lu "
        L"this=%p "
        L"writesObserved=%llu",
        callNumber,
        threadId,
        pThis,
        g_uiOrderWriteCount.load(
            std::memory_order_acquire
        )
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
    HMODULE module = GetModuleHandleW(
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
    HMODULE module = LoadLibraryExW_Original(
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
    HMODULE kernelBase = GetModuleHandleW(
        L"kernelbase.dll"
    );

    if (!kernelBase) {
        Wh_Log(
            L"kernelbase.dll is unavailable"
        );

        return false;
    }

    auto loadLibraryExW =
        reinterpret_cast<decltype(&LoadLibraryExW)>(
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
        L"System Tray Index Analyzer 0.4.0 "
        L"initializing"
    );

    if (!HookNativeRegistryWrites()) {
        return FALSE;
    }

    if (!StartUIOrderRegistryWatcher()) {
        return FALSE;
    }

    HMODULE module = GetSystemTrayModuleHandle();

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

    HMODULE module = GetSystemTrayModuleHandle();

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
    StopUIOrderRegistryWatcher();

    Wh_Log(
        L"System Tray Index Analyzer stopped; "
        L"capturedCalls=%llu "
        L"registryNotifications=%llu "
        L"uiOrderWrites=%llu",
        g_updateCallCount.load(
            std::memory_order_relaxed
        ),
        g_registryNotificationCount.load(
            std::memory_order_relaxed
        ),
        g_uiOrderWriteCount.load(
            std::memory_order_relaxed
        )
    );
}
