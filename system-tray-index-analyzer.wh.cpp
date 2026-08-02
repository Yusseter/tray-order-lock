// ==WindhawkMod==
// @id              system-tray-index-analyzer
// @name            System Tray Index Analyzer
// @description     Logs SystemTray index updates and read-only UIOrderList snapshots.
// @version         0.2.0
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

For every call, it records:

- Call number
- Thread ID
- StackViewModel address
- UIOrderList byte length before and after the original function
- UIOrderList entry count before and after the original function
- A 64-bit FNV-1a hash of UIOrderList before and after the original function
- Whether the two snapshots differ

The mod only reads:

    HKCU\Control Panel\NotifyIconSettings\UIOrderList

It does not modify tray icons, tray ordering, registry values, XAML elements,
function arguments or original return behavior.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <windhawk_utils.h>

#include <atomic>
#include <cstdint>
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
        L"System Tray Index Analyzer 0.2.0 "
        L"initializing"
    );

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

            return FALSE;
        }

        return TRUE;
    }

    Wh_Log(
        L"SystemTray.dll is not loaded yet; "
        L"waiting for module load"
    );

    return HookModuleLoader();
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
    Wh_Log(
        L"System Tray Index Analyzer stopped; "
        L"capturedCalls=%llu",
        g_updateCallCount.load(
            std::memory_order_relaxed
        )
    );
}
