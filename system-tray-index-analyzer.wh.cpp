// ==WindhawkMod==
// @id              system-tray-index-analyzer
// @name            System Tray Index Analyzer
// @description     Logs SystemTray StackViewModel index updates without modifying tray state.
// @version         0.1.0
// @author          Yusseter
// @github          https://github.com/Yusseter
// @homepage        https://github.com/Yusseter/windhawk-tray-order-lock
// @license         MIT
// @include         explorer.exe
// @architecture    x86-64
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# System Tray Index Analyzer

A temporary diagnostic mod for researching notification-area icon ordering.

The mod hooks:

    winrt::SystemTray::implementation::StackViewModel::UpdateIconIndexes()

It records when the function is called and does not modify tray icons, ordering,
`UIOrderList`, `NotifyIconSettings`, XAML elements, arguments or return behavior.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <windhawk_utils.h>

#include <atomic>

namespace {

std::atomic<bool> g_systemTrayModuleHooked = false;
std::atomic<unsigned long long> g_updateCallCount = 0;

using StackViewModel_UpdateIconIndexes_t = void(WINAPI*)(void* pThis);

StackViewModel_UpdateIconIndexes_t
    StackViewModel_UpdateIconIndexes_Original = nullptr;

void LogModuleInformation(HMODULE module) {
    wchar_t modulePath[MAX_PATH]{};

    DWORD length = GetModuleFileNameW(
        module,
        modulePath,
        ARRAYSIZE(modulePath)
    );

    if (length == 0 || length >= ARRAYSIZE(modulePath)) {
        Wh_Log(L"System tray module=%p, path unavailable", module);
        return;
    }

    Wh_Log(L"System tray module=%p, path=\"%s\"", module, modulePath);
}

void WINAPI StackViewModel_UpdateIconIndexes_Hook(void* pThis) {
    unsigned long long callNumber =
        g_updateCallCount.fetch_add(1, std::memory_order_relaxed) + 1;

    DWORD threadId = GetCurrentThreadId();

    Wh_Log(
        L"INDEX_UPDATE_BEGIN call=%llu thread=%lu this=%p",
        callNumber,
        threadId,
        pThis
    );

    StackViewModel_UpdateIconIndexes_Original(pThis);

    Wh_Log(
        L"INDEX_UPDATE_END call=%llu thread=%lu this=%p",
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

    if (!WindhawkUtils::HookSymbols(module, symbolHooks, ARRAYSIZE(symbolHooks))) {
        Wh_Log(L"Failed to locate or hook StackViewModel::UpdateIconIndexes");
        return false;
    }

    LogModuleInformation(module);
    Wh_Log(L"StackViewModel::UpdateIconIndexes hook installed");
    return true;
}

HMODULE GetSystemTrayModuleHandle() {
    HMODULE module = GetModuleHandleW(L"SystemTray.dll");
    if (module) {
        return module;
    }

    return GetModuleHandleW(L"Taskbar.View.dll");
}

void HandleLoadedModule(HMODULE module, LPCWSTR requestedPath) {
    if (!module || g_systemTrayModuleHooked.load(std::memory_order_acquire)) {
        return;
    }

    HMODULE systemTrayModule = GetSystemTrayModuleHandle();
    if (!systemTrayModule || systemTrayModule != module) {
        return;
    }

    bool expected = false;
    if (!g_systemTrayModuleHooked.compare_exchange_strong(
            expected,
            true,
            std::memory_order_acq_rel)) {
        return;
    }

    Wh_Log(
        L"Detected system tray module load: requestedPath=\"%s\"",
        requestedPath ? requestedPath : L"<null>"
    );

    if (!HookSystemTraySymbols(module)) {
        g_systemTrayModuleHooked.store(false, std::memory_order_release);
        return;
    }

    Wh_ApplyHookOperations();
}

using LoadLibraryExW_t = decltype(&LoadLibraryExW);
LoadLibraryExW_t LoadLibraryExW_Original = nullptr;

HMODULE WINAPI LoadLibraryExW_Hook(
    LPCWSTR libraryPath,
    HANDLE file,
    DWORD flags
) {
    HMODULE module = LoadLibraryExW_Original(libraryPath, file, flags);
    if (module) {
        HandleLoadedModule(module, libraryPath);
    }

    return module;
}

bool HookModuleLoader() {
    HMODULE kernelBase = GetModuleHandleW(L"kernelbase.dll");
    if (!kernelBase) {
        Wh_Log(L"kernelbase.dll is unavailable");
        return false;
    }

    auto loadLibraryExW = reinterpret_cast<decltype(&LoadLibraryExW)>(
        GetProcAddress(kernelBase, "LoadLibraryExW")
    );

    if (!loadLibraryExW) {
        Wh_Log(L"LoadLibraryExW is unavailable");
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
    Wh_Log(L"System Tray Index Analyzer initializing");

    HMODULE module = GetSystemTrayModuleHandle();
    if (module) {
        g_systemTrayModuleHooked.store(true, std::memory_order_release);
        return HookSystemTraySymbols(module);
    }

    Wh_Log(L"SystemTray.dll is not loaded yet; waiting for module load");
    return HookModuleLoader();
}

void Wh_ModAfterInit() {
    if (g_systemTrayModuleHooked.load(std::memory_order_acquire)) {
        return;
    }

    HMODULE module = GetSystemTrayModuleHandle();
    if (!module) {
        return;
    }

    bool expected = false;
    if (!g_systemTrayModuleHooked.compare_exchange_strong(
            expected,
            true,
            std::memory_order_acq_rel)) {
        return;
    }

    Wh_Log(L"System tray module found after initialization");

    if (HookSystemTraySymbols(module)) {
        Wh_ApplyHookOperations();
    } else {
        g_systemTrayModuleHooked.store(false, std::memory_order_release);
    }
}

void Wh_ModUninit() {
    Wh_Log(
        L"System Tray Index Analyzer stopped; capturedCalls=%llu",
        g_updateCallCount.load(std::memory_order_relaxed)
    );
}
