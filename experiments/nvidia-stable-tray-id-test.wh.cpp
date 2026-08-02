// ==WindhawkMod==
// @id              nvidia-stable-tray-id-test
// @name            NVIDIA Stable Tray ID Test
// @description     Assigns a shared fixed notification icon GUID to NVIDIA tray icon hosts.
// @version         0.2.0
// @author          Yusseter
// @github          https://github.com/Yusseter
// @homepage        https://github.com/Yusseter/windhawk-tray-order-lock
// @license         MIT
// @include         nvcontainer.exe
// @include         NVDisplay.Container.exe
// @architecture    x86-64
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# NVIDIA Stable Tray ID Test

A focused experiment that gives the NVIDIA Settings icon the same fixed GUID
whether it is hosted by `nvcontainer.exe` or `NVDisplay.Container.exe`.

The target icon uses UID `1051` and GUID
`{98A75E36-6078-4BC0-A312-93989E8E9A31}`.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <shellapi.h>
#include <windhawk_utils.h>

#include <algorithm>
#include <cstddef>
#include <cstring>

namespace {

const wchar_t* NotifyMessageName(DWORD message) {
    switch (message) {
        case NIM_ADD:
            return L"NIM_ADD";
        case NIM_MODIFY:
            return L"NIM_MODIFY";
        case NIM_DELETE:
            return L"NIM_DELETE";
        case NIM_SETFOCUS:
            return L"NIM_SETFOCUS";
        case NIM_SETVERSION:
            return L"NIM_SETVERSION";
        default:
            return L"UNKNOWN";
    }
}

void FormatGuid(const GUID& guid, wchar_t* buffer, size_t bufferLength) {
    if (!buffer || bufferLength == 0) {
        return;
    }

    _snwprintf_s(
        buffer,
        bufferLength,
        _TRUNCATE,
        L"{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
        guid.Data1,
        guid.Data2,
        guid.Data3,
        guid.Data4[0],
        guid.Data4[1],
        guid.Data4[2],
        guid.Data4[3],
        guid.Data4[4],
        guid.Data4[5],
        guid.Data4[6],
        guid.Data4[7]
    );
}

template <typename T>
bool CopyNotifyIconData(const T* source, T* destination) {
    if (!source || !destination || source->cbSize == 0) {
        return false;
    }

    std::memset(destination, 0, sizeof(*destination));
    std::memcpy(
        destination,
        source,
        std::min<size_t>(source->cbSize, sizeof(*destination))
    );

    return source->cbSize >=
        offsetof(T, guidItem) + sizeof(destination->guidItem);
}

}  // namespace

namespace {

constexpr UINT kTargetUid = 1051;
constexpr GUID kStableGuid = {
    0x98A75E36,
    0x6078,
    0x4BC0,
    {0xA3, 0x12, 0x93, 0x98, 0x9E, 0x8E, 0x9A, 0x31}
};

using Shell_NotifyIconW_t = decltype(&Shell_NotifyIconW);
using Shell_NotifyIconA_t = decltype(&Shell_NotifyIconA);

Shell_NotifyIconW_t Shell_NotifyIconW_Original = nullptr;
Shell_NotifyIconA_t Shell_NotifyIconA_Original = nullptr;

BOOL WINAPI Shell_NotifyIconW_Hook(
    DWORD message,
    PNOTIFYICONDATAW data
) {
    if (!data || data->uID != kTargetUid) {
        return Shell_NotifyIconW_Original(message, data);
    }

    NOTIFYICONDATAW patched{};
    if (!CopyNotifyIconData(data, &patched)) {
        return Shell_NotifyIconW_Original(message, data);
    }

    patched.uFlags |= NIF_GUID;
    patched.guidItem = kStableGuid;

    BOOL result = Shell_NotifyIconW_Original(message, &patched);

    wchar_t guidText[64]{};
    FormatGuid(kStableGuid, guidText, ARRAYSIZE(guidText));
    Wh_Log(
        L"Shell_NotifyIconW: message=%s, uID=%u, GUID=%s, result=%d",
        NotifyMessageName(message),
        patched.uID,
        guidText,
        result
    );

    return result;
}

BOOL WINAPI Shell_NotifyIconA_Hook(
    DWORD message,
    PNOTIFYICONDATAA data
) {
    if (!data || data->uID != kTargetUid) {
        return Shell_NotifyIconA_Original(message, data);
    }

    NOTIFYICONDATAA patched{};
    if (!CopyNotifyIconData(data, &patched)) {
        return Shell_NotifyIconA_Original(message, data);
    }

    patched.uFlags |= NIF_GUID;
    patched.guidItem = kStableGuid;

    BOOL result = Shell_NotifyIconA_Original(message, &patched);

    wchar_t guidText[64]{};
    FormatGuid(kStableGuid, guidText, ARRAYSIZE(guidText));
    Wh_Log(
        L"Shell_NotifyIconA: message=%s, uID=%u, GUID=%s, result=%d",
        NotifyMessageName(message),
        patched.uID,
        guidText,
        result
    );

    return result;
}

bool HookShellNotifyIconFunctions() {
    HMODULE shell32 = GetModuleHandleW(L"shell32.dll");
    if (!shell32) {
        shell32 = LoadLibraryW(L"shell32.dll");
    }

    if (!shell32) {
        Wh_Log(L"shell32.dll is unavailable");
        return false;
    }

    auto shellNotifyIconW = reinterpret_cast<Shell_NotifyIconW_t>(
        GetProcAddress(shell32, "Shell_NotifyIconW")
    );
    auto shellNotifyIconA = reinterpret_cast<Shell_NotifyIconA_t>(
        GetProcAddress(shell32, "Shell_NotifyIconA")
    );

    bool hooked = false;

    if (shellNotifyIconW) {
        hooked |= WindhawkUtils::Wh_SetFunctionHookT(
            shellNotifyIconW,
            Shell_NotifyIconW_Hook,
            &Shell_NotifyIconW_Original
        );
    }

    if (shellNotifyIconA) {
        hooked |= WindhawkUtils::Wh_SetFunctionHookT(
            shellNotifyIconA,
            Shell_NotifyIconA_Hook,
            &Shell_NotifyIconA_Original
        );
    }

    return hooked;
}

}  // namespace

BOOL Wh_ModInit() {
    DWORD sessionId = 0;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &sessionId) && sessionId == 0) {
        Wh_Log(L"Skipping the NVIDIA service process in session 0");
        return FALSE;
    }

    Wh_Log(L"NVIDIA Stable Tray ID Test initializing");
    return HookShellNotifyIconFunctions();
}

void Wh_ModUninit() {
    Wh_Log(L"NVIDIA Stable Tray ID Test stopped");
}
