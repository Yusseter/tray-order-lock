// ==WindhawkMod==
// @id              chatgpt-stable-tray-id-test
// @name            ChatGPT Stable Tray ID Test
// @description     Assigns a fixed notification icon GUID to ChatGPT for update-stability testing.
// @version         0.2.0
// @author          Yusseter
// @github          https://github.com/Yusseter
// @homepage        https://github.com/Yusseter/windhawk-tray-order-lock
// @license         MIT
// @include         ChatGPT.exe
// @architecture    x86-64
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# ChatGPT Stable Tray ID Test

A focused experiment that assigns a fixed GUID to the ChatGPT notification-area
icon. The goal is to prevent a packaged-app update path from creating a new tray
identity and moving the icon.

The target icon uses UID `3` and GUID
`{773D7384-708C-46ED-8B56-7BE424DB3C0C}`.
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

constexpr UINT kTargetUid = 3;
constexpr GUID kStableGuid = {
    0x773D7384,
    0x708C,
    0x46ED,
    {0x8B, 0x56, 0x7B, 0xE4, 0x24, 0xDB, 0x3C, 0x0C}
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
    Wh_Log(L"ChatGPT Stable Tray ID Test initializing");
    return HookShellNotifyIconFunctions();
}

void Wh_ModUninit() {
    Wh_Log(L"ChatGPT Stable Tray ID Test stopped");
}
