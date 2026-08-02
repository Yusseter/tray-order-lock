// ==WindhawkMod==
// @id              stable-tray-icons
// @name            Stable Tray Icons
// @description     Assigns stable GUIDs to selected notification icons whose executable paths or hosts change.
// @version         0.1.0
// @author          Yusseter
// @github          https://github.com/Yusseter
// @homepage        https://github.com/Yusseter/windhawk-tray-order-lock
// @license         MIT
// @include         ChatGPT.exe
// @include         nvcontainer.exe
// @include         NVDisplay.Container.exe
// @architecture    x86-64
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# Stable Tray Icons

Combines the verified ChatGPT and NVIDIA experiments into one mod.

- ChatGPT: UID `3`, GUID `{773D7384-708C-46ED-8B56-7BE424DB3C0C}`
- NVIDIA Settings: UID `1051`, GUID
  `{98A75E36-6078-4BC0-A312-93989E8E9A31}`

This is an app-identity workaround, not a complete tray-order lock.
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

#include <string>
#include <vector>

namespace {

struct TrayRule {
    const wchar_t* name;
    UINT uid;
    GUID guid;
};

std::vector<TrayRule> g_rules;
std::wstring g_processPath;

using Shell_NotifyIconW_t = decltype(&Shell_NotifyIconW);
using Shell_NotifyIconA_t = decltype(&Shell_NotifyIconA);

Shell_NotifyIconW_t Shell_NotifyIconW_Original = nullptr;
Shell_NotifyIconA_t Shell_NotifyIconA_Original = nullptr;

std::wstring GetCurrentProcessPath() {
    std::wstring path(32768, L'\0');
    DWORD length = GetModuleFileNameW(nullptr, path.data(), path.size());
    if (!length || length >= path.size()) {
        return L"<unknown>";
    }

    path.resize(length);
    return path;
}

const wchar_t* BaseName(const std::wstring& path) {
    const wchar_t* slash = wcsrchr(path.c_str(), L'\\');
    return slash ? slash + 1 : path.c_str();
}

void LoadSettings() {
    g_rules.clear();
    g_processPath = GetCurrentProcessPath();

    const wchar_t* processName = BaseName(g_processPath);

    if (_wcsicmp(processName, L"ChatGPT.exe") == 0) {
        g_rules.push_back({
            L"ChatGPT",
            3,
            {
                0x773D7384,
                0x708C,
                0x46ED,
                {0x8B, 0x56, 0x7B, 0xE4, 0x24, 0xDB, 0x3C, 0x0C}
            }
        });
    } else if (_wcsicmp(processName, L"nvcontainer.exe") == 0) {
        g_rules.push_back({
            L"NVIDIA Settings - User Container",
            1051,
            {
                0x98A75E36,
                0x6078,
                0x4BC0,
                {0xA3, 0x12, 0x93, 0x98, 0x9E, 0x8E, 0x9A, 0x31}
            }
        });
    } else if (_wcsicmp(processName, L"NVDisplay.Container.exe") == 0) {
        g_rules.push_back({
            L"NVIDIA Settings - Display Container",
            1051,
            {
                0x98A75E36,
                0x6078,
                0x4BC0,
                {0xA3, 0x12, 0x93, 0x98, 0x9E, 0x8E, 0x9A, 0x31}
            }
        });
    }

    Wh_Log(
        L"Loaded %zu rule(s) for process: %s",
        g_rules.size(),
        g_processPath.c_str()
    );
}

const TrayRule* FindRule(UINT uid) {
    for (const auto& rule : g_rules) {
        if (rule.uid == uid) {
            return &rule;
        }
    }

    return nullptr;
}

void LogPatchedCall(
    const wchar_t* api,
    const TrayRule& rule,
    DWORD message,
    BOOL result
) {
    wchar_t guidText[64]{};
    FormatGuid(rule.guid, guidText, ARRAYSIZE(guidText));

    Wh_Log(
        L"%s: rule=\"%s\", message=%s, uID=%u, GUID=%s, result=%d",
        api,
        rule.name,
        NotifyMessageName(message),
        rule.uid,
        guidText,
        result
    );
}

BOOL WINAPI Shell_NotifyIconW_Hook(
    DWORD message,
    PNOTIFYICONDATAW data
) {
    const TrayRule* rule = data ? FindRule(data->uID) : nullptr;
    if (!rule) {
        return Shell_NotifyIconW_Original(message, data);
    }

    NOTIFYICONDATAW patched{};
    if (!CopyNotifyIconData(data, &patched)) {
        return Shell_NotifyIconW_Original(message, data);
    }

    patched.uFlags |= NIF_GUID;
    patched.guidItem = rule->guid;

    BOOL result = Shell_NotifyIconW_Original(message, &patched);
    LogPatchedCall(L"Shell_NotifyIconW", *rule, message, result);
    return result;
}

BOOL WINAPI Shell_NotifyIconA_Hook(
    DWORD message,
    PNOTIFYICONDATAA data
) {
    const TrayRule* rule = data ? FindRule(data->uID) : nullptr;
    if (!rule) {
        return Shell_NotifyIconA_Original(message, data);
    }

    NOTIFYICONDATAA patched{};
    if (!CopyNotifyIconData(data, &patched)) {
        return Shell_NotifyIconA_Original(message, data);
    }

    patched.uFlags |= NIF_GUID;
    patched.guidItem = rule->guid;

    BOOL result = Shell_NotifyIconA_Original(message, &patched);
    LogPatchedCall(L"Shell_NotifyIconA", *rule, message, result);
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
        return FALSE;
    }

    LoadSettings();
    if (g_rules.empty()) {
        return FALSE;
    }

    return HookShellNotifyIconFunctions();
}

void Wh_ModUninit() {
    Wh_Log(L"Stable Tray Icons stopped");
}
