// ==WindhawkMod==
// @id              tray-order-lock-analyzer
// @name            Tray Order Lock Analyzer
// @description     Logs notification icon registrations to research stable cross-update tray identities.
// @version         0.2.0
// @author          Yusseter
// @github          https://github.com/Yusseter
// @homepage        https://github.com/Yusseter/windhawk-tray-order-lock
// @license         MIT
// @include         *
// @exclude         csrss.exe
// @exclude         smss.exe
// @exclude         wininit.exe
// @exclude         winlogon.exe
// @exclude         services.exe
// @exclude         lsass.exe
// @exclude         dwm.exe
// @compilerOptions -lversion
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# Tray Order Lock Analyzer

Logs `Shell_NotifyIconW` and `Shell_NotifyIconA` calls with process, package,
version-resource, window, UID, GUID, flags and tooltip information.

Version 0.2.0 writes to Windhawk's live log and to UTF-16 process logs under
`%LOCALAPPDATA%\TrayOrderLockAnalyzer`. It does not modify notification icons.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <appmodel.h>
#include <shellapi.h>
#include <windhawk_utils.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace {

using Shell_NotifyIconW_t = decltype(&Shell_NotifyIconW);
using Shell_NotifyIconA_t = decltype(&Shell_NotifyIconA);

Shell_NotifyIconW_t Shell_NotifyIconW_Original = nullptr;
Shell_NotifyIconA_t Shell_NotifyIconA_Original = nullptr;

std::wstring GetProcessPath() {
    std::wstring path(32768, L'\0');
    DWORD length = GetModuleFileNameW(nullptr, path.data(), path.size());
    if (!length || length >= path.size()) {
        return L"<unknown>";
    }

    path.resize(length);
    return path;
}

std::wstring GetBaseName(const std::wstring& path) {
    size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

std::wstring GetPackageFamily() {
    UINT32 length = 0;
    LONG result = GetPackageFamilyName(GetCurrentProcess(), &length, nullptr);
    if (result == APPMODEL_ERROR_NO_PACKAGE) {
        return L"<none>";
    }

    if (result != ERROR_INSUFFICIENT_BUFFER || length == 0) {
        return L"<unknown>";
    }

    std::wstring family(length, L'\0');
    result = GetPackageFamilyName(GetCurrentProcess(), &length, family.data());
    if (result != ERROR_SUCCESS) {
        return L"<unknown>";
    }

    if (!family.empty() && family.back() == L'\0') {
        family.pop_back();
    }

    return family.empty() ? L"<none>" : family;
}

struct VersionStrings {
    std::wstring company = L"<none>";
    std::wstring product = L"<none>";
};

VersionStrings GetVersionStrings(const std::wstring& path) {
    VersionStrings result;
    DWORD ignored = 0;
    DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (!size) {
        return result;
    }

    std::vector<BYTE> buffer(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, buffer.data())) {
        return result;
    }

    struct LanguageAndCodePage {
        WORD language;
        WORD codePage;
    };

    LanguageAndCodePage* translations = nullptr;
    UINT translationsSize = 0;
    if (!VerQueryValueW(
            buffer.data(),
            L"\\VarFileInfo\\Translation",
            reinterpret_cast<void**>(&translations),
            &translationsSize) ||
        translationsSize < sizeof(LanguageAndCodePage)) {
        return result;
    }

    auto query = [&](const wchar_t* key) -> std::wstring {
        wchar_t queryPath[128]{};
        _snwprintf_s(
            queryPath,
            ARRAYSIZE(queryPath),
            _TRUNCATE,
            L"\\StringFileInfo\\%04x%04x\\%s",
            translations[0].language,
            translations[0].codePage,
            key
        );

        wchar_t* value = nullptr;
        UINT valueLength = 0;
        if (!VerQueryValueW(
                buffer.data(),
                queryPath,
                reinterpret_cast<void**>(&value),
                &valueLength) ||
            !value || valueLength == 0) {
            return L"<none>";
        }

        return value;
    };

    result.company = query(L"CompanyName");
    result.product = query(L"ProductName");
    return result;
}

std::wstring GetWindowClass(HWND window) {
    if (!window) {
        return L"";
    }

    wchar_t text[512]{};
    int length = GetClassNameW(window, text, ARRAYSIZE(text));
    return length > 0 ? std::wstring(text, length) : L"";
}

std::wstring GetWindowTitle(HWND window) {
    if (!window) {
        return L"";
    }

    wchar_t text[512]{};
    int length = GetWindowTextW(window, text, ARRAYSIZE(text));
    return length > 0 ? std::wstring(text, length) : L"";
}

std::wstring GuidText(const GUID& guid) {
    wchar_t text[64]{};
    _snwprintf_s(
        text,
        ARRAYSIZE(text),
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
    return text;
}

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

std::wstring AnsiToWide(const char* text) {
    if (!text || !*text) {
        return L"";
    }

    int length = MultiByteToWideChar(CP_ACP, 0, text, -1, nullptr, 0);
    if (length <= 1) {
        return L"";
    }

    std::wstring result(length, L'\0');
    if (!MultiByteToWideChar(CP_ACP, 0, text, -1, result.data(), length)) {
        return L"";
    }

    if (!result.empty() && result.back() == L'\0') {
        result.pop_back();
    }

    return result;
}

std::wstring EscapeText(const std::wstring& value) {
    std::wstring escaped;
    escaped.reserve(value.size());
    for (wchar_t ch : value) {
        switch (ch) {
            case L'\\':
                escaped += L"\\\\";
                break;
            case L'\r':
                escaped += L"\\r";
                break;
            case L'\n':
                escaped += L"\\n";
                break;
            case L'\t':
                escaped += L"\\t";
                break;
            case L'\"':
                escaped += L"\\\"";
                break;
            default:
                escaped += ch;
                break;
        }
    }
    return escaped;
}

std::wstring BuildEventLine(
    const wchar_t* api,
    DWORD message,
    HWND window,
    UINT uid,
    UINT flags,
    UINT callbackMessage,
    DWORD cbSize,
    bool hasGuid,
    const GUID& guid,
    const std::wstring& tooltip
) {
    const std::wstring processPath = GetProcessPath();
    const std::wstring processName = GetBaseName(processPath);
    const std::wstring packageFamily = GetPackageFamily();
    const VersionStrings version = GetVersionStrings(processPath);
    const std::wstring windowClass = GetWindowClass(window);
    const std::wstring windowTitle = GetWindowTitle(window);
    const std::wstring guidString = hasGuid ? GuidText(guid) : L"<none>";

    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    wchar_t prefix[1024]{};
    _snwprintf_s(
        prefix,
        ARRAYSIZE(prefix),
        _TRUNCATE,
        L"TRAY_EVENT api=%s event=%s pid=%lu session=%lu exe=\"%s\" ",
        api,
        NotifyMessageName(message),
        GetCurrentProcessId(),
        sessionId,
        EscapeText(processName).c_str()
    );

    std::wstring line = prefix;
    line += L"path=\"" + EscapeText(processPath) + L"\" ";
    line += L"package=\"" + EscapeText(packageFamily) + L"\" ";
    line += L"company=\"" + EscapeText(version.company) + L"\" ";
    line += L"product=\"" + EscapeText(version.product) + L"\" ";

    wchar_t numeric[512]{};
    _snwprintf_s(
        numeric,
        ARRAYSIZE(numeric),
        _TRUNCATE,
        L"hwnd=%p class=\"%s\" title=\"%s\" uid=%u flags=0x%08X "
        L"callback=0x%08X cbSize=%lu hasGuid=%d guid=\"%s\" tooltip=\"%s\"",
        window,
        EscapeText(windowClass).c_str(),
        EscapeText(windowTitle).c_str(),
        uid,
        flags,
        callbackMessage,
        cbSize,
        hasGuid ? 1 : 0,
        guidString.c_str(),
        EscapeText(tooltip).c_str()
    );

    line += numeric;
    return line;
}

std::mutex g_logMutex;
HANDLE g_logFile = INVALID_HANDLE_VALUE;
std::once_flag g_logInitOnce;

void InitializePersistentLog() {
    wchar_t localAppData[32768]{};
    DWORD length = GetEnvironmentVariableW(
        L"LOCALAPPDATA",
        localAppData,
        ARRAYSIZE(localAppData)
    );

    if (!length || length >= ARRAYSIZE(localAppData)) {
        return;
    }

    std::wstring directory = localAppData;
    directory += L"\\TrayOrderLockAnalyzer";
    CreateDirectoryW(directory.c_str(), nullptr);

    SYSTEMTIME now{};
    GetLocalTime(&now);

    std::wstring processName = GetBaseName(GetProcessPath());
    for (wchar_t& ch : processName) {
        if (ch == L'\\' || ch == L'/' || ch == L':' || ch == L'*' ||
            ch == L'?' || ch == L'\"' || ch == L'<' || ch == L'>' ||
            ch == L'|') {
            ch = L'_';
        }
    }

    wchar_t fileName[512]{};
    _snwprintf_s(
        fileName,
        ARRAYSIZE(fileName),
        _TRUNCATE,
        L"\\events-%04u%02u%02u-%02u%02u%02u-%lu-%s.log",
        now.wYear,
        now.wMonth,
        now.wDay,
        now.wHour,
        now.wMinute,
        now.wSecond,
        GetCurrentProcessId(),
        processName.c_str()
    );

    std::wstring path = directory + fileName;
    g_logFile = CreateFileW(
        path.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (g_logFile == INVALID_HANDLE_VALUE) {
        return;
    }

    LARGE_INTEGER size{};
    if (GetFileSizeEx(g_logFile, &size) && size.QuadPart == 0) {
        const wchar_t bom = 0xFEFF;
        DWORD written = 0;
        WriteFile(g_logFile, &bom, sizeof(bom), &written, nullptr);
    }

    Wh_Log(L"Persistent log: %s", path.c_str());
}

void AppendPersistentLine(const std::wstring& line) {
    std::call_once(g_logInitOnce, InitializePersistentLog);
    if (g_logFile == INVALID_HANDLE_VALUE) {
        return;
    }

    std::wstring output = line + L"\r\n";
    std::lock_guard<std::mutex> lock(g_logMutex);

    DWORD written = 0;
    WriteFile(
        g_logFile,
        output.data(),
        static_cast<DWORD>(output.size() * sizeof(wchar_t)),
        &written,
        nullptr
    );
}

void ClosePersistentLog() {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_logFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
    }
}

void RecordEvent(
    const wchar_t* api,
    DWORD message,
    HWND window,
    UINT uid,
    UINT flags,
    UINT callbackMessage,
    DWORD cbSize,
    bool hasGuid,
    const GUID& guid,
    const std::wstring& tooltip
) {
    std::wstring line = BuildEventLine(
        api,
        message,
        window,
        uid,
        flags,
        callbackMessage,
        cbSize,
        hasGuid,
        guid,
        tooltip
    );

    Wh_Log(L"%s", line.c_str());
    AppendPersistentLine(line);
}

BOOL WINAPI Shell_NotifyIconW_Hook(
    DWORD message,
    PNOTIFYICONDATAW data
) {
    if (data) {
        bool hasGuid =
            data->cbSize >= offsetof(NOTIFYICONDATAW, guidItem) + sizeof(GUID) &&
            (data->uFlags & NIF_GUID) != 0;

        RecordEvent(
            L"W",
            message,
            data->hWnd,
            data->uID,
            data->uFlags,
            data->uCallbackMessage,
            data->cbSize,
            hasGuid,
            hasGuid ? data->guidItem : GUID{},
            data->szTip
        );
    }

    return Shell_NotifyIconW_Original(message, data);
}

BOOL WINAPI Shell_NotifyIconA_Hook(
    DWORD message,
    PNOTIFYICONDATAA data
) {
    if (data) {
        bool hasGuid =
            data->cbSize >= offsetof(NOTIFYICONDATAA, guidItem) + sizeof(GUID) &&
            (data->uFlags & NIF_GUID) != 0;

        RecordEvent(
            L"A",
            message,
            data->hWnd,
            data->uID,
            data->uFlags,
            data->uCallbackMessage,
            data->cbSize,
            hasGuid,
            hasGuid ? data->guidItem : GUID{},
            AnsiToWide(data->szTip)
        );
    }

    return Shell_NotifyIconA_Original(message, data);
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
    Wh_Log(L"Tray Order Lock Analyzer initializing");
    return HookShellNotifyIconFunctions();
}

void Wh_ModUninit() {
    ClosePersistentLog();
    Wh_Log(L"Tray Order Lock Analyzer stopped");
}
