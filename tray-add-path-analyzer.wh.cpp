// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Audits taskbar.dll symbols that use NotificationAreaIconIdentity.
// @version         0.32.0
// @author          Yusseter
// @github          https://github.com/Yusseter
// @homepage        https://github.com/Yusseter/tray-order-lock
// @license         MIT
// @include         explorer.exe
// @architecture    x86-64
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# Tray Add Path Analyzer

Version 0.32.0 performs a read-only PDB symbol audit for
NotificationAreaIconIdentity.

Version 0.31.0 established the exact signature:

    public: struct NotificationAreaIconIdentity __cdecl
    winrt::WindowsUdk::UI::Shell::implementation::
    NotificationAreaIcon2::Identity(void) const

The method therefore returns a user-defined structure by value. Its contents
and its relationship to the 64-bit NotifyIconSettings/UIOrderList identity
must be understood before the method can be invoked safely in production.

This version enumerates every taskbar.dll symbol whose undecorated or decorated
name contains NotificationAreaIconIdentity.

Long symbol names are emitted in multiple chunks so DbgView does not silently
truncate the information needed to reconstruct their complete signatures.

No discovered function is called or hooked.

This version:

- Installs no taskbar function hooks.
- Calls no NotificationAreaIconIdentity functions.
- Calls no NotificationAreaIcon2::Identity function.
- Moves no tray icons.
- Creates no tray icons.
- Writes no registry values.
- Does not modify tray ordering.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <windhawk_utils.h>

#include <cwchar>

namespace {

constexpr size_t kLogChunkLength =
    600;

bool ContainsText(
    const wchar_t* text,
    const wchar_t* expected
) {
    return
        text &&
        expected &&
        std::wcsstr(
            text,
            expected
        ) !=
        nullptr;
}

bool IsIdentitySymbol(
    const WH_FIND_SYMBOL& symbol
) {
    return
        ContainsText(
            symbol.symbol,
            L"NotificationAreaIconIdentity"
        ) ||
        ContainsText(
            symbol.symbolDecorated,
            L"NotificationAreaIconIdentity"
        );
}

bool IsBridgeCandidate(
    const WH_FIND_SYMBOL& symbol
) {
    const wchar_t* undecorated =
        symbol.symbol;

    if (!undecorated) {
        return false;
    }

    return
        ContainsText(
            undecorated,
            L"NotifyIconSettingsDatabase"
        ) ||
        ContainsText(
            undecorated,
            L"UIOrder"
        ) ||
        ContainsText(
            undecorated,
            L"NotificationAreaIconManager"
        ) ||
        ContainsText(
            undecorated,
            L"NotificationAreaIcon2"
        ) ||
        ContainsText(
            undecorated,
            L"Settings"
        ) ||
        ContainsText(
            undecorated,
            L"operator"
        ) ||
        ContainsText(
            undecorated,
            L"find<"
        );
}

void LogTextChunks(
    unsigned long long matchNumber,
    const wchar_t* field,
    const wchar_t* text
) {
    if (!text) {
        Wh_Log(
            L"IDENTITY_SYMBOL_TEXT "
            L"match=%llu "
            L"field=%s "
            L"chunk=1 "
            L"offset=0 "
            L"final=1 "
            L"text=\"<null>\"",
            matchNumber,
            field
        );

        return;
    }

    const size_t length =
        std::wcslen(
            text
        );

    if (length == 0) {
        Wh_Log(
            L"IDENTITY_SYMBOL_TEXT "
            L"match=%llu "
            L"field=%s "
            L"chunk=1 "
            L"offset=0 "
            L"final=1 "
            L"text=\"\"",
            matchNumber,
            field
        );

        return;
    }

    unsigned long long chunkNumber =
        0;

    for (
        size_t offset = 0;
        offset < length;
        offset += kLogChunkLength
    ) {
        chunkNumber++;

        const size_t remaining =
            length -
            offset;

        const size_t chunkLength =
            remaining <
                    kLogChunkLength
                ? remaining
                : kLogChunkLength;

        wchar_t chunk[
            kLogChunkLength +
            1
        ]{};

        std::wmemcpy(
            chunk,
            text +
                offset,
            chunkLength
        );

        chunk[
            chunkLength
        ] =
            L'\0';

        const bool finalChunk =
            offset +
                chunkLength >=
            length;

        Wh_Log(
            L"IDENTITY_SYMBOL_TEXT "
            L"match=%llu "
            L"field=%s "
            L"chunk=%llu "
            L"offset=%llu "
            L"final=%d "
            L"text=\"%s\"",
            matchNumber,
            field,
            chunkNumber,
            static_cast<unsigned long long>(
                offset
            ),
            finalChunk
                ? 1
                : 0,
            chunk
        );
    }
}

void LogTaskbarModule(
    HMODULE module
) {
    wchar_t modulePath[
        32768
    ]{};

    const DWORD length =
        GetModuleFileNameW(
            module,
            modulePath,
            ARRAYSIZE(
                modulePath
            )
        );

    Wh_Log(
        L"IDENTITY_TYPE_TASKBAR_MODULE "
        L"address=%p "
        L"path=\"%s\"",
        module,
        (
            length != 0 &&
            length <
                ARRAYSIZE(
                    modulePath
                )
        )
            ? modulePath
            : L"<unavailable>"
    );
}

bool RunIdentityTypeAudit(
    HMODULE taskbarModule
) {
    WH_FIND_SYMBOL_OPTIONS options{};

    options.optionsSize =
        sizeof(
            options
        );

    options.symbolServer =
        nullptr;

    options.noUndecoratedSymbols =
        FALSE;

    WH_FIND_SYMBOL symbol{};

    HANDLE search =
        Wh_FindFirstSymbol(
            taskbarModule,
            &options,
            &symbol
        );

    if (!search) {
        Wh_Log(
            L"IDENTITY_TYPE_ENUMERATION_FAILED "
            L"lastError=%lu",
            GetLastError()
        );

        return false;
    }

    unsigned long long scanned =
        0;

    unsigned long long matches =
        0;

    unsigned long long bridgeCandidates =
        0;

    do {
        scanned++;

        if (
            !IsIdentitySymbol(
                symbol
            )
        ) {
            continue;
        }

        matches++;

        const bool bridgeCandidate =
            IsBridgeCandidate(
                symbol
            );

        if (bridgeCandidate) {
            bridgeCandidates++;
        }

        Wh_Log(
            L"IDENTITY_SYMBOL_BEGIN "
            L"match=%llu "
            L"address=%p "
            L"bridgeCandidate=%d",
            matches,
            symbol.address,
            bridgeCandidate
                ? 1
                : 0
        );

        LogTextChunks(
            matches,
            L"undecorated",
            symbol.symbol
        );

        LogTextChunks(
            matches,
            L"decorated",
            symbol.symbolDecorated
        );

        Wh_Log(
            L"IDENTITY_SYMBOL_END "
            L"match=%llu",
            matches
        );
    } while (
        Wh_FindNextSymbol(
            search,
            &symbol
        )
    );

    Wh_FindCloseSymbol(
        search
    );

    Wh_Log(
        L"IDENTITY_TYPE_SUMMARY "
        L"scanned=%llu "
        L"matches=%llu "
        L"bridgeCandidates=%llu",
        scanned,
        matches,
        bridgeCandidates
    );

    return
        matches !=
        0;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Add Path Analyzer 0.32.0 initializing "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    HMODULE taskbarModule =
        GetModuleHandleW(
            L"taskbar.dll"
        );

    if (!taskbarModule) {
        Wh_Log(
            L"IDENTITY_TYPE_TASKBAR_NOT_READY "
            L"processId=%lu",
            GetCurrentProcessId()
        );

        return FALSE;
    }

    LogTaskbarModule(
        taskbarModule
    );

    const bool succeeded =
        RunIdentityTypeAudit(
            taskbarModule
        );

    Wh_Log(
        L"IDENTITY_TYPE_AUDIT_COMPLETE "
        L"processId=%lu "
        L"succeeded=%d",
        GetCurrentProcessId(),
        succeeded
            ? 1
            : 0
    );

    return
        succeeded
            ? TRUE
            : FALSE;
}

void Wh_ModUninit() {
    Wh_Log(
        L"Tray Add Path Analyzer 0.32.0 stopped "
        L"processId=%lu",
        GetCurrentProcessId()
    );
}
