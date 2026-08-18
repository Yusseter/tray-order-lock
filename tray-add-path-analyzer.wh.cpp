// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Enumerates the exact NotificationAreaIcon2 identity symbol signatures without invoking them.
// @version         0.31.0
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

Version 0.31.0 performs a read-only symbol-signature audit for the live
notification-area icon identity path.

The production Tray Order Lock needs to map:

    live NotificationAreaIcon2 implementation
        -> INotificationAreaIcon ABI pointer
        -> Windows NotifyIconSettings identity
        -> persistent logical identity

The implementation-to-ABI conversion has already been validated through the
NotificationAreaIcon2 query-interface path.

A NotificationAreaIcon2::Identity() symbol was also observed during the earlier
taskbar.dll symbol audit. However, its return ABI has not been validated. The
function must therefore not be called or hooked based on an assumed prototype.

This version enumerates Microsoft taskbar.dll symbols and reports every symbol
whose name refers to NotificationAreaIcon2 identity information.

For each match it records:

- Symbol address.
- Full undecorated symbol text.
- Decorated symbol name, when available.

This allows the exact PDB-visible function signature and return type to be
established before any runtime invocation is attempted.

This version:

- Installs no taskbar function hooks.
- Calls no NotificationAreaIcon2 identity function.
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

bool IsRelevantIdentitySymbol(
    const wchar_t* symbol
) {
    if (!symbol) {
        return false;
    }

    const bool notificationAreaIcon2 =
        ContainsText(
            symbol,
            L"NotificationAreaIcon2"
        );

    if (!notificationAreaIcon2) {
        return false;
    }

    return
        ContainsText(
            symbol,
            L"Identity"
        ) ||
        ContainsText(
            symbol,
            L"identity"
        );
}

bool IsRelevantDecoratedSymbol(
    const wchar_t* symbol
) {
    if (!symbol) {
        return false;
    }

    // Decorated C++ names don't necessarily preserve readable class/member
    // spelling in exactly the same form. Keep this as a supplementary check;
    // the undecorated PDB symbol remains the primary selector.
    return
        ContainsText(
            symbol,
            L"NotificationAreaIcon2"
        ) &&
        (
            ContainsText(
                symbol,
                L"Identity"
            ) ||
            ContainsText(
                symbol,
                L"identity"
            )
        );
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
        L"IDENTITY_SIGNATURE_TASKBAR_MODULE "
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

bool RunIdentitySignatureAudit(
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
            L"IDENTITY_SIGNATURE_ENUMERATION_FAILED "
            L"lastError=%lu",
            GetLastError()
        );

        return false;
    }

    unsigned long long scanned =
        0;

    unsigned long long matches =
        0;

    do {
        scanned++;

        const bool relevantUndecorated =
            IsRelevantIdentitySymbol(
                symbol.symbol
            );

        const bool relevantDecorated =
            IsRelevantDecoratedSymbol(
                symbol.symbolDecorated
            );

        if (
            !relevantUndecorated &&
            !relevantDecorated
        ) {
            continue;
        }

        matches++;

        Wh_Log(
            L"IDENTITY_SIGNATURE_MATCH "
            L"match=%llu "
            L"address=%p "
            L"undecorated=\"%s\" "
            L"decorated=\"%s\"",
            matches,
            symbol.address,
            symbol.symbol
                ? symbol.symbol
                : L"<null>",
            symbol.symbolDecorated
                ? symbol.symbolDecorated
                : L"<null>"
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
        L"IDENTITY_SIGNATURE_SUMMARY "
        L"scanned=%llu "
        L"matches=%llu",
        scanned,
        matches
    );

    return
        matches !=
        0;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Add Path Analyzer 0.31.0 initializing "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    HMODULE taskbarModule =
        GetModuleHandleW(
            L"taskbar.dll"
        );

    if (!taskbarModule) {
        Wh_Log(
            L"IDENTITY_SIGNATURE_TASKBAR_NOT_READY "
            L"processId=%lu",
            GetCurrentProcessId()
        );

        return FALSE;
    }

    LogTaskbarModule(
        taskbarModule
    );

    const bool succeeded =
        RunIdentitySignatureAudit(
            taskbarModule
        );

    Wh_Log(
        L"IDENTITY_SIGNATURE_AUDIT_COMPLETE "
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
        L"Tray Add Path Analyzer 0.31.0 stopped "
        L"processId=%lu",
        GetCurrentProcessId()
    );
}
