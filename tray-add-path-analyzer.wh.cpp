// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Audits the 64-bit NotifyIconSettings bridge used to construct live NotificationAreaIcon2 objects.
// @version         0.33.0
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

Version 0.33.0 performs a read-only PDB symbol audit for the bridge between
NotificationAreaIcon2 and the 64-bit NotifyIconSettings identity.

Version 0.32.0 established that NotificationAreaIcon2 is constructed with:

    NotificationAreaIconIdentity &&
    std::pair<unsigned __int64, shared registry HKEY> &

It also established that NotificationAreaIconIdentity itself can be constructed
from _TRAYNOTIFYDATAW.

The first member of the pair is therefore a strong candidate for the 64-bit
NotifyIconSettings/UIOrderList identity already used throughout the earlier
tray-order research. That relationship must still be established directly
before production code relies on it.

This version enumerates symbols involving:

- NotifyIconSettingsDatabase with 64-bit identity values.
- The unsigned-64-bit + registry-HKEY pair.
- NotificationAreaIcon2 construction with that pair.
- UI-order lookup functions related to the same 64-bit identity.

Long symbol names are emitted in chunks to avoid DbgView truncation.

No discovered function is called or hooked.

This version:

- Installs no taskbar function hooks.
- Calls no private taskbar function.
- Moves no tray icons.
- Creates no tray icons.
- Writes no registry values.
- Does not modify tray ordering.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <windhawk_utils.h>

#include <cstddef>
#include <cwchar>

namespace {

constexpr std::size_t kLogChunkLength =
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

struct MatchClassification {
    bool notifyIconSettingsDatabase =
        false;

    bool pairWithUnsigned64 =
        false;

    bool registryHandle =
        false;

    bool notificationAreaIcon2 =
        false;

    bool uiOrder =
        false;

    bool relevant =
        false;
};

MatchClassification ClassifyText(
    const wchar_t* text
) {
    MatchClassification result;

    if (!text) {
        return result;
    }

    result.notifyIconSettingsDatabase =
        ContainsText(
            text,
            L"NotifyIconSettingsDatabase"
        );

    result.pairWithUnsigned64 =
        ContainsText(
            text,
            L"pair<unsigned __int64"
        ) ||
        ContainsText(
            text,
            L"?$pair@_K"
        );

    result.registryHandle =
        ContainsText(
            text,
            L"HKEY__"
        ) ||
        ContainsText(
            text,
            L"shared_any_t"
        ) ||
        ContainsText(
            text,
            L"RegCloseKey"
        );

    result.notificationAreaIcon2 =
        ContainsText(
            text,
            L"NotificationAreaIcon2"
        );

    result.uiOrder =
        ContainsText(
            text,
            L"GetUIOrderForIcon"
        ) ||
        ContainsText(
            text,
            L"UIOrder"
        );

    result.relevant =
        (
            result.pairWithUnsigned64 &&
            result.registryHandle
        ) ||
        (
            result.notifyIconSettingsDatabase &&
            (
                result.pairWithUnsigned64 ||
                ContainsText(
                    text,
                    L"unsigned __int64"
                ) ||
                result.registryHandle ||
                result.uiOrder
            )
        ) ||
        (
            result.notificationAreaIcon2 &&
            result.pairWithUnsigned64
        );

    return result;
}

MatchClassification MergeClassification(
    const MatchClassification& left,
    const MatchClassification& right
) {
    MatchClassification result;

    result.notifyIconSettingsDatabase =
        left.notifyIconSettingsDatabase ||
        right.notifyIconSettingsDatabase;

    result.pairWithUnsigned64 =
        left.pairWithUnsigned64 ||
        right.pairWithUnsigned64;

    result.registryHandle =
        left.registryHandle ||
        right.registryHandle;

    result.notificationAreaIcon2 =
        left.notificationAreaIcon2 ||
        right.notificationAreaIcon2;

    result.uiOrder =
        left.uiOrder ||
        right.uiOrder;

    result.relevant =
        left.relevant ||
        right.relevant;

    return result;
}

MatchClassification ClassifySymbol(
    const WH_FIND_SYMBOL& symbol
) {
    return
        MergeClassification(
            ClassifyText(
                symbol.symbol
            ),
            ClassifyText(
                symbol.symbolDecorated
            )
        );
}

void LogTextChunks(
    unsigned long long matchNumber,
    const wchar_t* field,
    const wchar_t* text
) {
    if (!text) {
        Wh_Log(
            L"SETTINGS_BRIDGE_TEXT "
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

    const std::size_t length =
        std::wcslen(
            text
        );

    if (length == 0) {
        Wh_Log(
            L"SETTINGS_BRIDGE_TEXT "
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
        std::size_t offset = 0;
        offset < length;
        offset += kLogChunkLength
    ) {
        chunkNumber++;

        const std::size_t remaining =
            length -
            offset;

        const std::size_t chunkLength =
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

        Wh_Log(
            L"SETTINGS_BRIDGE_TEXT "
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
            (
                offset +
                    chunkLength >=
                length
            )
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
        L"SETTINGS_BRIDGE_TASKBAR_MODULE "
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

bool RunSettingsBridgeAudit(
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
            L"SETTINGS_BRIDGE_ENUMERATION_FAILED "
            L"lastError=%lu",
            GetLastError()
        );

        return false;
    }

    unsigned long long scanned =
        0;

    unsigned long long matches =
        0;

    unsigned long long databaseMatches =
        0;

    unsigned long long pairMatches =
        0;

    unsigned long long icon2Matches =
        0;

    unsigned long long uiOrderMatches =
        0;

    do {
        scanned++;

        const MatchClassification classification =
            ClassifySymbol(
                symbol
            );

        if (
            !classification.relevant
        ) {
            continue;
        }

        matches++;

        if (
            classification.notifyIconSettingsDatabase
        ) {
            databaseMatches++;
        }

        if (
            classification.pairWithUnsigned64 &&
            classification.registryHandle
        ) {
            pairMatches++;
        }

        if (
            classification.notificationAreaIcon2
        ) {
            icon2Matches++;
        }

        if (
            classification.uiOrder
        ) {
            uiOrderMatches++;
        }

        Wh_Log(
            L"SETTINGS_BRIDGE_SYMBOL_BEGIN "
            L"match=%llu "
            L"address=%p "
            L"database=%d "
            L"pairUnsigned64=%d "
            L"registryHandle=%d "
            L"notificationAreaIcon2=%d "
            L"uiOrder=%d",
            matches,
            symbol.address,
            classification.notifyIconSettingsDatabase
                ? 1
                : 0,
            classification.pairWithUnsigned64
                ? 1
                : 0,
            classification.registryHandle
                ? 1
                : 0,
            classification.notificationAreaIcon2
                ? 1
                : 0,
            classification.uiOrder
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
            L"SETTINGS_BRIDGE_SYMBOL_END "
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
        L"SETTINGS_BRIDGE_SUMMARY "
        L"scanned=%llu "
        L"matches=%llu "
        L"databaseMatches=%llu "
        L"pairMatches=%llu "
        L"icon2Matches=%llu "
        L"uiOrderMatches=%llu",
        scanned,
        matches,
        databaseMatches,
        pairMatches,
        icon2Matches,
        uiOrderMatches
    );

    return
        matches !=
        0;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Add Path Analyzer 0.33.0 initializing "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    HMODULE taskbarModule =
        GetModuleHandleW(
            L"taskbar.dll"
        );

    if (!taskbarModule) {
        Wh_Log(
            L"SETTINGS_BRIDGE_TASKBAR_NOT_READY "
            L"processId=%lu",
            GetCurrentProcessId()
        );

        return FALSE;
    }

    LogTaskbarModule(
        taskbarModule
    );

    const bool succeeded =
        RunSettingsBridgeAudit(
            taskbarModule
        );

    Wh_Log(
        L"SETTINGS_BRIDGE_AUDIT_COMPLETE "
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
        L"Tray Add Path Analyzer 0.33.0 stopped "
        L"processId=%lu",
        GetCurrentProcessId()
    );
}
