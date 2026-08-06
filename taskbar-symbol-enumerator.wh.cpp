// ==WindhawkMod==
// @id              taskbar-symbol-enumerator
// @name            Taskbar Symbol Enumerator
// @description     Lists taskbar.dll symbols related to notification-area icon management.
// @version         0.1.0
// @author          Yusseter
// @github          https://github.com/Yusseter
// @homepage        https://github.com/Yusseter/tray-order-lock
// @license         MIT
// @include         explorer.exe
// @architecture    x86-64
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# Taskbar Symbol Enumerator

A temporary read-only diagnostic mod.

It enumerates public Microsoft symbols from `taskbar.dll` and logs symbols
related to notification-area icon registration, insertion, removal, movement
and ordering.

The mod does not hook functions, modify memory, change tray order or write to
the registry.
*/
// ==/WindhawkModReadme==

#include <windows.h>

#include <algorithm>
#include <cwctype>
#include <string>

namespace {

bool ContainsOrdinalIgnoreCase(
    const wchar_t* text,
    const wchar_t* searchText
) {
    if (
        !text ||
        !searchText
    ) {
        return false;
    }

    std::wstring normalizedText =
        text;

    std::wstring normalizedSearchText =
        searchText;

    std::transform(
        normalizedText.begin(),
        normalizedText.end(),
        normalizedText.begin(),
        [](wchar_t character) {
            return
                static_cast<wchar_t>(
                    std::towlower(character)
                );
        }
    );

    std::transform(
        normalizedSearchText.begin(),
        normalizedSearchText.end(),
        normalizedSearchText.begin(),
        [](wchar_t character) {
            return
                static_cast<wchar_t>(
                    std::towlower(character)
                );
        }
    );

    return
        normalizedText.find(
            normalizedSearchText
        ) !=
        std::wstring::npos;
}

bool IsRelevantSymbolText(
    const wchar_t* symbol
) {
    if (
        !symbol
    ) {
        return false;
    }

    constexpr const wchar_t* kSearchTerms[] = {
        L"NotificationArea",
        L"NotificationIcon",
        L"NotifyIcon",
        L"SystemTray",
        L"TrayIcon",
        L"IconManager",
        L"TaskbarModel",
        L"StackViewModel",
        L"UIOrder",
        L"MoveIcon",
        L"AddIcon",
        L"InsertIcon",
        L"RemoveIcon",
        L"RegisterIcon",
        L"UnregisterIcon",
        L"IconAdded",
        L"IconRemoved",
    };

    for (
        const wchar_t* searchTerm :
        kSearchTerms
    ) {
        if (
            ContainsOrdinalIgnoreCase(
                symbol,
                searchTerm
            )
        ) {
            return true;
        }
    }

    return false;
}

bool IsRelevantSymbol(
    const WH_FIND_SYMBOL& symbol
) {
    return
        IsRelevantSymbolText(
            symbol.symbol
        ) ||
        IsRelevantSymbolText(
            symbol.symbolDecorated
        );
}

void LogModuleInformation(
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

    if (
        length == 0 ||
        length >=
            ARRAYSIZE(
                modulePath
            )
    ) {
        Wh_Log(
            L"TASKBAR_MODULE "
            L"address=%p "
            L"path=\"<unavailable>\"",
            module
        );

        return;
    }

    Wh_Log(
        L"TASKBAR_MODULE "
        L"address=%p "
        L"path=\"%s\"",
        module,
        modulePath
    );
}

bool EnumerateTaskbarSymbols() {
    HMODULE taskbarModule =
        GetModuleHandleW(
            L"taskbar.dll"
        );

    if (
        !taskbarModule
    ) {
        Wh_Log(
            L"taskbar.dll is not loaded"
        );

        return false;
    }

    LogModuleInformation(
        taskbarModule
    );

    WH_FIND_SYMBOL_OPTIONS options{};

    options.optionsSize =
        sizeof(options);

    options.symbolServer =
        nullptr;

    options.noUndecoratedSymbols =
        FALSE;

    WH_FIND_SYMBOL symbol{};

    HANDLE symbolSearch =
        Wh_FindFirstSymbol(
            taskbarModule,
            &options,
            &symbol
        );

    if (
        !symbolSearch
    ) {
        Wh_Log(
            L"Wh_FindFirstSymbol failed"
        );

        return false;
    }

    unsigned long long totalSymbolCount =
        0;

    unsigned long long matchedSymbolCount =
        0;

    do {
        totalSymbolCount++;

        if (
            !IsRelevantSymbol(
                symbol
            )
        ) {
            continue;
        }

        matchedSymbolCount++;

        Wh_Log(
            L"TASKBAR_SYMBOL "
            L"match=%llu "
            L"address=%p "
            L"symbol=\"%s\" "
            L"decorated=\"%s\"",
            matchedSymbolCount,
            symbol.address,
            symbol.symbol
                ? symbol.symbol
                : L"",
            symbol.symbolDecorated
                ? symbol.symbolDecorated
                : L""
        );
    } while (
        Wh_FindNextSymbol(
            symbolSearch,
            &symbol
        )
    );

    Wh_FindCloseSymbol(
        symbolSearch
    );

    Wh_Log(
        L"SYMBOL_ENUMERATION_COMPLETE "
        L"total=%llu "
        L"matched=%llu",
        totalSymbolCount,
        matchedSymbolCount
    );

    return true;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Taskbar Symbol Enumerator "
        L"0.1.0 initializing"
    );

    return
        EnumerateTaskbarSymbols()
            ? TRUE
            : FALSE;
}

void Wh_ModUninit() {
    Wh_Log(
        L"Taskbar Symbol Enumerator stopped"
    );
}
