// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Tests safe no-op behavior when logical tray identity matching is ambiguous.
// @version         0.24.0
// @author          Yusseter
// @github          https://github.com/Yusseter
// @homepage        https://github.com/Yusseter/tray-order-lock
// @license         MIT
// @include         explorer.exe
// @architecture    x86-64
// @compilerOptions -ladvapi32 -luuid
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# Tray Add Path Analyzer

A temporary logical-identity ambiguity diagnostic mod.

Version 0.24.0 validates conservative behavior when more than one historical
Windows tray identity matches the same logical fallback key.

The dedicated test executable is:

TrayUidAmbiguityProbeV240.exe

All three runs use UID 1 and no GUID.

The executable is run from:

Version-1.0.0
Version-1.1.0
Version-2.0.0

Because UID-based Windows tray identity does not survive an executable path
change, the three paths create three distinct Windows tray identities.

After the first and second runs finish, their version directories are deleted.
Their registry identities remain as historical records.

For the third identity, the analyzer builds this fallback key:

version-normalized executable path + UID

The immediate parent version directory is normalized, so all three paths map
to the same logical executable path.

The analyzer then scans UIOrderList for historical records matching:

- the dedicated executable name,
- UID 1,
- the same normalized executable path,
- an identity other than the newly added current identity.

The expected result is exactly two historical candidates.

Since both historical identities satisfy the same logical fallback, choosing
either one would be ambiguous. The analyzer therefore performs a safe no-op:

- it does not choose a historical identity,
- it does not call MoveIcon,
- it leaves the new target at its current live overflow index.

File existence is logged only as controlled test evidence that the first two
version paths have been removed. It is not used as the logical identity key.

The experiment verifies:

- Three distinct UID-based Windows identities are created.
- The first two identities remain in UIOrderList as historical records.
- Both historical identities match the current normalized path + UID key.
- Both historical executable paths are unavailable during the final run.
- The current Version-2.0.0 path remains available.
- Exactly two historical candidates are found.
- No candidate is selected.
- No analyzer MoveIcon call occurs.
- The current target live index remains unchanged across the ambiguity
  decision.
- No registry values are written by the analyzer.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <unknwn.h>
#include <windhawk_utils.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr wchar_t kNotifyIconSettingsPath[] =
    L"Control Panel\\NotifyIconSettings";

constexpr wchar_t kUIOrderListValueName[] =
    L"UIOrderList";

constexpr wchar_t kTargetExecutableName[] =
    L"trayuidambiguityprobev240.exe";

constexpr wchar_t kVersion1Marker[] =
    L"\\version-1.0.0\\";

constexpr wchar_t kVersion11Marker[] =
    L"\\version-1.1.0\\";

constexpr wchar_t kVersion2Marker[] =
    L"\\version-2.0.0\\";

constexpr DWORD kTargetUid =
    1;

using NotificationAreaIconManager_AddIcon_t =
    void(__cdecl*)(
        void* pThis,
        void* trayNotifyData
    );

using NotificationAreaIconManager_AddVisible_t =
    void(__cdecl*)(
        void* pThis,
        void* iconImplementation
    );

using NotificationAreaIconManager_MoveIcon_t =
    void(__cdecl*)(
        void* pThis,
        void* iconArgumentStorage,
        int location,
        unsigned int index
    );

using NotificationAreaIcon_QueryInterface_t =
    int(__cdecl*)(
        void* iconImplementation,
        const GUID& interfaceId,
        void** result
    );

using TaskbarModel_GetOverflowIcons_t =
    int(__cdecl*)(
        void* pThis,
        void** result
    );

using Vector_GetAt_t =
    HRESULT(STDMETHODCALLTYPE*)(
        void* pThis,
        unsigned int index,
        void** value
    );

using Vector_GetSize_t =
    HRESULT(STDMETHODCALLTYPE*)(
        void* pThis,
        unsigned int* size
    );

NotificationAreaIconManager_AddIcon_t
    NotificationAreaIconManager_AddIcon_Original =
        nullptr;

NotificationAreaIconManager_AddVisible_t
    NotificationAreaIconManager_AddVisible_Original =
        nullptr;

NotificationAreaIconManager_MoveIcon_t
    NotificationAreaIconManager_MoveIcon =
        nullptr;

NotificationAreaIcon_QueryInterface_t
    NotificationAreaIcon_QueryInterface =
        nullptr;

TaskbarModel_GetOverflowIcons_t
    TaskbarModel_GetOverflowIcons_Original =
        nullptr;

const GUID* g_notificationAreaIconInterfaceId =
    nullptr;

const GUID* g_notificationAreaIconVectorId =
    nullptr;

std::atomic<void*> g_taskbarModel6 =
    nullptr;

std::atomic<std::uint64_t> g_firstIdentity =
    0;

std::atomic<std::uint64_t> g_secondIdentity =
    0;

std::atomic<std::uint64_t> g_currentIdentity =
    0;

std::atomic<unsigned long long> g_addIconCalls =
    0;

std::atomic<unsigned long long> g_visibleAddCalls =
    0;

std::atomic<unsigned long long> g_overflowGetterCalls =
    0;

std::atomic<unsigned long long> g_moveAttempts =
    0;

std::atomic<unsigned long long> g_restoreDecisions =
    0;

std::atomic<unsigned int> g_candidateCount =
    0;

std::atomic<std::uint64_t> g_candidate1Identity =
    0;

std::atomic<std::uint64_t> g_candidate2Identity =
    0;

std::atomic<unsigned long long> g_firstUiOrderPosition =
    0;

std::atomic<unsigned long long> g_secondUiOrderPosition =
    0;

std::atomic<unsigned long long> g_currentUiOrderPosition =
    0;

std::atomic<unsigned int> g_currentOverflowIndexBefore =
    0;

std::atomic<unsigned int> g_currentOverflowIndexAfter =
    0;

std::atomic<bool> g_ambiguousMatchObserved =
    false;

std::atomic<bool> g_ambiguousSafeNoOpObserved =
    false;

std::atomic<bool> g_ambiguityValidationCompleted =
    false;

thread_local unsigned int g_internalMoveDepth =
    0;

struct UIOrderSnapshot {
    bool valid =
        false;

    LONG status =
        ERROR_SUCCESS;

    std::vector<std::uint64_t> entries;
};

struct AddIconContext {
    bool active =
        false;

    unsigned long long callNumber =
        0;

    UIOrderSnapshot before;
};

struct OverflowTargetPosition {
    bool enumerated =
        false;

    HRESULT getterResult =
        E_FAIL;

    HRESULT vectorQueryResult =
        E_FAIL;

    HRESULT sizeResult =
        E_FAIL;

    unsigned int size =
        0;

    bool targetFound =
        false;

    unsigned int targetIndex =
        0;
};

struct HistoricalCandidate {
    std::uint64_t identity =
        0;

    std::wstring executablePath;

    std::wstring normalizedPath;

    DWORD uid =
        0;

    bool uidValid =
        false;

    bool pathExists =
        false;

    unsigned long long uiOrderPosition =
        0;
};

thread_local AddIconContext g_addIconContext;

std::wstring ToLower(
    std::wstring value
) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](
            wchar_t character
        ) {
            return
                static_cast<wchar_t>(
                    std::towlower(
                        character
                    )
                );
        }
    );

    return value;
}

std::wstring NormalizeSlashes(
    std::wstring path
) {
    std::replace(
        path.begin(),
        path.end(),
        L'/',
        L'\\'
    );

    return path;
}

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

bool ContainsOrdinalIgnoreCase(
    const std::wstring& value,
    const std::wstring& expected
) {
    return
        ToLower(
            value
        ).find(
            ToLower(
                expected
            )
        ) !=
        std::wstring::npos;
}

bool EndsWithOrdinalIgnoreCase(
    const std::wstring& value,
    const std::wstring& suffix
) {
    if (
        value.size() <
        suffix.size()
    ) {
        return false;
    }

    const std::size_t offset =
        value.size() -
        suffix.size();

    for (
        std::size_t index = 0;
        index <
            suffix.size();
        index++
    ) {
        const wchar_t left =
            static_cast<wchar_t>(
                std::towlower(
                    value[
                        offset +
                        index
                    ]
                )
            );

        const wchar_t right =
            static_cast<wchar_t>(
                std::towlower(
                    suffix[
                        index
                    ]
                )
            );

        if (
            left !=
            right
        ) {
            return false;
        }
    }

    return true;
}

bool StartsWithOrdinalIgnoreCase(
    const std::wstring& value,
    const std::wstring& prefix
) {
    if (
        value.size() <
        prefix.size()
    ) {
        return false;
    }

    for (
        std::size_t index = 0;
        index <
            prefix.size();
        index++
    ) {
        if (
            std::towlower(
                value[
                    index
                ]
            ) !=
            std::towlower(
                prefix[
                    index
                ]
            )
        ) {
            return false;
        }
    }

    return true;
}

bool IsVersionDirectoryName(
    const std::wstring& directoryName
) {
    constexpr wchar_t kPrefix[] =
        L"version-";

    if (
        !StartsWithOrdinalIgnoreCase(
            directoryName,
            kPrefix
        )
    ) {
        return false;
    }

    const std::size_t prefixLength =
        std::wcslen(
            kPrefix
        );

    if (
        directoryName.size() <=
        prefixLength
    ) {
        return false;
    }

    bool digitSeen =
        false;

    for (
        std::size_t index = prefixLength;
        index <
            directoryName.size();
        index++
    ) {
        const wchar_t character =
            directoryName[
                index
            ];

        if (
            character >=
                L'0' &&
            character <=
                L'9'
        ) {
            digitSeen =
                true;

            continue;
        }

        if (
            character ==
            L'.'
        ) {
            continue;
        }

        return false;
    }

    return digitSeen;
}

std::wstring NormalizeVersionedExecutablePath(
    const std::wstring& executablePath
) {
    std::wstring normalized =
        ToLower(
            NormalizeSlashes(
                executablePath
            )
        );

    const std::size_t fileSeparator =
        normalized.find_last_of(
            L'\\'
        );

    if (
        fileSeparator ==
        std::wstring::npos ||
        fileSeparator ==
        0
    ) {
        return normalized;
    }

    const std::size_t parentSeparator =
        normalized.find_last_of(
            L'\\',
            fileSeparator -
                1
        );

    if (
        parentSeparator ==
        std::wstring::npos
    ) {
        return normalized;
    }

    const std::size_t parentStart =
        parentSeparator +
        1;

    const std::size_t parentLength =
        fileSeparator -
        parentStart;

    const std::wstring parentDirectory =
        normalized.substr(
            parentStart,
            parentLength
        );

    if (
        !IsVersionDirectoryName(
            parentDirectory
        )
    ) {
        return normalized;
    }

    normalized.replace(
        parentStart,
        parentLength,
        L"<version>"
    );

    return normalized;
}

bool FileExists(
    const std::wstring& path
) {
    if (path.empty()) {
        return false;
    }

    const DWORD attributes =
        GetFileAttributesW(
            path.c_str()
        );

    return
        attributes !=
            INVALID_FILE_ATTRIBUTES &&
        (
            attributes &
            FILE_ATTRIBUTE_DIRECTORY
        ) ==
            0;
}

bool IsNotificationAreaIconQueryInterfaceSymbol(
    const wchar_t* symbol
) {
    return
        ContainsText(
            symbol,
            L"root_implements<"
        ) &&
        ContainsText(
            symbol,
            L"NotificationAreaIcon2"
        ) &&
        ContainsText(
            symbol,
            L">::query_interface("
        ) &&
        ContainsText(
            symbol,
            L"winrt::guid const &"
        ) &&
        ContainsText(
            symbol,
            L"void * *"
        ) &&
        !ContainsText(
            symbol,
            L"query_interface_common"
        ) &&
        !ContainsText(
            symbol,
            L"query_interface_tearoff"
        );
}

bool IsNotificationAreaIconIidSymbol(
    const wchar_t* symbol
) {
    constexpr wchar_t kExpectedSymbol[] =
        L"struct guid::guid const "
        L"winrt::impl::guid_v<struct "
        L"winrt::WindowsUdk::UI::Shell::"
        L"INotificationAreaIcon>";

    return
        symbol &&
        std::wcscmp(
            symbol,
            kExpectedSymbol
        ) ==
            0;
}

bool IsNotificationAreaIconVectorIidSymbol(
    const wchar_t* symbol
) {
    constexpr wchar_t kExpectedSymbol[] =
        L"struct guid::guid const "
        L"winrt::impl::guid_v<struct "
        L"winrt::Windows::Foundation::Collections::"
        L"IVector<struct "
        L"winrt::WindowsUdk::UI::Shell::"
        L"NotificationAreaIcon> >";

    return
        symbol &&
        std::wcscmp(
            symbol,
            kExpectedSymbol
        ) ==
            0;
}

bool IsMoveIconSymbol(
    const wchar_t* symbol
) {
    constexpr wchar_t kExpectedSymbol[] =
        L"public: void __cdecl "
        L"NotificationAreaIconManager2::MoveIcon("
        L"struct winrt::WindowsUdk::UI::Shell::"
        L"NotificationAreaIcon,"
        L"enum winrt::WindowsUdk::UI::Shell::"
        L"NotificationAreaIconLocation,"
        L"unsigned int)";

    return
        symbol &&
        std::wcscmp(
            symbol,
            kExpectedSymbol
        ) ==
            0;
}

bool ResolveRequiredSymbols(
    HMODULE taskbarModule
) {
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

    if (!symbolSearch) {
        Wh_Log(
            L"Wh_FindFirstSymbol failed"
        );

        return false;
    }

    do {
        if (
            !NotificationAreaIcon_QueryInterface &&
            IsNotificationAreaIconQueryInterfaceSymbol(
                symbol.symbol
            )
        ) {
            NotificationAreaIcon_QueryInterface =
                reinterpret_cast<
                    NotificationAreaIcon_QueryInterface_t
                >(
                    symbol.address
                );

            Wh_Log(
                L"QUERY_INTERFACE_SYMBOL "
                L"address=%p",
                symbol.address
            );
        }

        if (
            !g_notificationAreaIconInterfaceId &&
            IsNotificationAreaIconIidSymbol(
                symbol.symbol
            )
        ) {
            g_notificationAreaIconInterfaceId =
                reinterpret_cast<const GUID*>(
                    symbol.address
                );

            Wh_Log(
                L"ICON_INTERFACE_ID_SYMBOL "
                L"address=%p",
                symbol.address
            );
        }

        if (
            !g_notificationAreaIconVectorId &&
            IsNotificationAreaIconVectorIidSymbol(
                symbol.symbol
            )
        ) {
            g_notificationAreaIconVectorId =
                reinterpret_cast<const GUID*>(
                    symbol.address
                );

            Wh_Log(
                L"VECTOR_INTERFACE_ID_SYMBOL "
                L"address=%p",
                symbol.address
            );
        }

        if (
            !NotificationAreaIconManager_MoveIcon &&
            IsMoveIconSymbol(
                symbol.symbol
            )
        ) {
            NotificationAreaIconManager_MoveIcon =
                reinterpret_cast<
                    NotificationAreaIconManager_MoveIcon_t
                >(
                    symbol.address
                );

            Wh_Log(
                L"MOVE_ICON_SYMBOL "
                L"address=%p",
                symbol.address
            );
        }

        if (
            NotificationAreaIcon_QueryInterface &&
            g_notificationAreaIconInterfaceId &&
            g_notificationAreaIconVectorId &&
            NotificationAreaIconManager_MoveIcon
        ) {
            break;
        }
    } while (
        Wh_FindNextSymbol(
            symbolSearch,
            &symbol
        )
    );

    Wh_FindCloseSymbol(
        symbolSearch
    );

    if (
        !NotificationAreaIcon_QueryInterface ||
        !g_notificationAreaIconInterfaceId ||
        !g_notificationAreaIconVectorId ||
        !NotificationAreaIconManager_MoveIcon
    ) {
        Wh_Log(
            L"AMBIGUITY_REQUIRED_SYMBOL_MISSING"
        );

        return false;
    }

    Wh_Log(
        L"AMBIGUITY_SUPPORT_READY "
        L"queryFunction=%p "
        L"iconInterfaceId=%p "
        L"vectorInterfaceId=%p "
        L"moveFunction=%p",
        NotificationAreaIcon_QueryInterface,
        g_notificationAreaIconInterfaceId,
        g_notificationAreaIconVectorId,
        NotificationAreaIconManager_MoveIcon
    );

    return true;
}

UIOrderSnapshot CaptureUIOrderSnapshot() {
    UIOrderSnapshot snapshot;

    for (
        int attempt = 0;
        attempt <
            3;
        attempt++
    ) {
        DWORD registryType =
            REG_NONE;

        DWORD requiredBytes =
            0;

        LONG status =
            RegGetValueW(
                HKEY_CURRENT_USER,
                kNotifyIconSettingsPath,
                kUIOrderListValueName,
                RRF_RT_REG_BINARY,
                &registryType,
                nullptr,
                &requiredBytes
            );

        snapshot.status =
            status;

        if (
            status !=
            ERROR_SUCCESS
        ) {
            return snapshot;
        }

        std::vector<BYTE> data(
            requiredBytes
        );

        DWORD actualBytes =
            requiredBytes;

        status =
            RegGetValueW(
                HKEY_CURRENT_USER,
                kNotifyIconSettingsPath,
                kUIOrderListValueName,
                RRF_RT_REG_BINARY,
                &registryType,
                data.empty()
                    ? nullptr
                    : data.data(),
                &actualBytes
            );

        if (
            status ==
            ERROR_MORE_DATA
        ) {
            continue;
        }

        snapshot.status =
            status;

        if (
            status !=
            ERROR_SUCCESS
        ) {
            return snapshot;
        }

        if (
            actualBytes %
                sizeof(
                    std::uint64_t
                ) !=
            0
        ) {
            snapshot.status =
                ERROR_INVALID_DATA;

            return snapshot;
        }

        snapshot.entries.resize(
            actualBytes /
            sizeof(
                std::uint64_t
            )
        );

        if (
            actualBytes !=
            0
        ) {
            std::memcpy(
                snapshot.entries.data(),
                data.data(),
                actualBytes
            );
        }

        snapshot.valid =
            true;

        return snapshot;
    }

    snapshot.status =
        ERROR_MORE_DATA;

    return snapshot;
}

std::vector<std::uint64_t> FindAddedIdentities(
    const UIOrderSnapshot& before,
    const UIOrderSnapshot& after
) {
    std::vector<std::uint64_t> added;

    if (
        !before.valid ||
        !after.valid
    ) {
        return added;
    }

    for (
        std::uint64_t identity :
        after.entries
    ) {
        if (
            std::find(
                before.entries.begin(),
                before.entries.end(),
                identity
            ) ==
            before.entries.end()
        ) {
            added.push_back(
                identity
            );
        }
    }

    return added;
}

unsigned long long FindOneBasedPosition(
    const UIOrderSnapshot& snapshot,
    std::uint64_t identity
) {
    if (!snapshot.valid) {
        return 0;
    }

    const auto iterator =
        std::find(
            snapshot.entries.begin(),
            snapshot.entries.end(),
            identity
        );

    if (
        iterator ==
        snapshot.entries.end()
    ) {
        return 0;
    }

    return
        static_cast<unsigned long long>(
            std::distance(
                snapshot.entries.begin(),
                iterator
            )
        ) +
        1;
}

std::wstring MakeTrayEntrySubkey(
    std::uint64_t identity
) {
    return
        std::wstring(
            kNotifyIconSettingsPath
        ) +
        L"\\" +
        std::to_wstring(
            identity
        );
}

std::wstring QueryStringValue(
    const std::wstring& subkey,
    const wchar_t* valueName
) {
    DWORD registryType =
        REG_NONE;

    DWORD requiredBytes =
        0;

    LONG status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            valueName,
            RRF_RT_REG_SZ |
                RRF_RT_REG_EXPAND_SZ,
            &registryType,
            nullptr,
            &requiredBytes
        );

    if (
        status !=
            ERROR_SUCCESS ||
        requiredBytes ==
            0
    ) {
        return L"";
    }

    std::vector<wchar_t> buffer(
        requiredBytes /
            sizeof(wchar_t) +
        1,
        L'\0'
    );

    DWORD actualBytes =
        requiredBytes;

    status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            valueName,
            RRF_RT_REG_SZ |
                RRF_RT_REG_EXPAND_SZ,
            &registryType,
            buffer.data(),
            &actualBytes
        );

    if (
        status !=
        ERROR_SUCCESS
    ) {
        return L"";
    }

    buffer.back() =
        L'\0';

    return
        std::wstring(
            buffer.data()
        );
}

bool QueryDwordValue(
    const std::wstring& subkey,
    const wchar_t* valueName,
    DWORD* value
) {
    if (!value) {
        return false;
    }

    DWORD registryType =
        REG_NONE;

    DWORD result =
        0;

    DWORD resultBytes =
        sizeof(result);

    const LONG status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            valueName,
            RRF_RT_REG_DWORD,
            &registryType,
            &result,
            &resultBytes
        );

    if (
        status !=
            ERROR_SUCCESS ||
        registryType !=
            REG_DWORD ||
        resultBytes !=
            sizeof(result)
    ) {
        return false;
    }

    *value =
        result;

    return true;
}

std::wstring QueryExecutablePath(
    std::uint64_t identity
) {
    return
        QueryStringValue(
            MakeTrayEntrySubkey(
                identity
            ),
            L"ExecutablePath"
        );
}

bool QueryIdentityUid(
    std::uint64_t identity,
    DWORD* uid
) {
    return
        QueryDwordValue(
            MakeTrayEntrySubkey(
                identity
            ),
            L"UID",
            uid
        );
}

bool IsTargetIdentity(
    std::uint64_t identity
) {
    const std::wstring path =
        QueryExecutablePath(
            identity
        );

    if (
        !EndsWithOrdinalIgnoreCase(
            path,
            kTargetExecutableName
        )
    ) {
        return false;
    }

    DWORD uid =
        0;

    return
        QueryIdentityUid(
            identity,
            &uid
        ) &&
        uid ==
            kTargetUid;
}

bool IsSameComObject(
    void* left,
    void* right
) {
    if (
        !left ||
        !right
    ) {
        return false;
    }

    IUnknown* leftUnknown =
        nullptr;

    IUnknown* rightUnknown =
        nullptr;

    const HRESULT leftResult =
        reinterpret_cast<IUnknown*>(
            left
        )->QueryInterface(
            IID_IUnknown,
            reinterpret_cast<void**>(
                &leftUnknown
            )
        );

    const HRESULT rightResult =
        reinterpret_cast<IUnknown*>(
            right
        )->QueryInterface(
            IID_IUnknown,
            reinterpret_cast<void**>(
                &rightUnknown
            )
        );

    const bool same =
        SUCCEEDED(
            leftResult
        ) &&
        SUCCEEDED(
            rightResult
        ) &&
        leftUnknown &&
        rightUnknown &&
        leftUnknown ==
            rightUnknown;

    if (leftUnknown) {
        leftUnknown->Release();
    }

    if (rightUnknown) {
        rightUnknown->Release();
    }

    return same;
}

OverflowTargetPosition QueryOverflowTargetPosition(
    void* targetAbi
) {
    OverflowTargetPosition position;

    void* taskbarModel6 =
        g_taskbarModel6.load(
            std::memory_order_acquire
        );

    if (
        !taskbarModel6 ||
        !targetAbi ||
        !TaskbarModel_GetOverflowIcons_Original ||
        !g_notificationAreaIconVectorId
    ) {
        return position;
    }

    void* collectionAbi =
        nullptr;

    position.getterResult =
        static_cast<HRESULT>(
            TaskbarModel_GetOverflowIcons_Original(
                taskbarModel6,
                &collectionAbi
            )
        );

    if (
        FAILED(
            position.getterResult
        ) ||
        !collectionAbi
    ) {
        return position;
    }

    void* vectorAbi =
        nullptr;

    position.vectorQueryResult =
        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->QueryInterface(
            *g_notificationAreaIconVectorId,
            &vectorAbi
        );

    if (
        FAILED(
            position.vectorQueryResult
        ) ||
        !vectorAbi
    ) {
        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->Release();

        return position;
    }

    void** vtable =
        *reinterpret_cast<void***>(
            vectorAbi
        );

    if (!vtable) {
        reinterpret_cast<IUnknown*>(
            vectorAbi
        )->Release();

        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->Release();

        return position;
    }

    Vector_GetAt_t getAt =
        reinterpret_cast<Vector_GetAt_t>(
            vtable[
                6
            ]
        );

    Vector_GetSize_t getSize =
        reinterpret_cast<Vector_GetSize_t>(
            vtable[
                7
            ]
        );

    if (
        !getAt ||
        !getSize
    ) {
        reinterpret_cast<IUnknown*>(
            vectorAbi
        )->Release();

        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->Release();

        return position;
    }

    position.sizeResult =
        getSize(
            vectorAbi,
            &position.size
        );

    if (
        FAILED(
            position.sizeResult
        )
    ) {
        reinterpret_cast<IUnknown*>(
            vectorAbi
        )->Release();

        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->Release();

        return position;
    }

    position.enumerated =
        true;

    for (
        unsigned int index = 0;
        index <
            position.size;
        index++
    ) {
        void* itemAbi =
            nullptr;

        const HRESULT getAtResult =
            getAt(
                vectorAbi,
                index,
                &itemAbi
            );

        if (
            FAILED(
                getAtResult
            ) ||
            !itemAbi
        ) {
            continue;
        }

        const bool same =
            IsSameComObject(
                itemAbi,
                targetAbi
            );

        reinterpret_cast<IUnknown*>(
            itemAbi
        )->Release();

        if (same) {
            position.targetFound =
                true;

            position.targetIndex =
                index;

            break;
        }
    }

    reinterpret_cast<IUnknown*>(
        vectorAbi
    )->Release();

    reinterpret_cast<IUnknown*>(
        collectionAbi
    )->Release();

    return position;
}

std::vector<HistoricalCandidate>
FindHistoricalCandidates(
    std::uint64_t currentIdentity,
    const std::wstring& currentNormalizedPath
) {
    std::vector<HistoricalCandidate> candidates;

    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    if (!snapshot.valid) {
        return candidates;
    }

    for (
        std::size_t index = 0;
        index <
            snapshot.entries.size();
        index++
    ) {
        const std::uint64_t identity =
            snapshot.entries[
                index
            ];

        if (
            identity ==
            currentIdentity
        ) {
            continue;
        }

        const std::wstring executablePath =
            QueryExecutablePath(
                identity
            );

        if (
            executablePath.empty() ||
            !EndsWithOrdinalIgnoreCase(
                executablePath,
                kTargetExecutableName
            )
        ) {
            continue;
        }

        DWORD uid =
            0;

        const bool uidValid =
            QueryIdentityUid(
                identity,
                &uid
            );

        if (
            !uidValid ||
            uid !=
                kTargetUid
        ) {
            continue;
        }

        const std::wstring normalizedPath =
            NormalizeVersionedExecutablePath(
                executablePath
            );

        if (
            normalizedPath !=
            currentNormalizedPath
        ) {
            continue;
        }

        HistoricalCandidate candidate;

        candidate.identity =
            identity;

        candidate.executablePath =
            executablePath;

        candidate.normalizedPath =
            normalizedPath;

        candidate.uid =
            uid;

        candidate.uidValid =
            uidValid;

        candidate.pathExists =
            FileExists(
                executablePath
            );

        candidate.uiOrderPosition =
            static_cast<unsigned long long>(
                index
            ) +
            1;

        candidates.push_back(
            std::move(
                candidate
            )
        );
    }

    return candidates;
}

bool CandidateListContainsIdentity(
    const std::vector<HistoricalCandidate>& candidates,
    std::uint64_t identity
) {
    return
        std::any_of(
            candidates.begin(),
            candidates.end(),
            [
                identity
            ](
                const HistoricalCandidate& candidate
            ) {
                return
                    candidate.identity ==
                    identity;
            }
        );
}

void LogFinalValidation(
    std::uint64_t currentIdentity,
    const std::vector<HistoricalCandidate>& candidates,
    const OverflowTargetPosition& before,
    const OverflowTargetPosition& after
) {
    const std::uint64_t firstIdentity =
        g_firstIdentity.load(
            std::memory_order_acquire
        );

    const std::uint64_t secondIdentity =
        g_secondIdentity.load(
            std::memory_order_acquire
        );

    const std::wstring firstPath =
        QueryExecutablePath(
            firstIdentity
        );

    const std::wstring secondPath =
        QueryExecutablePath(
            secondIdentity
        );

    const std::wstring currentPath =
        QueryExecutablePath(
            currentIdentity
        );

    const std::wstring firstNormalized =
        NormalizeVersionedExecutablePath(
            firstPath
        );

    const std::wstring secondNormalized =
        NormalizeVersionedExecutablePath(
            secondPath
        );

    const std::wstring currentNormalized =
        NormalizeVersionedExecutablePath(
            currentPath
        );

    DWORD firstUid =
        0;

    DWORD secondUid =
        0;

    DWORD currentUid =
        0;

    const bool firstUidValid =
        QueryIdentityUid(
            firstIdentity,
            &firstUid
        );

    const bool secondUidValid =
        QueryIdentityUid(
            secondIdentity,
            &secondUid
        );

    const bool currentUidValid =
        QueryIdentityUid(
            currentIdentity,
            &currentUid
        );

    const bool identitiesDistinct =
        firstIdentity !=
            0 &&
        secondIdentity !=
            0 &&
        currentIdentity !=
            0 &&
        firstIdentity !=
            secondIdentity &&
        firstIdentity !=
            currentIdentity &&
        secondIdentity !=
            currentIdentity;

    const bool firstVersion1 =
        ContainsOrdinalIgnoreCase(
            NormalizeSlashes(
                firstPath
            ),
            kVersion1Marker
        );

    const bool secondVersion11 =
        ContainsOrdinalIgnoreCase(
            NormalizeSlashes(
                secondPath
            ),
            kVersion11Marker
        );

    const bool currentVersion2 =
        ContainsOrdinalIgnoreCase(
            NormalizeSlashes(
                currentPath
            ),
            kVersion2Marker
        );

    const bool normalizedPathsEqual =
        !currentNormalized.empty() &&
        firstNormalized ==
            currentNormalized &&
        secondNormalized ==
            currentNormalized;

    const bool firstCandidatePresent =
        CandidateListContainsIdentity(
            candidates,
            firstIdentity
        );

    const bool secondCandidatePresent =
        CandidateListContainsIdentity(
            candidates,
            secondIdentity
        );

    const bool firstPathExists =
        FileExists(
            firstPath
        );

    const bool secondPathExists =
        FileExists(
            secondPath
        );

    const bool currentPathExists =
        FileExists(
            currentPath
        );

    const bool targetIndexUnchanged =
        before.enumerated &&
        after.enumerated &&
        before.targetFound &&
        after.targetFound &&
        before.targetIndex ==
            after.targetIndex;

    const bool exactlyTwoCandidates =
        candidates.size() ==
        2;

    const bool noAnalyzerMove =
        g_moveAttempts.load(
            std::memory_order_acquire
        ) ==
        0;

    const bool exactlyOneRestoreDecision =
        g_restoreDecisions.load(
            std::memory_order_acquire
        ) ==
        1;

    const bool ambiguousMatchObserved =
        exactlyTwoCandidates &&
        firstCandidatePresent &&
        secondCandidatePresent;

    g_ambiguousMatchObserved.store(
        ambiguousMatchObserved,
        std::memory_order_release
    );

    const bool ambiguousSafeNoOpObserved =
        ambiguousMatchObserved &&
        noAnalyzerMove &&
        targetIndexUnchanged;

    g_ambiguousSafeNoOpObserved.store(
        ambiguousSafeNoOpObserved,
        std::memory_order_release
    );

    const bool validationCompleted =
        identitiesDistinct &&
        firstUidValid &&
        secondUidValid &&
        currentUidValid &&
        firstUid ==
            kTargetUid &&
        secondUid ==
            kTargetUid &&
        currentUid ==
            kTargetUid &&
        firstVersion1 &&
        secondVersion11 &&
        currentVersion2 &&
        normalizedPathsEqual &&
        exactlyTwoCandidates &&
        firstCandidatePresent &&
        secondCandidatePresent &&
        !firstPathExists &&
        !secondPathExists &&
        currentPathExists &&
        exactlyOneRestoreDecision &&
        noAnalyzerMove &&
        targetIndexUnchanged &&
        ambiguousMatchObserved &&
        ambiguousSafeNoOpObserved;

    g_ambiguityValidationCompleted.store(
        validationCompleted,
        std::memory_order_release
    );

    Wh_Log(
        L"AMBIGUITY_RESULT "
        L"firstIdentity=%llu "
        L"secondIdentity=%llu "
        L"currentIdentity=%llu "
        L"identitiesDistinct=%d "
        L"firstUidValid=%d "
        L"firstUid=%u "
        L"secondUidValid=%d "
        L"secondUid=%u "
        L"currentUidValid=%d "
        L"currentUid=%u "
        L"firstVersion1=%d "
        L"secondVersion11=%d "
        L"currentVersion2=%d "
        L"normalizedPathsEqual=%d "
        L"candidateCount=%llu "
        L"firstCandidatePresent=%d "
        L"secondCandidatePresent=%d "
        L"firstPathExists=%d "
        L"secondPathExists=%d "
        L"currentPathExists=%d "
        L"targetIndexBefore=%u "
        L"targetIndexAfter=%u "
        L"targetIndexUnchanged=%d "
        L"restoreDecisions=%llu "
        L"moveAttempts=%llu "
        L"ambiguousMatchObserved=%d "
        L"ambiguousSafeNoOpObserved=%d "
        L"ambiguityValidationCompleted=%d",
        static_cast<unsigned long long>(
            firstIdentity
        ),
        static_cast<unsigned long long>(
            secondIdentity
        ),
        static_cast<unsigned long long>(
            currentIdentity
        ),
        identitiesDistinct
            ? 1
            : 0,
        firstUidValid
            ? 1
            : 0,
        firstUid,
        secondUidValid
            ? 1
            : 0,
        secondUid,
        currentUidValid
            ? 1
            : 0,
        currentUid,
        firstVersion1
            ? 1
            : 0,
        secondVersion11
            ? 1
            : 0,
        currentVersion2
            ? 1
            : 0,
        normalizedPathsEqual
            ? 1
            : 0,
        static_cast<unsigned long long>(
            candidates.size()
        ),
        firstCandidatePresent
            ? 1
            : 0,
        secondCandidatePresent
            ? 1
            : 0,
        firstPathExists
            ? 1
            : 0,
        secondPathExists
            ? 1
            : 0,
        currentPathExists
            ? 1
            : 0,
        before.targetIndex,
        after.targetIndex,
        targetIndexUnchanged
            ? 1
            : 0,
        g_restoreDecisions.load(
            std::memory_order_acquire
        ),
        g_moveAttempts.load(
            std::memory_order_acquire
        ),
        ambiguousMatchObserved
            ? 1
            : 0,
        ambiguousSafeNoOpObserved
            ? 1
            : 0,
        validationCompleted
            ? 1
            : 0
    );

    Wh_Log(
        L"AMBIGUITY_SUMMARY "
        L"firstIdentity=%llu "
        L"secondIdentity=%llu "
        L"currentIdentity=%llu "
        L"candidate1Identity=%llu "
        L"candidate2Identity=%llu "
        L"firstUiOrderPosition=%llu "
        L"secondUiOrderPosition=%llu "
        L"currentUiOrderPosition=%llu "
        L"candidateCount=%u "
        L"currentOverflowIndexBefore=%u "
        L"currentOverflowIndexAfter=%u "
        L"restoreDecisions=%llu "
        L"moveAttempts=%llu "
        L"ambiguityValidationCompleted=%d",
        static_cast<unsigned long long>(
            firstIdentity
        ),
        static_cast<unsigned long long>(
            secondIdentity
        ),
        static_cast<unsigned long long>(
            currentIdentity
        ),
        static_cast<unsigned long long>(
            g_candidate1Identity.load(
                std::memory_order_acquire
            )
        ),
        static_cast<unsigned long long>(
            g_candidate2Identity.load(
                std::memory_order_acquire
            )
        ),
        g_firstUiOrderPosition.load(
            std::memory_order_acquire
        ),
        g_secondUiOrderPosition.load(
            std::memory_order_acquire
        ),
        g_currentUiOrderPosition.load(
            std::memory_order_acquire
        ),
        g_candidateCount.load(
            std::memory_order_acquire
        ),
        g_currentOverflowIndexBefore.load(
            std::memory_order_acquire
        ),
        g_currentOverflowIndexAfter.load(
            std::memory_order_acquire
        ),
        g_restoreDecisions.load(
            std::memory_order_acquire
        ),
        g_moveAttempts.load(
            std::memory_order_acquire
        ),
        validationCompleted
            ? 1
            : 0
    );
}

void HandleTargetIcon(
    unsigned long long callNumber,
    std::uint64_t identity,
    void* iconImplementation
) {
    const std::uint64_t firstIdentity =
        g_firstIdentity.load(
            std::memory_order_acquire
        );

    const std::uint64_t secondIdentity =
        g_secondIdentity.load(
            std::memory_order_acquire
        );

    if (
        firstIdentity ==
        0
    ) {
        g_firstIdentity.store(
            identity,
            std::memory_order_release
        );

        const UIOrderSnapshot snapshot =
            CaptureUIOrderSnapshot();

        const unsigned long long position =
            FindOneBasedPosition(
                snapshot,
                identity
            );

        g_firstUiOrderPosition.store(
            position,
            std::memory_order_release
        );

        const std::wstring path =
            QueryExecutablePath(
                identity
            );

        DWORD uid =
            0;

        const bool uidValid =
            QueryIdentityUid(
                identity,
                &uid
            );

        Wh_Log(
            L"AMBIGUITY_HISTORY_CAPTURE "
            L"phase=1 "
            L"call=%llu "
            L"id=%llu "
            L"uidValid=%d "
            L"uid=%u "
            L"uiOrderPosition=%llu "
            L"pathExists=%d "
            L"path=\"%s\" "
            L"normalizedPath=\"%s\"",
            callNumber,
            static_cast<unsigned long long>(
                identity
            ),
            uidValid
                ? 1
                : 0,
            uid,
            position,
            FileExists(
                path
            )
                ? 1
                : 0,
            path.c_str(),
            NormalizeVersionedExecutablePath(
                path
            ).c_str()
        );

        return;
    }

    if (
        secondIdentity ==
            0 &&
        identity !=
            firstIdentity
    ) {
        g_secondIdentity.store(
            identity,
            std::memory_order_release
        );

        const UIOrderSnapshot snapshot =
            CaptureUIOrderSnapshot();

        const unsigned long long position =
            FindOneBasedPosition(
                snapshot,
                identity
            );

        g_secondUiOrderPosition.store(
            position,
            std::memory_order_release
        );

        const std::wstring path =
            QueryExecutablePath(
                identity
            );

        DWORD uid =
            0;

        const bool uidValid =
            QueryIdentityUid(
                identity,
                &uid
            );

        Wh_Log(
            L"AMBIGUITY_HISTORY_CAPTURE "
            L"phase=2 "
            L"call=%llu "
            L"id=%llu "
            L"uidValid=%d "
            L"uid=%u "
            L"uiOrderPosition=%llu "
            L"pathExists=%d "
            L"path=\"%s\" "
            L"normalizedPath=\"%s\"",
            callNumber,
            static_cast<unsigned long long>(
                identity
            ),
            uidValid
                ? 1
                : 0,
            uid,
            position,
            FileExists(
                path
            )
                ? 1
                : 0,
            path.c_str(),
            NormalizeVersionedExecutablePath(
                path
            ).c_str()
        );

        return;
    }

    if (
        identity ==
            firstIdentity ||
        identity ==
            secondIdentity ||
        g_currentIdentity.load(
            std::memory_order_acquire
        ) !=
            0
    ) {
        return;
    }

    g_currentIdentity.store(
        identity,
        std::memory_order_release
    );

    void* targetAbi =
        nullptr;

    const HRESULT queryResult =
        static_cast<HRESULT>(
            NotificationAreaIcon_QueryInterface(
                iconImplementation,
                *g_notificationAreaIconInterfaceId,
                &targetAbi
            )
        );

    Wh_Log(
        L"AMBIGUITY_CURRENT_QUERY "
        L"call=%llu "
        L"id=%llu "
        L"result=0x%08X "
        L"abi=%p",
        callNumber,
        static_cast<unsigned long long>(
            identity
        ),
        static_cast<unsigned int>(
            queryResult
        ),
        targetAbi
    );

    if (
        FAILED(
            queryResult
        ) ||
        !targetAbi
    ) {
        return;
    }

    const OverflowTargetPosition before =
        QueryOverflowTargetPosition(
            targetAbi
        );

    const std::wstring currentPath =
        QueryExecutablePath(
            identity
        );

    const std::wstring currentNormalizedPath =
        NormalizeVersionedExecutablePath(
            currentPath
        );

    const UIOrderSnapshot currentSnapshot =
        CaptureUIOrderSnapshot();

    g_currentUiOrderPosition.store(
        FindOneBasedPosition(
            currentSnapshot,
            identity
        ),
        std::memory_order_release
    );

    const std::vector<HistoricalCandidate> candidates =
        FindHistoricalCandidates(
            identity,
            currentNormalizedPath
        );

    g_candidateCount.store(
        static_cast<unsigned int>(
            candidates.size()
        ),
        std::memory_order_release
    );

    if (
        candidates.size() >=
        1
    ) {
        g_candidate1Identity.store(
            candidates[
                0
            ].identity,
            std::memory_order_release
        );
    }

    if (
        candidates.size() >=
        2
    ) {
        g_candidate2Identity.store(
            candidates[
                1
            ].identity,
            std::memory_order_release
        );
    }

    Wh_Log(
        L"AMBIGUITY_SEARCH "
        L"currentIdentity=%llu "
        L"currentUiOrderPosition=%llu "
        L"currentPathExists=%d "
        L"candidateCount=%llu "
        L"normalizedPath=\"%s\"",
        static_cast<unsigned long long>(
            identity
        ),
        g_currentUiOrderPosition.load(
            std::memory_order_acquire
        ),
        FileExists(
            currentPath
        )
            ? 1
            : 0,
        static_cast<unsigned long long>(
            candidates.size()
        ),
        currentNormalizedPath.c_str()
    );

    for (
        std::size_t index = 0;
        index <
            candidates.size();
        index++
    ) {
        const HistoricalCandidate& candidate =
            candidates[
                index
            ];

        Wh_Log(
            L"AMBIGUITY_CANDIDATE "
            L"candidate=%llu "
            L"id=%llu "
            L"uidValid=%d "
            L"uid=%u "
            L"uiOrderPosition=%llu "
            L"pathExists=%d "
            L"path=\"%s\" "
            L"normalizedPath=\"%s\"",
            static_cast<unsigned long long>(
                index +
                1
            ),
            static_cast<unsigned long long>(
                candidate.identity
            ),
            candidate.uidValid
                ? 1
                : 0,
            candidate.uid,
            candidate.uiOrderPosition,
            candidate.pathExists
                ? 1
                : 0,
            candidate.executablePath.c_str(),
            candidate.normalizedPath.c_str()
        );
    }

    g_restoreDecisions.fetch_add(
        1,
        std::memory_order_relaxed
    );

    if (
        candidates.size() >
        1
    ) {
        Wh_Log(
            L"AMBIGUITY_DECISION "
            L"currentIdentity=%llu "
            L"candidateCount=%llu "
            L"reason=\"multiple-logical-history-candidates\" "
            L"action=\"do-not-select-candidate-do-not-call-MoveIcon\"",
            static_cast<unsigned long long>(
                identity
            ),
            static_cast<unsigned long long>(
                candidates.size()
            )
        );
    } else if (
        candidates.empty()
    ) {
        Wh_Log(
            L"AMBIGUITY_DECISION "
            L"currentIdentity=%llu "
            L"candidateCount=0 "
            L"reason=\"no-logical-history-candidate\" "
            L"action=\"do-not-call-MoveIcon\"",
            static_cast<unsigned long long>(
                identity
            )
        );
    } else {
        Wh_Log(
            L"AMBIGUITY_UNEXPECTED_UNIQUE_CANDIDATE "
            L"currentIdentity=%llu "
            L"candidateIdentity=%llu "
            L"action=\"test-does-not-execute-restore\"",
            static_cast<unsigned long long>(
                identity
            ),
            static_cast<unsigned long long>(
                candidates.front().identity
            )
        );
    }

    const OverflowTargetPosition after =
        QueryOverflowTargetPosition(
            targetAbi
        );

    g_currentOverflowIndexBefore.store(
        before.targetIndex,
        std::memory_order_release
    );

    g_currentOverflowIndexAfter.store(
        after.targetIndex,
        std::memory_order_release
    );

    LogFinalValidation(
        identity,
        candidates,
        before,
        after
    );

    reinterpret_cast<IUnknown*>(
        targetAbi
    )->Release();
}

int __cdecl
TaskbarModel_GetOverflowIcons_Hook(
    void* pThis,
    void** result
) {
    const unsigned long long callNumber =
        g_overflowGetterCalls.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    const int originalResult =
        TaskbarModel_GetOverflowIcons_Original(
            pThis,
            result
        );

    if (
        SUCCEEDED(
            static_cast<HRESULT>(
                originalResult
            )
        ) &&
        result &&
        *result
    ) {
        g_taskbarModel6.store(
            pThis,
            std::memory_order_release
        );
    }

    Wh_Log(
        L"OVERFLOW_GETTER "
        L"call=%llu "
        L"pThis=%p "
        L"result=0x%08X "
        L"collection=%p",
        callNumber,
        pThis,
        static_cast<unsigned int>(
            static_cast<HRESULT>(
                originalResult
            )
        ),
        result
            ? *result
            : nullptr
    );

    return originalResult;
}

void __cdecl
NotificationAreaIconManager_AddIcon_Hook(
    void* pThis,
    void* trayNotifyData
) {
    const unsigned long long callNumber =
        g_addIconCalls.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    AddIconContext previousContext =
        std::move(
            g_addIconContext
        );

    g_addIconContext =
        {};

    g_addIconContext.active =
        true;

    g_addIconContext.callNumber =
        callNumber;

    g_addIconContext.before =
        CaptureUIOrderSnapshot();

    Wh_Log(
        L"ADD_ICON_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"beforeValid=%d "
        L"beforeStatus=%ld "
        L"beforeCount=%llu",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        g_addIconContext.before.valid
            ? 1
            : 0,
        g_addIconContext.before.status,
        static_cast<unsigned long long>(
            g_addIconContext.before.entries.size()
        )
    );

    NotificationAreaIconManager_AddIcon_Original(
        pThis,
        trayNotifyData
    );

    const UIOrderSnapshot after =
        CaptureUIOrderSnapshot();

    Wh_Log(
        L"ADD_ICON_END "
        L"call=%llu "
        L"afterValid=%d "
        L"afterStatus=%ld "
        L"afterCount=%llu",
        callNumber,
        after.valid
            ? 1
            : 0,
        after.status,
        static_cast<unsigned long long>(
            after.entries.size()
        )
    );

    g_addIconContext =
        std::move(
            previousContext
        );
}

void __cdecl
NotificationAreaIconManager_AddVisible_Hook(
    void* pThis,
    void* iconImplementation
) {
    const unsigned long long callNumber =
        g_visibleAddCalls.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    NotificationAreaIconManager_AddVisible_Original(
        pThis,
        iconImplementation
    );

    Wh_Log(
        L"VISIBLE_ADD "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"implementation=%p "
        L"duringAddIcon=%d "
        L"parentAddCall=%llu "
        L"internalMoveDepth=%u",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        iconImplementation,
        g_addIconContext.active
            ? 1
            : 0,
        g_addIconContext.active
            ? g_addIconContext.callNumber
            : 0,
        g_internalMoveDepth
    );

    if (
        g_internalMoveDepth !=
            0 ||
        !g_addIconContext.active
    ) {
        return;
    }

    const UIOrderSnapshot current =
        CaptureUIOrderSnapshot();

    const std::vector<std::uint64_t> added =
        FindAddedIdentities(
            g_addIconContext.before,
            current
        );

    std::vector<std::uint64_t> targetAdded;

    for (
        std::uint64_t identity :
        added
    ) {
        if (
            IsTargetIdentity(
                identity
            )
        ) {
            targetAdded.push_back(
                identity
            );
        }
    }

    Wh_Log(
        L"VISIBLE_ADD_DELTA "
        L"call=%llu "
        L"parentAddCall=%llu "
        L"addedCount=%llu "
        L"targetAdded=%llu",
        callNumber,
        g_addIconContext.callNumber,
        static_cast<unsigned long long>(
            added.size()
        ),
        static_cast<unsigned long long>(
            targetAdded.size()
        )
    );

    if (
        targetAdded.size() ==
        1
    ) {
        HandleTargetIcon(
            callNumber,
            targetAdded.front(),
            iconImplementation
        );
    }
}

bool HookTaskbarSymbols(
    HMODULE taskbarModule
) {
    WindhawkUtils::SYMBOL_HOOK symbolHooks[] = {
        {
            {
                LR"(private: void __cdecl NotificationAreaIconManager2::AddIcon(struct _TRAYNOTIFYDATAW * const))"
            },
            &NotificationAreaIconManager_AddIcon_Original,
            NotificationAreaIconManager_AddIcon_Hook,
        },
        {
            {
                LR"(private: void __cdecl NotificationAreaIconManager2::AddIconToVisibleCollection(struct winrt::WindowsUdk::UI::Shell::implementation::NotificationAreaIcon2 *))"
            },
            &NotificationAreaIconManager_AddVisible_Original,
            NotificationAreaIconManager_AddVisible_Hook,
        },
        {
            {
                LR"(public: virtual int __cdecl winrt::impl::produce<struct winrt::WindowsUdk::UI::Shell::implementation::TaskbarModel,struct winrt::WindowsUdk::UI::Shell::ITaskbarModel6>::get_NotificationAreaOverflowIcons(void * *))"
            },
            &TaskbarModel_GetOverflowIcons_Original,
            TaskbarModel_GetOverflowIcons_Hook,
        },
    };

    if (
        !WindhawkUtils::HookSymbols(
            taskbarModule,
            symbolHooks,
            ARRAYSIZE(
                symbolHooks
            )
        )
    ) {
        Wh_Log(
            L"Failed to hook one or more "
            L"taskbar.dll symbols"
        );

        return false;
    }

    return true;
}

bool IsPrimaryShellProcess() {
    const HWND shellWindow =
        GetShellWindow();

    if (!shellWindow) {
        return false;
    }

    DWORD shellProcessId =
        0;

    GetWindowThreadProcessId(
        shellWindow,
        &shellProcessId
    );

    return
        shellProcessId ==
        GetCurrentProcessId();
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Add Path Analyzer "
        L"0.24.0 initializing"
    );

    if (
        !IsPrimaryShellProcess()
    ) {
        Wh_Log(
            L"AMBIGUITY_TEST_SKIPPED "
            L"reason=\"non-primary Explorer process\" "
            L"processId=%lu",
            GetCurrentProcessId()
        );

        return TRUE;
    }

    HMODULE taskbarModule =
        GetModuleHandleW(
            L"taskbar.dll"
        );

    if (!taskbarModule) {
        Wh_Log(
            L"taskbar.dll is not loaded"
        );

        return FALSE;
    }

    if (
        !ResolveRequiredSymbols(
            taskbarModule
        )
    ) {
        return FALSE;
    }

    if (
        !HookTaskbarSymbols(
            taskbarModule
        )
    ) {
        return FALSE;
    }

    Wh_Log(
        L"AMBIGUITY_TEST_READY "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    return TRUE;
}

void Wh_ModUninit() {
    Wh_Log(
        L"Tray Add Path Analyzer stopped; "
        L"addIconCalls=%llu "
        L"visibleAddCalls=%llu "
        L"overflowGetterCalls=%llu "
        L"moveAttempts=%llu "
        L"restoreDecisions=%llu "
        L"firstIdentity=%llu "
        L"secondIdentity=%llu "
        L"currentIdentity=%llu "
        L"candidateCount=%u "
        L"ambiguousMatchObserved=%d "
        L"ambiguousSafeNoOpObserved=%d "
        L"ambiguityValidationCompleted=%d",
        g_addIconCalls.load(
            std::memory_order_acquire
        ),
        g_visibleAddCalls.load(
            std::memory_order_acquire
        ),
        g_overflowGetterCalls.load(
            std::memory_order_acquire
        ),
        g_moveAttempts.load(
            std::memory_order_acquire
        ),
        g_restoreDecisions.load(
            std::memory_order_acquire
        ),
        static_cast<unsigned long long>(
            g_firstIdentity.load(
                std::memory_order_acquire
            )
        ),
        static_cast<unsigned long long>(
            g_secondIdentity.load(
                std::memory_order_acquire
            )
        ),
        static_cast<unsigned long long>(
            g_currentIdentity.load(
                std::memory_order_acquire
            )
        ),
        g_candidateCount.load(
            std::memory_order_acquire
        ),
        g_ambiguousMatchObserved.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_ambiguousSafeNoOpObserved.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_ambiguityValidationCompleted.load(
            std::memory_order_acquire
        )
            ? 1
            : 0
    );
}
