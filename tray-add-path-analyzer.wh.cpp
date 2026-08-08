// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Tests dual-neighbor tray-order restoration with single-neighbor fallback.
// @version         0.21.0
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

A temporary live-collection diagnostic mod.

Version 0.21.0 tests a dual-neighbor restoration model for replacement
UID-based tray identities.

Two stable GUID-based anchor icons are created.

During the first target version, the analyzer determines which live anchor is
before the other in the overflow vector and establishes this canonical
relationship:

preceding anchor -> target -> following anchor

Three additional helper icons are then created, changing the live overflow
collection and shifting the anchors.

Version-2.0.0 creates a replacement Windows identity for the same UID-based
target. Both logical neighbors still exist. The analyzer restores the target
directly between them using their CURRENT live vector positions rather than a
saved numeric index.

After Version-2.0.0 exits, the left anchor application is stopped gracefully.

Version-3.0.0 creates another replacement target identity. Exactly one of the
two previously recorded logical neighbors remains live. The analyzer restores
the target using that remaining neighbor:

- immediately after the preceding neighbor, or
- immediately before the following neighbor.

The experiment verifies:

- Three different Windows identities are created for the target.
- The first target establishes a two-neighbor ordering relation.
- Three helpers change the collection geometry.
- The second target is restored between both original neighbors.
- The saved numeric index from the first placement is no longer correct.
- One original neighbor is then removed.
- The third target is restored from the surviving neighbor alone.
- Exactly three analyzer MoveIcon calls occur.
- No anchor, helper, or unrelated tray icon is moved.
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

constexpr wchar_t kLeftAnchorExecutableName[] =
    L"trayorderleftanchorprobev210.exe";

constexpr wchar_t kRightAnchorExecutableName[] =
    L"trayorderrightanchorprobev210.exe";

constexpr wchar_t kTargetExecutableName[] =
    L"trayuiddualneighborrestoreprobev210.exe";

constexpr wchar_t kHelperExecutableName[] =
    L"trayordercollectionhelperv210.exe";

constexpr wchar_t kVersion1Marker[] =
    L"\\version-1.0.0\\";

constexpr wchar_t kVersion2Marker[] =
    L"\\version-2.0.0\\";

constexpr wchar_t kVersion3Marker[] =
    L"\\version-3.0.0\\";

constexpr DWORD kTargetUid =
    1;

constexpr int kOverflowLocation =
    1;

constexpr int kPrecedingUnknown =
    0;

constexpr int kPrecedingLeft =
    1;

constexpr int kPrecedingRight =
    2;

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

std::atomic<void*> g_leftAnchorAbi =
    nullptr;

std::atomic<void*> g_rightAnchorAbi =
    nullptr;

std::atomic<std::uint64_t> g_leftAnchorIdentity =
    0;

std::atomic<std::uint64_t> g_rightAnchorIdentity =
    0;

std::atomic<int> g_precedingAnchorSide =
    kPrecedingUnknown;

std::atomic<std::uint64_t> g_firstTargetIdentity =
    0;

std::atomic<std::uint64_t> g_secondTargetIdentity =
    0;

std::atomic<std::uint64_t> g_thirdTargetIdentity =
    0;

std::atomic<unsigned long long> g_addIconCalls =
    0;

std::atomic<unsigned long long> g_visibleAddCalls =
    0;

std::atomic<unsigned long long> g_overflowGetterCalls =
    0;

std::atomic<unsigned long long> g_moveAttempts =
    0;

std::atomic<unsigned long long> g_helperIdentityCount =
    0;

std::atomic<unsigned int> g_firstOverflowSize =
    0;

std::atomic<unsigned int> g_secondOverflowSize =
    0;

std::atomic<unsigned int> g_thirdOverflowSize =
    0;

std::atomic<unsigned int> g_firstMoveTargetIndex =
    0;

std::atomic<unsigned int> g_secondMoveTargetIndex =
    0;

std::atomic<unsigned int> g_thirdMoveTargetIndex =
    0;

std::atomic<unsigned int> g_firstPrecedingIndexAfter =
    0;

std::atomic<unsigned int> g_firstTargetIndexAfter =
    0;

std::atomic<unsigned int> g_firstFollowingIndexAfter =
    0;

std::atomic<unsigned int> g_secondPrecedingIndexBefore =
    0;

std::atomic<unsigned int> g_secondFollowingIndexBefore =
    0;

std::atomic<unsigned int> g_secondPrecedingIndexAfter =
    0;

std::atomic<unsigned int> g_secondTargetIndexAfter =
    0;

std::atomic<unsigned int> g_secondFollowingIndexAfter =
    0;

std::atomic<unsigned int> g_thirdTargetIndexAfter =
    0;

std::atomic<unsigned long long> g_firstUiOrderPosition =
    0;

std::atomic<unsigned long long> g_secondUiOrderPosition =
    0;

std::atomic<unsigned long long> g_thirdUiOrderPosition =
    0;

std::atomic<bool> g_leftAnchorCaptured =
    false;

std::atomic<bool> g_rightAnchorCaptured =
    false;

std::atomic<bool> g_firstRelationEstablished =
    false;

std::atomic<bool> g_secondDualNeighborRestored =
    false;

std::atomic<bool> g_thirdSingleNeighborRestored =
    false;

std::atomic<bool> g_dualNeighborValidationCompleted =
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

struct OverflowPositions {
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

    bool leftFound =
        false;

    unsigned int leftIndex =
        0;

    bool rightFound =
        false;

    unsigned int rightIndex =
        0;

    bool targetFound =
        false;

    unsigned int targetIndex =
        0;
};

struct LogicalNeighborPositions {
    bool precedingFound =
        false;

    unsigned int precedingIndex =
        0;

    bool followingFound =
        false;

    unsigned int followingIndex =
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
        index < suffix.size();
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

    if (!NotificationAreaIcon_QueryInterface) {
        Wh_Log(
            L"NotificationAreaIcon2 "
            L"query_interface symbol not found"
        );

        return false;
    }

    if (!g_notificationAreaIconInterfaceId) {
        Wh_Log(
            L"INotificationAreaIcon IID "
            L"symbol not found"
        );

        return false;
    }

    if (!g_notificationAreaIconVectorId) {
        Wh_Log(
            L"IVector<NotificationAreaIcon> "
            L"IID symbol not found"
        );

        return false;
    }

    if (!NotificationAreaIconManager_MoveIcon) {
        Wh_Log(
            L"NotificationAreaIconManager2::"
            L"MoveIcon symbol not found"
        );

        return false;
    }

    Wh_Log(
        L"DUAL_NEIGHBOR_SUPPORT_READY "
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
        attempt < 3;
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
                sizeof(std::uint64_t) !=
            0
        ) {
            snapshot.status =
                ERROR_INVALID_DATA;

            return snapshot;
        }

        snapshot.entries.resize(
            actualBytes /
            sizeof(std::uint64_t)
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

bool IsExecutableIdentity(
    std::uint64_t identity,
    const wchar_t* executableName
) {
    return
        EndsWithOrdinalIgnoreCase(
            QueryExecutablePath(
                identity
            ),
            executableName
        );
}

bool IsLeftAnchorIdentity(
    std::uint64_t identity
) {
    return
        IsExecutableIdentity(
            identity,
            kLeftAnchorExecutableName
        );
}

bool IsRightAnchorIdentity(
    std::uint64_t identity
) {
    return
        IsExecutableIdentity(
            identity,
            kRightAnchorExecutableName
        );
}

bool IsHelperIdentity(
    std::uint64_t identity
) {
    return
        IsExecutableIdentity(
            identity,
            kHelperExecutableName
        );
}

bool IsTargetIdentity(
    std::uint64_t identity
) {
    if (
        !IsExecutableIdentity(
            identity,
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

OverflowPositions QueryOverflowPositions(
    void* targetAbi
) {
    OverflowPositions positions;

    void* taskbarModel6 =
        g_taskbarModel6.load(
            std::memory_order_acquire
        );

    void* leftAnchorAbi =
        g_leftAnchorAbi.load(
            std::memory_order_acquire
        );

    void* rightAnchorAbi =
        g_rightAnchorAbi.load(
            std::memory_order_acquire
        );

    if (
        !taskbarModel6 ||
        !targetAbi ||
        !TaskbarModel_GetOverflowIcons_Original ||
        !g_notificationAreaIconVectorId
    ) {
        return positions;
    }

    void* collectionAbi =
        nullptr;

    positions.getterResult =
        static_cast<HRESULT>(
            TaskbarModel_GetOverflowIcons_Original(
                taskbarModel6,
                &collectionAbi
            )
        );

    if (
        FAILED(
            positions.getterResult
        ) ||
        !collectionAbi
    ) {
        return positions;
    }

    void* vectorAbi =
        nullptr;

    positions.vectorQueryResult =
        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->QueryInterface(
            *g_notificationAreaIconVectorId,
            &vectorAbi
        );

    if (
        FAILED(
            positions.vectorQueryResult
        ) ||
        !vectorAbi
    ) {
        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->Release();

        return positions;
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

        return positions;
    }

    Vector_GetAt_t getAt =
        reinterpret_cast<Vector_GetAt_t>(
            vtable[6]
        );

    Vector_GetSize_t getSize =
        reinterpret_cast<Vector_GetSize_t>(
            vtable[7]
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

        return positions;
    }

    positions.sizeResult =
        getSize(
            vectorAbi,
            &positions.size
        );

    if (
        FAILED(
            positions.sizeResult
        )
    ) {
        reinterpret_cast<IUnknown*>(
            vectorAbi
        )->Release();

        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->Release();

        return positions;
    }

    positions.enumerated =
        true;

    for (
        unsigned int index = 0;
        index < positions.size;
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

        if (
            leftAnchorAbi &&
            !positions.leftFound &&
            IsSameComObject(
                itemAbi,
                leftAnchorAbi
            )
        ) {
            positions.leftFound =
                true;

            positions.leftIndex =
                index;
        }

        if (
            rightAnchorAbi &&
            !positions.rightFound &&
            IsSameComObject(
                itemAbi,
                rightAnchorAbi
            )
        ) {
            positions.rightFound =
                true;

            positions.rightIndex =
                index;
        }

        if (
            !positions.targetFound &&
            IsSameComObject(
                itemAbi,
                targetAbi
            )
        ) {
            positions.targetFound =
                true;

            positions.targetIndex =
                index;
        }

        reinterpret_cast<IUnknown*>(
            itemAbi
        )->Release();
    }

    reinterpret_cast<IUnknown*>(
        vectorAbi
    )->Release();

    reinterpret_cast<IUnknown*>(
        collectionAbi
    )->Release();

    return positions;
}

LogicalNeighborPositions GetLogicalNeighborPositions(
    const OverflowPositions& positions
) {
    LogicalNeighborPositions logical;

    const int precedingSide =
        g_precedingAnchorSide.load(
            std::memory_order_acquire
        );

    if (
        precedingSide ==
        kPrecedingLeft
    ) {
        logical.precedingFound =
            positions.leftFound;

        logical.precedingIndex =
            positions.leftIndex;

        logical.followingFound =
            positions.rightFound;

        logical.followingIndex =
            positions.rightIndex;
    } else if (
        precedingSide ==
        kPrecedingRight
    ) {
        logical.precedingFound =
            positions.rightFound;

        logical.precedingIndex =
            positions.rightIndex;

        logical.followingFound =
            positions.leftFound;

        logical.followingIndex =
            positions.leftIndex;
    }

    return logical;
}

bool EstablishLogicalNeighborOrder(
    const OverflowPositions& positions
) {
    if (
        !positions.leftFound ||
        !positions.rightFound ||
        positions.leftIndex ==
            positions.rightIndex
    ) {
        return false;
    }

    int expected =
        kPrecedingUnknown;

    const int observed =
        positions.leftIndex <
                positions.rightIndex
            ? kPrecedingLeft
            : kPrecedingRight;

    g_precedingAnchorSide.compare_exchange_strong(
        expected,
        observed,
        std::memory_order_acq_rel
    );

    return
        g_precedingAnchorSide.load(
            std::memory_order_acquire
        ) !=
        kPrecedingUnknown;
}

unsigned int ClampVectorIndex(
    unsigned int index,
    unsigned int size
) {
    if (size == 0) {
        return 0;
    }

    if (
        index >=
        size
    ) {
        return
            size -
            1;
    }

    return index;
}

unsigned int CalculateImmediatelyAfterIndex(
    unsigned int anchorIndex,
    unsigned int targetIndex,
    unsigned int size
) {
    unsigned int desiredIndex =
        targetIndex <
                anchorIndex
            ? anchorIndex
            : anchorIndex +
                1;

    return
        ClampVectorIndex(
            desiredIndex,
            size
        );
}

unsigned int CalculateImmediatelyBeforeIndex(
    unsigned int anchorIndex,
    unsigned int targetIndex,
    unsigned int size
) {
    unsigned int desiredIndex =
        targetIndex <
                anchorIndex
            ? anchorIndex -
                1
            : anchorIndex;

    return
        ClampVectorIndex(
            desiredIndex,
            size
        );
}

bool IsDirectlyBetweenLogicalNeighbors(
    const OverflowPositions& positions
) {
    if (
        !positions.targetFound
    ) {
        return false;
    }

    const LogicalNeighborPositions logical =
        GetLogicalNeighborPositions(
            positions
        );

    return
        logical.precedingFound &&
        logical.followingFound &&
        logical.precedingIndex +
                1 ==
            positions.targetIndex &&
        positions.targetIndex +
                1 ==
            logical.followingIndex;
}

bool IsCorrectSingleNeighborRelation(
    const OverflowPositions& positions
) {
    if (
        !positions.targetFound
    ) {
        return false;
    }

    const LogicalNeighborPositions logical =
        GetLogicalNeighborPositions(
            positions
        );

    if (
        logical.precedingFound &&
        !logical.followingFound
    ) {
        return
            logical.precedingIndex +
                    1 ==
                positions.targetIndex;
    }

    if (
        !logical.precedingFound &&
        logical.followingFound
    ) {
        return
            positions.targetIndex +
                    1 ==
                logical.followingIndex;
    }

    return false;
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

void CaptureAnchorInterface(
    bool left,
    unsigned long long callNumber,
    std::uint64_t identity,
    void* iconImplementation
) {
    std::atomic<void*>* slot =
        left
            ? &g_leftAnchorAbi
            : &g_rightAnchorAbi;

    std::atomic<std::uint64_t>* identitySlot =
        left
            ? &g_leftAnchorIdentity
            : &g_rightAnchorIdentity;

    std::atomic<bool>* capturedSlot =
        left
            ? &g_leftAnchorCaptured
            : &g_rightAnchorCaptured;

    if (
        slot->load(
            std::memory_order_acquire
        )
    ) {
        return;
    }

    void* queriedAbi =
        nullptr;

    const HRESULT queryResult =
        static_cast<HRESULT>(
            NotificationAreaIcon_QueryInterface(
                iconImplementation,
                *g_notificationAreaIconInterfaceId,
                &queriedAbi
            )
        );

    Wh_Log(
        L"DUAL_ANCHOR_INTERFACE_QUERY "
        L"side=\"%s\" "
        L"call=%llu "
        L"id=%llu "
        L"implementation=%p "
        L"result=0x%08X "
        L"queriedAbi=%p",
        left
            ? L"left"
            : L"right",
        callNumber,
        static_cast<unsigned long long>(
            identity
        ),
        iconImplementation,
        static_cast<unsigned int>(
            queryResult
        ),
        queriedAbi
    );

    if (
        FAILED(
            queryResult
        ) ||
        !queriedAbi
    ) {
        return;
    }

    void* expected =
        nullptr;

    if (
        slot->compare_exchange_strong(
            expected,
            queriedAbi,
            std::memory_order_acq_rel
        )
    ) {
        identitySlot->store(
            identity,
            std::memory_order_release
        );

        capturedSlot->store(
            true,
            std::memory_order_release
        );

        Wh_Log(
            L"DUAL_ANCHOR_CAPTURED "
            L"side=\"%s\" "
            L"id=%llu "
            L"abi=%p",
            left
                ? L"left"
                : L"right",
            static_cast<unsigned long long>(
                identity
            ),
            queriedAbi
        );

        return;
    }

    reinterpret_cast<IUnknown*>(
        queriedAbi
    )->Release();
}

int DetermineTargetPhase(
    std::uint64_t identity
) {
    const std::uint64_t first =
        g_firstTargetIdentity.load(
            std::memory_order_acquire
        );

    const std::uint64_t second =
        g_secondTargetIdentity.load(
            std::memory_order_acquire
        );

    const std::uint64_t third =
        g_thirdTargetIdentity.load(
            std::memory_order_acquire
        );

    if (
        first ==
        0
    ) {
        return 1;
    }

    if (
        second ==
            0 &&
        identity !=
            first
    ) {
        return 2;
    }

    if (
        third ==
            0 &&
        identity !=
            first &&
        identity !=
            second
    ) {
        return 3;
    }

    return 0;
}

bool ValidateTargetVersionPath(
    std::uint64_t identity,
    int phase
) {
    const std::wstring path =
        NormalizeSlashes(
            QueryExecutablePath(
                identity
            )
        );

    if (phase == 1) {
        return
            ContainsOrdinalIgnoreCase(
                path,
                kVersion1Marker
            );
    }

    if (phase == 2) {
        return
            ContainsOrdinalIgnoreCase(
                path,
                kVersion2Marker
            );
    }

    if (phase == 3) {
        return
            ContainsOrdinalIgnoreCase(
                path,
                kVersion3Marker
            );
    }

    return false;
}

void LogFinalValidation() {
    const std::uint64_t firstIdentity =
        g_firstTargetIdentity.load(
            std::memory_order_acquire
        );

    const std::uint64_t secondIdentity =
        g_secondTargetIdentity.load(
            std::memory_order_acquire
        );

    const std::uint64_t thirdIdentity =
        g_thirdTargetIdentity.load(
            std::memory_order_acquire
        );

    DWORD firstUid =
        0;

    DWORD secondUid =
        0;

    DWORD thirdUid =
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

    const bool thirdUidValid =
        QueryIdentityUid(
            thirdIdentity,
            &thirdUid
        );

    const bool identitiesDistinct =
        firstIdentity !=
            0 &&
        secondIdentity !=
            0 &&
        thirdIdentity !=
            0 &&
        firstIdentity !=
            secondIdentity &&
        firstIdentity !=
            thirdIdentity &&
        secondIdentity !=
            thirdIdentity;

    const bool version1Path =
        ValidateTargetVersionPath(
            firstIdentity,
            1
        );

    const bool version2Path =
        ValidateTargetVersionPath(
            secondIdentity,
            2
        );

    const bool version3Path =
        ValidateTargetVersionPath(
            thirdIdentity,
            3
        );

    const unsigned int firstOverflowSize =
        g_firstOverflowSize.load(
            std::memory_order_acquire
        );

    const unsigned int secondOverflowSize =
        g_secondOverflowSize.load(
            std::memory_order_acquire
        );

    const unsigned int firstMoveIndex =
        g_firstMoveTargetIndex.load(
            std::memory_order_acquire
        );

    const unsigned int secondMoveIndex =
        g_secondMoveTargetIndex.load(
            std::memory_order_acquire
        );

    const bool collectionChanged =
        firstOverflowSize !=
        secondOverflowSize;

    const bool savedNumericIndexInvalidated =
        firstMoveIndex !=
        secondMoveIndex;

    const unsigned long long helperCount =
        g_helperIdentityCount.load(
            std::memory_order_acquire
        );

    const bool firstRelationEstablished =
        g_firstRelationEstablished.load(
            std::memory_order_acquire
        );

    const bool secondDualNeighborRestored =
        g_secondDualNeighborRestored.load(
            std::memory_order_acquire
        );

    const bool thirdSingleNeighborRestored =
        g_thirdSingleNeighborRestored.load(
            std::memory_order_acquire
        );

    const bool exactlyThreeAnalyzerMoves =
        g_moveAttempts.load(
            std::memory_order_acquire
        ) ==
        3;

    const bool validationCompleted =
        identitiesDistinct &&
        firstUidValid &&
        secondUidValid &&
        thirdUidValid &&
        firstUid ==
            kTargetUid &&
        secondUid ==
            kTargetUid &&
        thirdUid ==
            kTargetUid &&
        version1Path &&
        version2Path &&
        version3Path &&
        helperCount ==
            3 &&
        collectionChanged &&
        savedNumericIndexInvalidated &&
        firstRelationEstablished &&
        secondDualNeighborRestored &&
        thirdSingleNeighborRestored &&
        exactlyThreeAnalyzerMoves;

    g_dualNeighborValidationCompleted.store(
        validationCompleted,
        std::memory_order_release
    );

    Wh_Log(
        L"DUAL_NEIGHBOR_FINAL_RESULT "
        L"firstIdentity=%llu "
        L"secondIdentity=%llu "
        L"thirdIdentity=%llu "
        L"identitiesDistinct=%d "
        L"firstUidValid=%d "
        L"firstUid=%u "
        L"secondUidValid=%d "
        L"secondUid=%u "
        L"thirdUidValid=%d "
        L"thirdUid=%u "
        L"version1Path=%d "
        L"version2Path=%d "
        L"version3Path=%d "
        L"helperCount=%llu "
        L"firstOverflowSize=%u "
        L"secondOverflowSize=%u "
        L"collectionChanged=%d "
        L"firstMoveIndex=%u "
        L"secondMoveIndex=%u "
        L"savedNumericIndexInvalidated=%d "
        L"firstRelationEstablished=%d "
        L"secondDualNeighborRestored=%d "
        L"thirdSingleNeighborRestored=%d "
        L"exactlyThreeAnalyzerMoves=%d "
        L"dualNeighborValidationCompleted=%d",
        static_cast<unsigned long long>(
            firstIdentity
        ),
        static_cast<unsigned long long>(
            secondIdentity
        ),
        static_cast<unsigned long long>(
            thirdIdentity
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
        thirdUidValid
            ? 1
            : 0,
        thirdUid,
        version1Path
            ? 1
            : 0,
        version2Path
            ? 1
            : 0,
        version3Path
            ? 1
            : 0,
        helperCount,
        firstOverflowSize,
        secondOverflowSize,
        collectionChanged
            ? 1
            : 0,
        firstMoveIndex,
        secondMoveIndex,
        savedNumericIndexInvalidated
            ? 1
            : 0,
        firstRelationEstablished
            ? 1
            : 0,
        secondDualNeighborRestored
            ? 1
            : 0,
        thirdSingleNeighborRestored
            ? 1
            : 0,
        exactlyThreeAnalyzerMoves
            ? 1
            : 0,
        validationCompleted
            ? 1
            : 0
    );

    Wh_Log(
        L"DUAL_NEIGHBOR_SUMMARY "
        L"leftAnchorIdentity=%llu "
        L"rightAnchorIdentity=%llu "
        L"precedingAnchorSide=%d "
        L"firstTargetIdentity=%llu "
        L"secondTargetIdentity=%llu "
        L"thirdTargetIdentity=%llu "
        L"helperCount=%llu "
        L"firstOverflowSize=%u "
        L"secondOverflowSize=%u "
        L"thirdOverflowSize=%u "
        L"firstMoveTargetIndex=%u "
        L"secondMoveTargetIndex=%u "
        L"thirdMoveTargetIndex=%u "
        L"firstPrecedingIndexAfter=%u "
        L"firstTargetIndexAfter=%u "
        L"firstFollowingIndexAfter=%u "
        L"secondPrecedingIndexBefore=%u "
        L"secondFollowingIndexBefore=%u "
        L"secondPrecedingIndexAfter=%u "
        L"secondTargetIndexAfter=%u "
        L"secondFollowingIndexAfter=%u "
        L"thirdTargetIndexAfter=%u "
        L"firstUiOrderPosition=%llu "
        L"secondUiOrderPosition=%llu "
        L"thirdUiOrderPosition=%llu "
        L"moveAttempts=%llu "
        L"dualNeighborValidationCompleted=%d",
        static_cast<unsigned long long>(
            g_leftAnchorIdentity.load(
                std::memory_order_acquire
            )
        ),
        static_cast<unsigned long long>(
            g_rightAnchorIdentity.load(
                std::memory_order_acquire
            )
        ),
        g_precedingAnchorSide.load(
            std::memory_order_acquire
        ),
        static_cast<unsigned long long>(
            firstIdentity
        ),
        static_cast<unsigned long long>(
            secondIdentity
        ),
        static_cast<unsigned long long>(
            thirdIdentity
        ),
        helperCount,
        firstOverflowSize,
        secondOverflowSize,
        g_thirdOverflowSize.load(
            std::memory_order_acquire
        ),
        firstMoveIndex,
        secondMoveIndex,
        g_thirdMoveTargetIndex.load(
            std::memory_order_acquire
        ),
        g_firstPrecedingIndexAfter.load(
            std::memory_order_acquire
        ),
        g_firstTargetIndexAfter.load(
            std::memory_order_acquire
        ),
        g_firstFollowingIndexAfter.load(
            std::memory_order_acquire
        ),
        g_secondPrecedingIndexBefore.load(
            std::memory_order_acquire
        ),
        g_secondFollowingIndexBefore.load(
            std::memory_order_acquire
        ),
        g_secondPrecedingIndexAfter.load(
            std::memory_order_acquire
        ),
        g_secondTargetIndexAfter.load(
            std::memory_order_acquire
        ),
        g_secondFollowingIndexAfter.load(
            std::memory_order_acquire
        ),
        g_thirdTargetIndexAfter.load(
            std::memory_order_acquire
        ),
        g_firstUiOrderPosition.load(
            std::memory_order_acquire
        ),
        g_secondUiOrderPosition.load(
            std::memory_order_acquire
        ),
        g_thirdUiOrderPosition.load(
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
    void* pThis,
    std::uint64_t targetIdentity,
    void* iconImplementation
) {
    if (
        !g_leftAnchorAbi.load(
            std::memory_order_acquire
        ) ||
        !g_rightAnchorAbi.load(
            std::memory_order_acquire
        )
    ) {
        Wh_Log(
            L"DUAL_NEIGHBOR_TARGET_SKIPPED "
            L"reason=\"anchors-not-captured\" "
            L"id=%llu",
            static_cast<unsigned long long>(
                targetIdentity
            )
        );

        return;
    }

    const int phase =
        DetermineTargetPhase(
            targetIdentity
        );

    if (
        phase ==
        0
    ) {
        return;
    }

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
        L"DUAL_NEIGHBOR_TARGET_QUERY "
        L"phase=%d "
        L"id=%llu "
        L"implementation=%p "
        L"result=0x%08X "
        L"targetAbi=%p",
        phase,
        static_cast<unsigned long long>(
            targetIdentity
        ),
        iconImplementation,
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

    const OverflowPositions before =
        QueryOverflowPositions(
            targetAbi
        );

    if (
        !before.enumerated ||
        !before.targetFound
    ) {
        Wh_Log(
            L"DUAL_NEIGHBOR_POSITION_FAILED "
            L"phase=%d "
            L"id=%llu "
            L"enumerated=%d "
            L"targetFound=%d",
            phase,
            static_cast<unsigned long long>(
                targetIdentity
            ),
            before.enumerated
                ? 1
                : 0,
            before.targetFound
                ? 1
                : 0
        );

        reinterpret_cast<IUnknown*>(
            targetAbi
        )->Release();

        return;
    }

    if (
        phase ==
        1
    ) {
        if (
            !before.leftFound ||
            !before.rightFound ||
            !EstablishLogicalNeighborOrder(
                before
            )
        ) {
            Wh_Log(
                L"DUAL_NEIGHBOR_FIRST_SKIPPED "
                L"reason=\"both-anchors-not-live\" "
                L"leftFound=%d "
                L"rightFound=%d",
                before.leftFound
                    ? 1
                    : 0,
                before.rightFound
                    ? 1
                    : 0
            );

            reinterpret_cast<IUnknown*>(
                targetAbi
            )->Release();

            return;
        }
    }

    const LogicalNeighborPositions logicalBefore =
        GetLogicalNeighborPositions(
            before
        );

    const bool bothNeighborsLive =
        logicalBefore.precedingFound &&
        logicalBefore.followingFound;

    const bool exactlyOneNeighborLive =
        logicalBefore.precedingFound !=
        logicalBefore.followingFound;

    Wh_Log(
        L"DUAL_NEIGHBOR_POSITION_BEFORE "
        L"phase=%d "
        L"id=%llu "
        L"size=%u "
        L"leftFound=%d "
        L"leftIndex=%u "
        L"rightFound=%d "
        L"rightIndex=%u "
        L"targetIndex=%u "
        L"precedingFound=%d "
        L"precedingIndex=%u "
        L"followingFound=%d "
        L"followingIndex=%u "
        L"bothNeighborsLive=%d "
        L"exactlyOneNeighborLive=%d",
        phase,
        static_cast<unsigned long long>(
            targetIdentity
        ),
        before.size,
        before.leftFound
            ? 1
            : 0,
        before.leftIndex,
        before.rightFound
            ? 1
            : 0,
        before.rightIndex,
        before.targetIndex,
        logicalBefore.precedingFound
            ? 1
            : 0,
        logicalBefore.precedingIndex,
        logicalBefore.followingFound
            ? 1
            : 0,
        logicalBefore.followingIndex,
        bothNeighborsLive
            ? 1
            : 0,
        exactlyOneNeighborLive
            ? 1
            : 0
    );

    unsigned int desiredIndex =
        0;

    const wchar_t* strategy =
        L"none";

    if (
        phase ==
            1 ||
        phase ==
            2
    ) {
        if (!bothNeighborsLive) {
            reinterpret_cast<IUnknown*>(
                targetAbi
            )->Release();

            return;
        }

        desiredIndex =
            CalculateImmediatelyAfterIndex(
                logicalBefore.precedingIndex,
                before.targetIndex,
                before.size
            );

        strategy =
            L"both-neighbors";
    } else {
        if (!exactlyOneNeighborLive) {
            reinterpret_cast<IUnknown*>(
                targetAbi
            )->Release();

            return;
        }

        if (
            logicalBefore.precedingFound
        ) {
            desiredIndex =
                CalculateImmediatelyAfterIndex(
                    logicalBefore.precedingIndex,
                    before.targetIndex,
                    before.size
                );

            strategy =
                L"preceding-only";
        } else {
            desiredIndex =
                CalculateImmediatelyBeforeIndex(
                    logicalBefore.followingIndex,
                    before.targetIndex,
                    before.size
                );

            strategy =
                L"following-only";
        }
    }

    if (phase == 1) {
        g_firstTargetIdentity.store(
            targetIdentity,
            std::memory_order_release
        );

        g_firstOverflowSize.store(
            before.size,
            std::memory_order_release
        );

        g_firstMoveTargetIndex.store(
            desiredIndex,
            std::memory_order_release
        );
    } else if (phase == 2) {
        g_secondTargetIdentity.store(
            targetIdentity,
            std::memory_order_release
        );

        g_secondOverflowSize.store(
            before.size,
            std::memory_order_release
        );

        g_secondMoveTargetIndex.store(
            desiredIndex,
            std::memory_order_release
        );

        g_secondPrecedingIndexBefore.store(
            logicalBefore.precedingIndex,
            std::memory_order_release
        );

        g_secondFollowingIndexBefore.store(
            logicalBefore.followingIndex,
            std::memory_order_release
        );
    } else {
        g_thirdTargetIdentity.store(
            targetIdentity,
            std::memory_order_release
        );

        g_thirdOverflowSize.store(
            before.size,
            std::memory_order_release
        );

        g_thirdMoveTargetIndex.store(
            desiredIndex,
            std::memory_order_release
        );
    }

    const unsigned long long moveNumber =
        g_moveAttempts.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    void* iconArgumentStorage =
        targetAbi;

    Wh_Log(
        L"DUAL_NEIGHBOR_MOVE_BEGIN "
        L"move=%llu "
        L"phase=%d "
        L"strategy=\"%s\" "
        L"call=%llu "
        L"id=%llu "
        L"overflowSize=%u "
        L"targetIndexBefore=%u "
        L"computedTargetIndex=%u",
        moveNumber,
        phase,
        strategy,
        callNumber,
        static_cast<unsigned long long>(
            targetIdentity
        ),
        before.size,
        before.targetIndex,
        desiredIndex
    );

    g_internalMoveDepth++;

    NotificationAreaIconManager_MoveIcon(
        pThis,
        &iconArgumentStorage,
        kOverflowLocation,
        desiredIndex
    );

    g_internalMoveDepth--;

    const OverflowPositions after =
        QueryOverflowPositions(
            targetAbi
        );

    const LogicalNeighborPositions logicalAfter =
        GetLogicalNeighborPositions(
            after
        );

    const UIOrderSnapshot uiOrder =
        CaptureUIOrderSnapshot();

    const unsigned long long uiOrderPosition =
        FindOneBasedPosition(
            uiOrder,
            targetIdentity
        );

    const bool targetIndexChanged =
        after.targetFound &&
        before.targetIndex !=
            after.targetIndex;

    const bool directBetween =
        IsDirectlyBetweenLogicalNeighbors(
            after
        );

    const bool correctSingleRelation =
        IsCorrectSingleNeighborRelation(
            after
        );

    if (phase == 1) {
        g_firstPrecedingIndexAfter.store(
            logicalAfter.precedingIndex,
            std::memory_order_release
        );

        g_firstTargetIndexAfter.store(
            after.targetIndex,
            std::memory_order_release
        );

        g_firstFollowingIndexAfter.store(
            logicalAfter.followingIndex,
            std::memory_order_release
        );

        g_firstUiOrderPosition.store(
            uiOrderPosition,
            std::memory_order_release
        );

        g_firstRelationEstablished.store(
            after.targetFound &&
                targetIndexChanged &&
                directBetween,
            std::memory_order_release
        );
    } else if (phase == 2) {
        g_secondPrecedingIndexAfter.store(
            logicalAfter.precedingIndex,
            std::memory_order_release
        );

        g_secondTargetIndexAfter.store(
            after.targetIndex,
            std::memory_order_release
        );

        g_secondFollowingIndexAfter.store(
            logicalAfter.followingIndex,
            std::memory_order_release
        );

        g_secondUiOrderPosition.store(
            uiOrderPosition,
            std::memory_order_release
        );

        g_secondDualNeighborRestored.store(
            after.targetFound &&
                targetIndexChanged &&
                directBetween,
            std::memory_order_release
        );
    } else {
        g_thirdTargetIndexAfter.store(
            after.targetIndex,
            std::memory_order_release
        );

        g_thirdUiOrderPosition.store(
            uiOrderPosition,
            std::memory_order_release
        );

        g_thirdSingleNeighborRestored.store(
            after.targetFound &&
                targetIndexChanged &&
                correctSingleRelation,
            std::memory_order_release
        );
    }

    Wh_Log(
        L"DUAL_NEIGHBOR_MOVE_COMPLETE "
        L"move=%llu "
        L"phase=%d "
        L"strategy=\"%s\" "
        L"id=%llu "
        L"afterEnumerated=%d "
        L"size=%u "
        L"leftFound=%d "
        L"leftIndex=%u "
        L"rightFound=%d "
        L"rightIndex=%u "
        L"targetFound=%d "
        L"targetIndex=%u "
        L"precedingFound=%d "
        L"precedingIndex=%u "
        L"followingFound=%d "
        L"followingIndex=%u "
        L"targetIndexChanged=%d "
        L"directBetween=%d "
        L"correctSingleRelation=%d "
        L"uiOrderPosition=%llu",
        moveNumber,
        phase,
        strategy,
        static_cast<unsigned long long>(
            targetIdentity
        ),
        after.enumerated
            ? 1
            : 0,
        after.size,
        after.leftFound
            ? 1
            : 0,
        after.leftIndex,
        after.rightFound
            ? 1
            : 0,
        after.rightIndex,
        after.targetFound
            ? 1
            : 0,
        after.targetIndex,
        logicalAfter.precedingFound
            ? 1
            : 0,
        logicalAfter.precedingIndex,
        logicalAfter.followingFound
            ? 1
            : 0,
        logicalAfter.followingIndex,
        targetIndexChanged
            ? 1
            : 0,
        directBetween
            ? 1
            : 0,
        correctSingleRelation
            ? 1
            : 0,
        uiOrderPosition
    );

    if (phase == 2) {
        const bool savedNumericIndexInvalidated =
            g_firstMoveTargetIndex.load(
                std::memory_order_acquire
            ) !=
            g_secondMoveTargetIndex.load(
                std::memory_order_acquire
            );

        Wh_Log(
            L"DUAL_NEIGHBOR_BOTH_RESULT "
            L"firstIdentity=%llu "
            L"secondIdentity=%llu "
            L"identityChanged=%d "
            L"helperCount=%llu "
            L"firstOverflowSize=%u "
            L"secondOverflowSize=%u "
            L"firstMoveTargetIndex=%u "
            L"secondMoveTargetIndex=%u "
            L"savedNumericIndexInvalidated=%d "
            L"firstRelationEstablished=%d "
            L"secondDualNeighborRestored=%d",
            static_cast<unsigned long long>(
                g_firstTargetIdentity.load(
                    std::memory_order_acquire
                )
            ),
            static_cast<unsigned long long>(
                targetIdentity
            ),
            g_firstTargetIdentity.load(
                std::memory_order_acquire
            ) !=
                    targetIdentity
                ? 1
                : 0,
            g_helperIdentityCount.load(
                std::memory_order_acquire
            ),
            g_firstOverflowSize.load(
                std::memory_order_acquire
            ),
            g_secondOverflowSize.load(
                std::memory_order_acquire
            ),
            g_firstMoveTargetIndex.load(
                std::memory_order_acquire
            ),
            g_secondMoveTargetIndex.load(
                std::memory_order_acquire
            ),
            savedNumericIndexInvalidated
                ? 1
                : 0,
            g_firstRelationEstablished.load(
                std::memory_order_acquire
            )
                ? 1
                : 0,
            g_secondDualNeighborRestored.load(
                std::memory_order_acquire
            )
                ? 1
                : 0
        );
    }

    if (phase == 3) {
        const LogicalNeighborPositions beforeLogical =
            GetLogicalNeighborPositions(
                before
            );

        Wh_Log(
            L"DUAL_NEIGHBOR_FALLBACK_RESULT "
            L"thirdIdentity=%llu "
            L"strategy=\"%s\" "
            L"precedingFoundBefore=%d "
            L"followingFoundBefore=%d "
            L"exactlyOneNeighborBefore=%d "
            L"leftFoundBefore=%d "
            L"rightFoundBefore=%d "
            L"correctSingleRelationAfter=%d "
            L"thirdSingleNeighborRestored=%d",
            static_cast<unsigned long long>(
                targetIdentity
            ),
            strategy,
            beforeLogical.precedingFound
                ? 1
                : 0,
            beforeLogical.followingFound
                ? 1
                : 0,
            beforeLogical.precedingFound !=
                    beforeLogical.followingFound
                ? 1
                : 0,
            before.leftFound
                ? 1
                : 0,
            before.rightFound
                ? 1
                : 0,
            correctSingleRelation
                ? 1
                : 0,
            g_thirdSingleNeighborRestored.load(
                std::memory_order_acquire
            )
                ? 1
                : 0
        );

        LogFinalValidation();
    }

    reinterpret_cast<IUnknown*>(
        targetAbi
    )->Release();
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

    std::vector<std::uint64_t> leftAnchorAdded;
    std::vector<std::uint64_t> rightAnchorAdded;
    std::vector<std::uint64_t> targetAdded;
    std::vector<std::uint64_t> helperAdded;

    for (
        std::uint64_t identity :
        added
    ) {
        if (
            IsLeftAnchorIdentity(
                identity
            )
        ) {
            leftAnchorAdded.push_back(
                identity
            );
        }

        if (
            IsRightAnchorIdentity(
                identity
            )
        ) {
            rightAnchorAdded.push_back(
                identity
            );
        }

        if (
            IsTargetIdentity(
                identity
            )
        ) {
            targetAdded.push_back(
                identity
            );
        }

        if (
            IsHelperIdentity(
                identity
            )
        ) {
            helperAdded.push_back(
                identity
            );
        }
    }

    Wh_Log(
        L"VISIBLE_ADD_DELTA "
        L"call=%llu "
        L"parentAddCall=%llu "
        L"addedCount=%llu "
        L"leftAnchorAdded=%llu "
        L"rightAnchorAdded=%llu "
        L"targetAdded=%llu "
        L"helperAdded=%llu",
        callNumber,
        g_addIconContext.callNumber,
        static_cast<unsigned long long>(
            added.size()
        ),
        static_cast<unsigned long long>(
            leftAnchorAdded.size()
        ),
        static_cast<unsigned long long>(
            rightAnchorAdded.size()
        ),
        static_cast<unsigned long long>(
            targetAdded.size()
        ),
        static_cast<unsigned long long>(
            helperAdded.size()
        )
    );

    if (
        leftAnchorAdded.size() ==
        1
    ) {
        CaptureAnchorInterface(
            true,
            callNumber,
            leftAnchorAdded.front(),
            iconImplementation
        );

        return;
    }

    if (
        rightAnchorAdded.size() ==
        1
    ) {
        CaptureAnchorInterface(
            false,
            callNumber,
            rightAnchorAdded.front(),
            iconImplementation
        );

        return;
    }

    if (
        helperAdded.size() ==
        1
    ) {
        const unsigned long long helperNumber =
            g_helperIdentityCount.fetch_add(
                1,
                std::memory_order_relaxed
            ) +
            1;

        Wh_Log(
            L"DUAL_NEIGHBOR_HELPER_OBSERVED "
            L"helper=%llu "
            L"id=%llu",
            helperNumber,
            static_cast<unsigned long long>(
                helperAdded.front()
            )
        );

        return;
    }

    if (
        targetAdded.size() ==
        1
    ) {
        HandleTargetIcon(
            callNumber,
            pThis,
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
        L"0.21.0 initializing"
    );

    if (
        !IsPrimaryShellProcess()
    ) {
        Wh_Log(
            L"DUAL_NEIGHBOR_TEST_SKIPPED "
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
        L"DUAL_NEIGHBOR_TEST_READY "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    return TRUE;
}

void Wh_ModUninit() {
    void* leftAnchorAbi =
        g_leftAnchorAbi.exchange(
            nullptr,
            std::memory_order_acq_rel
        );

    if (leftAnchorAbi) {
        reinterpret_cast<IUnknown*>(
            leftAnchorAbi
        )->Release();
    }

    void* rightAnchorAbi =
        g_rightAnchorAbi.exchange(
            nullptr,
            std::memory_order_acq_rel
        );

    if (rightAnchorAbi) {
        reinterpret_cast<IUnknown*>(
            rightAnchorAbi
        )->Release();
    }

    Wh_Log(
        L"Tray Add Path Analyzer stopped; "
        L"addIconCalls=%llu "
        L"visibleAddCalls=%llu "
        L"overflowGetterCalls=%llu "
        L"moveAttempts=%llu "
        L"leftAnchorCaptured=%d "
        L"rightAnchorCaptured=%d "
        L"helperCount=%llu "
        L"firstTargetIdentity=%llu "
        L"secondTargetIdentity=%llu "
        L"thirdTargetIdentity=%llu "
        L"firstRelationEstablished=%d "
        L"secondDualNeighborRestored=%d "
        L"thirdSingleNeighborRestored=%d "
        L"dualNeighborValidationCompleted=%d",
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
        g_leftAnchorCaptured.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_rightAnchorCaptured.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_helperIdentityCount.load(
            std::memory_order_acquire
        ),
        static_cast<unsigned long long>(
            g_firstTargetIdentity.load(
                std::memory_order_acquire
            )
        ),
        static_cast<unsigned long long>(
            g_secondTargetIdentity.load(
                std::memory_order_acquire
            )
        ),
        static_cast<unsigned long long>(
            g_thirdTargetIdentity.load(
                std::memory_order_acquire
            )
        ),
        g_firstRelationEstablished.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_secondDualNeighborRestored.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_thirdSingleNeighborRestored.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_dualNeighborValidationCompleted.load(
            std::memory_order_acquire
        )
            ? 1
            : 0
    );
}
