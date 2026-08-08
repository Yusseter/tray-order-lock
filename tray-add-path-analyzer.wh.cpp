// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Tests outward canonical-neighbor search for replacement tray identities.
// @version         0.22.0
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

Version 0.22.0 tests outward canonical-neighbor search when both immediate
logical neighbors of a replacement UID-based tray icon have disappeared.

Four stable GUID-based anchor icons are created:

Anchor A
Anchor B
Anchor C
Anchor D

Their actual live overflow order is observed rather than assumed.

During Version-1.0.0, the analyzer verifies that B and C are the two middle
anchors. It records the canonical order from the live collection and places
the target between those two middle anchors:

far predecessor
-> near predecessor
-> target
-> near follower
-> far follower

After Version-1.0.0 exits:

- Anchor B is stopped.
- Anchor C is stopped.
- Three helper icons are added.

The two immediate canonical neighbors are therefore gone and the live
collection geometry changes.

Version-2.0.0 creates a replacement UID identity. The analyzer searches
outward through the saved canonical sequence:

- first checks the missing near predecessor,
- then finds the far predecessor,
- first checks the missing near follower,
- then finds the far follower.

The replacement target is placed between those surviving farther neighbors
using their CURRENT live overflow positions.

After Version-2.0.0 exits, Anchor A is also stopped.

Version-3.0.0 creates another replacement identity. At this point both near
neighbors remain missing and only one of the original far anchors remains.
The analyzer searches outward again and restores the target relative to that
single surviving distant neighbor.

The experiment verifies:

- Three distinct Windows target identities are created.
- B and C are the immediate canonical neighbors established in phase 1.
- Both immediate neighbors are absent in phases 2 and 3.
- Three helpers change the collection geometry.
- Phase 2 finds both farther neighbors at search depth 2.
- Phase 2 restores the replacement inside the surviving canonical interval.
- The saved phase-1 numeric index is no longer suitable in phase 2.
- Phase 3 finds exactly one surviving farther neighbor at search depth 2.
- Phase 3 restores the target on the correct side of that distant neighbor.
- Exactly three analyzer MoveIcon calls occur.
- No anchor, helper, or unrelated icon is moved.
- The analyzer performs no registry writes.
*/
// ==/WindhawkModReadme==

#include <windows.h>
#include <unknwn.h>
#include <windhawk_utils.h>

#include <algorithm>
#include <array>
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

constexpr int kAnchorCount =
    4;

constexpr int kAnchorA =
    0;

constexpr int kAnchorB =
    1;

constexpr int kAnchorC =
    2;

constexpr int kAnchorD =
    3;

constexpr wchar_t kAnchorAExecutableName[] =
    L"trayorderanchoraprobev220.exe";

constexpr wchar_t kAnchorBExecutableName[] =
    L"trayorderanchorbprobev220.exe";

constexpr wchar_t kAnchorCExecutableName[] =
    L"trayorderanchorcprobev220.exe";

constexpr wchar_t kAnchorDExecutableName[] =
    L"trayorderanchordprobev220.exe";

constexpr const wchar_t* kAnchorExecutableNames[
    kAnchorCount
] = {
    kAnchorAExecutableName,
    kAnchorBExecutableName,
    kAnchorCExecutableName,
    kAnchorDExecutableName,
};

constexpr wchar_t kTargetExecutableName[] =
    L"trayuidoutwardrestoreprobev220.exe";

constexpr wchar_t kHelperExecutableName[] =
    L"trayordercollectionhelperv220.exe";

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

constexpr int kInvalidAnchorSlot =
    -1;

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

std::atomic<void*> g_anchorAbis[
    kAnchorCount
]{};

std::atomic<std::uint64_t> g_anchorIdentities[
    kAnchorCount
]{};

std::atomic<bool> g_anchorCaptured[
    kAnchorCount
]{};

std::atomic<int> g_farPrecedingSlot =
    kInvalidAnchorSlot;

std::atomic<int> g_nearPrecedingSlot =
    kInvalidAnchorSlot;

std::atomic<int> g_nearFollowingSlot =
    kInvalidAnchorSlot;

std::atomic<int> g_farFollowingSlot =
    kInvalidAnchorSlot;

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

std::atomic<unsigned int> g_secondPredecessorDepth =
    0;

std::atomic<unsigned int> g_secondFollowerDepth =
    0;

std::atomic<unsigned int> g_thirdLiveNeighborDepth =
    0;

std::atomic<unsigned long long> g_firstUiOrderPosition =
    0;

std::atomic<unsigned long long> g_secondUiOrderPosition =
    0;

std::atomic<unsigned long long> g_thirdUiOrderPosition =
    0;

std::atomic<bool> g_canonicalOrderEstablished =
    false;

std::atomic<bool> g_firstImmediateRelationEstablished =
    false;

std::atomic<bool> g_secondImmediateNeighborsAbsent =
    false;

std::atomic<bool> g_secondOutwardBothRestored =
    false;

std::atomic<bool> g_thirdImmediateNeighborsAbsent =
    false;

std::atomic<bool> g_thirdOutwardSingleRestored =
    false;

std::atomic<bool> g_outwardSearchValidationCompleted =
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

    bool anchorFound[
        kAnchorCount
    ]{};

    unsigned int anchorIndex[
        kAnchorCount
    ]{};

    bool targetFound =
        false;

    unsigned int targetIndex =
        0;
};

struct CanonicalSearchResult {
    bool found =
        false;

    int anchorSlot =
        kInvalidAnchorSlot;

    unsigned int index =
        0;

    unsigned int depth =
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
            L"OUTWARD_SEARCH_REQUIRED_SYMBOL_MISSING"
        );

        return false;
    }

    Wh_Log(
        L"OUTWARD_SEARCH_SUPPORT_READY "
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

int GetAnchorSlotForIdentity(
    std::uint64_t identity
) {
    for (
        int slot = 0;
        slot <
            kAnchorCount;
        slot++
    ) {
        if (
            IsExecutableIdentity(
                identity,
                kAnchorExecutableNames[
                    slot
                ]
            )
        ) {
            return slot;
        }
    }

    return
        kInvalidAnchorSlot;
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

    if (
        !taskbarModel6 ||
        !targetAbi ||
        !TaskbarModel_GetOverflowIcons_Original ||
        !g_notificationAreaIconVectorId
    ) {
        return positions;
    }

    void* anchorAbis[
        kAnchorCount
    ]{};

    for (
        int slot = 0;
        slot <
            kAnchorCount;
        slot++
    ) {
        anchorAbis[
            slot
        ] =
            g_anchorAbis[
                slot
            ].load(
                std::memory_order_acquire
            );
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
        index <
            positions.size;
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

        for (
            int slot = 0;
            slot <
                kAnchorCount;
            slot++
        ) {
            if (
                anchorAbis[
                    slot
                ] &&
                !positions.anchorFound[
                    slot
                ] &&
                IsSameComObject(
                    itemAbi,
                    anchorAbis[
                        slot
                    ]
                )
            ) {
                positions.anchorFound[
                    slot
                ] =
                    true;

                positions.anchorIndex[
                    slot
                ] =
                    index;
            }
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

bool GetAnchorPosition(
    const OverflowPositions& positions,
    int slot,
    unsigned int* index
) {
    if (
        slot <
            0 ||
        slot >=
            kAnchorCount
    ) {
        return false;
    }

    if (
        !positions.anchorFound[
            slot
        ]
    ) {
        return false;
    }

    if (index) {
        *index =
            positions.anchorIndex[
                slot
            ];
    }

    return true;
}

bool EstablishCanonicalOrder(
    const OverflowPositions& positions
) {
    for (
        int slot = 0;
        slot <
            kAnchorCount;
        slot++
    ) {
        if (
            !positions.anchorFound[
                slot
            ]
        ) {
            return false;
        }
    }

    std::array<
        std::pair<
            unsigned int,
            int
        >,
        kAnchorCount
    > ordered = {{
        {
            positions.anchorIndex[
                kAnchorA
            ],
            kAnchorA
        },
        {
            positions.anchorIndex[
                kAnchorB
            ],
            kAnchorB
        },
        {
            positions.anchorIndex[
                kAnchorC
            ],
            kAnchorC
        },
        {
            positions.anchorIndex[
                kAnchorD
            ],
            kAnchorD
        },
    }};

    std::sort(
        ordered.begin(),
        ordered.end(),
        [](
            const auto& left,
            const auto& right
        ) {
            return
                left.first <
                right.first;
        }
    );

    const int middle1 =
        ordered[
            1
        ].second;

    const int middle2 =
        ordered[
            2
        ].second;

    const int outer1 =
        ordered[
            0
        ].second;

    const int outer2 =
        ordered[
            3
        ].second;

    const bool middleAreBandC =
        (
            middle1 ==
                kAnchorB &&
            middle2 ==
                kAnchorC
        ) ||
        (
            middle1 ==
                kAnchorC &&
            middle2 ==
                kAnchorB
        );

    const bool outerAreAandD =
        (
            outer1 ==
                kAnchorA &&
            outer2 ==
                kAnchorD
        ) ||
        (
            outer1 ==
                kAnchorD &&
            outer2 ==
                kAnchorA
        );

    if (
        !middleAreBandC ||
        !outerAreAandD
    ) {
        Wh_Log(
            L"OUTWARD_CANONICAL_ORDER_REJECTED "
            L"orderedSlots=%d,%d,%d,%d",
            ordered[
                0
            ].second,
            ordered[
                1
            ].second,
            ordered[
                2
            ].second,
            ordered[
                3
            ].second
        );

        return false;
    }

    g_farPrecedingSlot.store(
        ordered[
            0
        ].second,
        std::memory_order_release
    );

    g_nearPrecedingSlot.store(
        ordered[
            1
        ].second,
        std::memory_order_release
    );

    g_nearFollowingSlot.store(
        ordered[
            2
        ].second,
        std::memory_order_release
    );

    g_farFollowingSlot.store(
        ordered[
            3
        ].second,
        std::memory_order_release
    );

    g_canonicalOrderEstablished.store(
        true,
        std::memory_order_release
    );

    Wh_Log(
        L"OUTWARD_CANONICAL_ORDER_ESTABLISHED "
        L"farPrecedingSlot=%d "
        L"nearPrecedingSlot=%d "
        L"nearFollowingSlot=%d "
        L"farFollowingSlot=%d "
        L"indices=%u,%u,%u,%u",
        ordered[
            0
        ].second,
        ordered[
            1
        ].second,
        ordered[
            2
        ].second,
        ordered[
            3
        ].second,
        ordered[
            0
        ].first,
        ordered[
            1
        ].first,
        ordered[
            2
        ].first,
        ordered[
            3
        ].first
    );

    return true;
}

CanonicalSearchResult SearchPredecessorOutward(
    const OverflowPositions& positions
) {
    CanonicalSearchResult result;

    const int candidates[] = {
        g_nearPrecedingSlot.load(
            std::memory_order_acquire
        ),
        g_farPrecedingSlot.load(
            std::memory_order_acquire
        ),
    };

    for (
        unsigned int candidate = 0;
        candidate <
            ARRAYSIZE(
                candidates
            );
        candidate++
    ) {
        unsigned int index =
            0;

        if (
            GetAnchorPosition(
                positions,
                candidates[
                    candidate
                ],
                &index
            )
        ) {
            result.found =
                true;

            result.anchorSlot =
                candidates[
                    candidate
                ];

            result.index =
                index;

            result.depth =
                candidate +
                1;

            return result;
        }
    }

    return result;
}

CanonicalSearchResult SearchFollowerOutward(
    const OverflowPositions& positions
) {
    CanonicalSearchResult result;

    const int candidates[] = {
        g_nearFollowingSlot.load(
            std::memory_order_acquire
        ),
        g_farFollowingSlot.load(
            std::memory_order_acquire
        ),
    };

    for (
        unsigned int candidate = 0;
        candidate <
            ARRAYSIZE(
                candidates
            );
        candidate++
    ) {
        unsigned int index =
            0;

        if (
            GetAnchorPosition(
                positions,
                candidates[
                    candidate
                ],
                &index
            )
        ) {
            result.found =
                true;

            result.anchorSlot =
                candidates[
                    candidate
                ];

            result.index =
                index;

            result.depth =
                candidate +
                1;

            return result;
        }
    }

    return result;
}

unsigned int ClampVectorIndex(
    unsigned int index,
    unsigned int size
) {
    if (
        size ==
        0
    ) {
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
        0;

    if (
        targetIndex <
        anchorIndex
    ) {
        desiredIndex =
            anchorIndex >
                    0
                ? anchorIndex -
                    1
                : 0;
    } else {
        desiredIndex =
            anchorIndex;
    }

    return
        ClampVectorIndex(
            desiredIndex,
            size
        );
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

    if (
        phase ==
        1
    ) {
        return
            ContainsOrdinalIgnoreCase(
                path,
                kVersion1Marker
            );
    }

    if (
        phase ==
        2
    ) {
        return
            ContainsOrdinalIgnoreCase(
                path,
                kVersion2Marker
            );
    }

    if (
        phase ==
        3
    ) {
        return
            ContainsOrdinalIgnoreCase(
                path,
                kVersion3Marker
            );
    }

    return false;
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

void CaptureAnchorInterface(
    int anchorSlot,
    unsigned long long callNumber,
    std::uint64_t identity,
    void* iconImplementation
) {
    if (
        anchorSlot <
            0 ||
        anchorSlot >=
            kAnchorCount
    ) {
        return;
    }

    if (
        g_anchorAbis[
            anchorSlot
        ].load(
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
        L"OUTWARD_ANCHOR_QUERY "
        L"slot=%d "
        L"call=%llu "
        L"id=%llu "
        L"result=0x%08X "
        L"abi=%p",
        anchorSlot,
        callNumber,
        static_cast<unsigned long long>(
            identity
        ),
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
        g_anchorAbis[
            anchorSlot
        ].compare_exchange_strong(
            expected,
            queriedAbi,
            std::memory_order_acq_rel
        )
    ) {
        g_anchorIdentities[
            anchorSlot
        ].store(
            identity,
            std::memory_order_release
        );

        g_anchorCaptured[
            anchorSlot
        ].store(
            true,
            std::memory_order_release
        );

        Wh_Log(
            L"OUTWARD_ANCHOR_CAPTURED "
            L"slot=%d "
            L"id=%llu "
            L"abi=%p",
            anchorSlot,
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

bool AllAnchorsCaptured() {
    for (
        int slot = 0;
        slot <
            kAnchorCount;
        slot++
    ) {
        if (
            !g_anchorCaptured[
                slot
            ].load(
                std::memory_order_acquire
            )
        ) {
            return false;
        }
    }

    return true;
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

    const bool collectionChanged =
        firstOverflowSize !=
        secondOverflowSize;

    const bool numericIndexInvalidated =
        g_firstMoveTargetIndex.load(
            std::memory_order_acquire
        ) !=
        g_secondMoveTargetIndex.load(
            std::memory_order_acquire
        );

    const bool exactlyThreeMoves =
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
        AllAnchorsCaptured() &&
        g_canonicalOrderEstablished.load(
            std::memory_order_acquire
        ) &&
        g_helperIdentityCount.load(
            std::memory_order_acquire
        ) ==
            3 &&
        collectionChanged &&
        numericIndexInvalidated &&
        g_firstImmediateRelationEstablished.load(
            std::memory_order_acquire
        ) &&
        g_secondImmediateNeighborsAbsent.load(
            std::memory_order_acquire
        ) &&
        g_secondPredecessorDepth.load(
            std::memory_order_acquire
        ) ==
            2 &&
        g_secondFollowerDepth.load(
            std::memory_order_acquire
        ) ==
            2 &&
        g_secondOutwardBothRestored.load(
            std::memory_order_acquire
        ) &&
        g_thirdImmediateNeighborsAbsent.load(
            std::memory_order_acquire
        ) &&
        g_thirdLiveNeighborDepth.load(
            std::memory_order_acquire
        ) ==
            2 &&
        g_thirdOutwardSingleRestored.load(
            std::memory_order_acquire
        ) &&
        exactlyThreeMoves;

    g_outwardSearchValidationCompleted.store(
        validationCompleted,
        std::memory_order_release
    );

    Wh_Log(
        L"OUTWARD_SEARCH_FINAL_RESULT "
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
        L"allAnchorsCaptured=%d "
        L"canonicalOrderEstablished=%d "
        L"helperCount=%llu "
        L"firstOverflowSize=%u "
        L"secondOverflowSize=%u "
        L"collectionChanged=%d "
        L"firstMoveIndex=%u "
        L"secondMoveIndex=%u "
        L"numericIndexInvalidated=%d "
        L"firstImmediateRelationEstablished=%d "
        L"secondImmediateNeighborsAbsent=%d "
        L"secondPredecessorDepth=%u "
        L"secondFollowerDepth=%u "
        L"secondOutwardBothRestored=%d "
        L"thirdImmediateNeighborsAbsent=%d "
        L"thirdLiveNeighborDepth=%u "
        L"thirdOutwardSingleRestored=%d "
        L"exactlyThreeMoves=%d "
        L"outwardSearchValidationCompleted=%d",
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
        AllAnchorsCaptured()
            ? 1
            : 0,
        g_canonicalOrderEstablished.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_helperIdentityCount.load(
            std::memory_order_acquire
        ),
        firstOverflowSize,
        secondOverflowSize,
        collectionChanged
            ? 1
            : 0,
        g_firstMoveTargetIndex.load(
            std::memory_order_acquire
        ),
        g_secondMoveTargetIndex.load(
            std::memory_order_acquire
        ),
        numericIndexInvalidated
            ? 1
            : 0,
        g_firstImmediateRelationEstablished.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_secondImmediateNeighborsAbsent.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_secondPredecessorDepth.load(
            std::memory_order_acquire
        ),
        g_secondFollowerDepth.load(
            std::memory_order_acquire
        ),
        g_secondOutwardBothRestored.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_thirdImmediateNeighborsAbsent.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_thirdLiveNeighborDepth.load(
            std::memory_order_acquire
        ),
        g_thirdOutwardSingleRestored.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        exactlyThreeMoves
            ? 1
            : 0,
        validationCompleted
            ? 1
            : 0
    );

    Wh_Log(
        L"OUTWARD_SEARCH_SUMMARY "
        L"farPrecedingSlot=%d "
        L"nearPrecedingSlot=%d "
        L"nearFollowingSlot=%d "
        L"farFollowingSlot=%d "
        L"firstTargetIdentity=%llu "
        L"secondTargetIdentity=%llu "
        L"thirdTargetIdentity=%llu "
        L"firstOverflowSize=%u "
        L"secondOverflowSize=%u "
        L"thirdOverflowSize=%u "
        L"firstMoveTargetIndex=%u "
        L"secondMoveTargetIndex=%u "
        L"thirdMoveTargetIndex=%u "
        L"secondPredecessorDepth=%u "
        L"secondFollowerDepth=%u "
        L"thirdLiveNeighborDepth=%u "
        L"firstUiOrderPosition=%llu "
        L"secondUiOrderPosition=%llu "
        L"thirdUiOrderPosition=%llu "
        L"moveAttempts=%llu "
        L"outwardSearchValidationCompleted=%d",
        g_farPrecedingSlot.load(
            std::memory_order_acquire
        ),
        g_nearPrecedingSlot.load(
            std::memory_order_acquire
        ),
        g_nearFollowingSlot.load(
            std::memory_order_acquire
        ),
        g_farFollowingSlot.load(
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
        g_firstOverflowSize.load(
            std::memory_order_acquire
        ),
        g_secondOverflowSize.load(
            std::memory_order_acquire
        ),
        g_thirdOverflowSize.load(
            std::memory_order_acquire
        ),
        g_firstMoveTargetIndex.load(
            std::memory_order_acquire
        ),
        g_secondMoveTargetIndex.load(
            std::memory_order_acquire
        ),
        g_thirdMoveTargetIndex.load(
            std::memory_order_acquire
        ),
        g_secondPredecessorDepth.load(
            std::memory_order_acquire
        ),
        g_secondFollowerDepth.load(
            std::memory_order_acquire
        ),
        g_thirdLiveNeighborDepth.load(
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
    if (!AllAnchorsCaptured()) {
        Wh_Log(
            L"OUTWARD_TARGET_SKIPPED "
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
        L"OUTWARD_TARGET_QUERY "
        L"phase=%d "
        L"id=%llu "
        L"result=0x%08X "
        L"abi=%p",
        phase,
        static_cast<unsigned long long>(
            targetIdentity
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

    const OverflowPositions before =
        QueryOverflowPositions(
            targetAbi
        );

    if (
        !before.enumerated ||
        !before.targetFound
    ) {
        reinterpret_cast<IUnknown*>(
            targetAbi
        )->Release();

        return;
    }

    unsigned int desiredIndex =
        0;

    const wchar_t* strategy =
        L"none";

    CanonicalSearchResult predecessor;
    CanonicalSearchResult follower;

    if (
        phase ==
        1
    ) {
        if (
            !EstablishCanonicalOrder(
                before
            )
        ) {
            reinterpret_cast<IUnknown*>(
                targetAbi
            )->Release();

            return;
        }

        unsigned int nearPrecedingIndex =
            0;

        unsigned int nearFollowingIndex =
            0;

        const bool nearPrecedingFound =
            GetAnchorPosition(
                before,
                g_nearPrecedingSlot.load(
                    std::memory_order_acquire
                ),
                &nearPrecedingIndex
            );

        const bool nearFollowingFound =
            GetAnchorPosition(
                before,
                g_nearFollowingSlot.load(
                    std::memory_order_acquire
                ),
                &nearFollowingIndex
            );

        if (
            !nearPrecedingFound ||
            !nearFollowingFound
        ) {
            reinterpret_cast<IUnknown*>(
                targetAbi
            )->Release();

            return;
        }

        desiredIndex =
            CalculateImmediatelyAfterIndex(
                nearPrecedingIndex,
                before.targetIndex,
                before.size
            );

        strategy =
            L"immediate-neighbors";

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
    } else {
        if (
            !g_canonicalOrderEstablished.load(
                std::memory_order_acquire
            )
        ) {
            reinterpret_cast<IUnknown*>(
                targetAbi
            )->Release();

            return;
        }

        const int nearPrecedingSlot =
            g_nearPrecedingSlot.load(
                std::memory_order_acquire
            );

        const int nearFollowingSlot =
            g_nearFollowingSlot.load(
                std::memory_order_acquire
            );

        const bool nearPrecedingLive =
            GetAnchorPosition(
                before,
                nearPrecedingSlot,
                nullptr
            );

        const bool nearFollowingLive =
            GetAnchorPosition(
                before,
                nearFollowingSlot,
                nullptr
            );

        const bool immediateNeighborsAbsent =
            !nearPrecedingLive &&
            !nearFollowingLive;

        predecessor =
            SearchPredecessorOutward(
                before
            );

        follower =
            SearchFollowerOutward(
                before
            );

        Wh_Log(
            L"OUTWARD_SEARCH_BEFORE "
            L"phase=%d "
            L"id=%llu "
            L"size=%u "
            L"targetIndex=%u "
            L"nearPrecedingLive=%d "
            L"nearFollowingLive=%d "
            L"immediateNeighborsAbsent=%d "
            L"predecessorFound=%d "
            L"predecessorSlot=%d "
            L"predecessorIndex=%u "
            L"predecessorDepth=%u "
            L"followerFound=%d "
            L"followerSlot=%d "
            L"followerIndex=%u "
            L"followerDepth=%u",
            phase,
            static_cast<unsigned long long>(
                targetIdentity
            ),
            before.size,
            before.targetIndex,
            nearPrecedingLive
                ? 1
                : 0,
            nearFollowingLive
                ? 1
                : 0,
            immediateNeighborsAbsent
                ? 1
                : 0,
            predecessor.found
                ? 1
                : 0,
            predecessor.anchorSlot,
            predecessor.index,
            predecessor.depth,
            follower.found
                ? 1
                : 0,
            follower.anchorSlot,
            follower.index,
            follower.depth
        );

        if (
            !immediateNeighborsAbsent
        ) {
            reinterpret_cast<IUnknown*>(
                targetAbi
            )->Release();

            return;
        }

        if (
            phase ==
            2
        ) {
            if (
                !predecessor.found ||
                !follower.found
            ) {
                reinterpret_cast<IUnknown*>(
                    targetAbi
                )->Release();

                return;
            }

            desiredIndex =
                CalculateImmediatelyAfterIndex(
                    predecessor.index,
                    before.targetIndex,
                    before.size
                );

            strategy =
                L"outward-both";

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

            g_secondPredecessorDepth.store(
                predecessor.depth,
                std::memory_order_release
            );

            g_secondFollowerDepth.store(
                follower.depth,
                std::memory_order_release
            );

            g_secondImmediateNeighborsAbsent.store(
                true,
                std::memory_order_release
            );
        } else {
            const bool exactlyOneFound =
                predecessor.found !=
                follower.found;

            if (!exactlyOneFound) {
                reinterpret_cast<IUnknown*>(
                    targetAbi
                )->Release();

                return;
            }

            if (predecessor.found) {
                desiredIndex =
                    CalculateImmediatelyAfterIndex(
                        predecessor.index,
                        before.targetIndex,
                        before.size
                    );

                strategy =
                    L"outward-predecessor-only";

                g_thirdLiveNeighborDepth.store(
                    predecessor.depth,
                    std::memory_order_release
                );
            } else {
                desiredIndex =
                    CalculateImmediatelyBeforeIndex(
                        follower.index,
                        before.targetIndex,
                        before.size
                    );

                strategy =
                    L"outward-follower-only";

                g_thirdLiveNeighborDepth.store(
                    follower.depth,
                    std::memory_order_release
                );
            }

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

            g_thirdImmediateNeighborsAbsent.store(
                true,
                std::memory_order_release
            );
        }
    }

    const unsigned long long moveNumber =
        g_moveAttempts.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    Wh_Log(
        L"OUTWARD_MOVE_BEGIN "
        L"move=%llu "
        L"phase=%d "
        L"strategy=\"%s\" "
        L"id=%llu "
        L"overflowSize=%u "
        L"targetIndexBefore=%u "
        L"computedTargetIndex=%u",
        moveNumber,
        phase,
        strategy,
        static_cast<unsigned long long>(
            targetIdentity
        ),
        before.size,
        before.targetIndex,
        desiredIndex
    );

    void* iconArgumentStorage =
        targetAbi;

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

    bool relationValidated =
        false;

    if (
        phase ==
        1
    ) {
        unsigned int farPrecedingIndex =
            0;

        unsigned int nearPrecedingIndex =
            0;

        unsigned int nearFollowingIndex =
            0;

        unsigned int farFollowingIndex =
            0;

        const bool allCanonicalAnchorsLive =
            GetAnchorPosition(
                after,
                g_farPrecedingSlot.load(
                    std::memory_order_acquire
                ),
                &farPrecedingIndex
            ) &&
            GetAnchorPosition(
                after,
                g_nearPrecedingSlot.load(
                    std::memory_order_acquire
                ),
                &nearPrecedingIndex
            ) &&
            GetAnchorPosition(
                after,
                g_nearFollowingSlot.load(
                    std::memory_order_acquire
                ),
                &nearFollowingIndex
            ) &&
            GetAnchorPosition(
                after,
                g_farFollowingSlot.load(
                    std::memory_order_acquire
                ),
                &farFollowingIndex
            );

        relationValidated =
            allCanonicalAnchorsLive &&
            after.targetFound &&
            farPrecedingIndex <
                nearPrecedingIndex &&
            nearPrecedingIndex +
                    1 ==
                after.targetIndex &&
            after.targetIndex +
                    1 ==
                nearFollowingIndex &&
            nearFollowingIndex <
                farFollowingIndex;

        g_firstUiOrderPosition.store(
            uiOrderPosition,
            std::memory_order_release
        );

        g_firstImmediateRelationEstablished.store(
            targetIndexChanged &&
                relationValidated,
            std::memory_order_release
        );
    } else if (
        phase ==
        2
    ) {
        const CanonicalSearchResult afterPredecessor =
            SearchPredecessorOutward(
                after
            );

        const CanonicalSearchResult afterFollower =
            SearchFollowerOutward(
                after
            );

        relationValidated =
            after.targetFound &&
            afterPredecessor.found &&
            afterFollower.found &&
            afterPredecessor.depth ==
                2 &&
            afterFollower.depth ==
                2 &&
            afterPredecessor.index <
                after.targetIndex &&
            after.targetIndex <
                afterFollower.index &&
            afterPredecessor.index +
                    1 ==
                after.targetIndex;

        g_secondUiOrderPosition.store(
            uiOrderPosition,
            std::memory_order_release
        );

        g_secondOutwardBothRestored.store(
            targetIndexChanged &&
                relationValidated,
            std::memory_order_release
        );
    } else {
        const CanonicalSearchResult afterPredecessor =
            SearchPredecessorOutward(
                after
            );

        const CanonicalSearchResult afterFollower =
            SearchFollowerOutward(
                after
            );

        if (
            afterPredecessor.found &&
            !afterFollower.found
        ) {
            relationValidated =
                after.targetFound &&
                afterPredecessor.depth ==
                    2 &&
                afterPredecessor.index +
                        1 ==
                    after.targetIndex;
        } else if (
            !afterPredecessor.found &&
            afterFollower.found
        ) {
            relationValidated =
                after.targetFound &&
                afterFollower.depth ==
                    2 &&
                after.targetIndex +
                        1 ==
                    afterFollower.index;
        }

        g_thirdUiOrderPosition.store(
            uiOrderPosition,
            std::memory_order_release
        );

        g_thirdOutwardSingleRestored.store(
            targetIndexChanged &&
                relationValidated,
            std::memory_order_release
        );
    }

    Wh_Log(
        L"OUTWARD_MOVE_COMPLETE "
        L"move=%llu "
        L"phase=%d "
        L"strategy=\"%s\" "
        L"id=%llu "
        L"afterEnumerated=%d "
        L"afterSize=%u "
        L"targetFound=%d "
        L"targetIndex=%u "
        L"targetIndexChanged=%d "
        L"relationValidated=%d "
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
        after.targetFound
            ? 1
            : 0,
        after.targetIndex,
        targetIndexChanged
            ? 1
            : 0,
        relationValidated
            ? 1
            : 0,
        uiOrderPosition
    );

    if (
        phase ==
        2
    ) {
        Wh_Log(
            L"OUTWARD_BOTH_RESULT "
            L"firstIdentity=%llu "
            L"secondIdentity=%llu "
            L"identityChanged=%d "
            L"immediateNeighborsAbsent=%d "
            L"predecessorDepth=%u "
            L"followerDepth=%u "
            L"helperCount=%llu "
            L"firstOverflowSize=%u "
            L"secondOverflowSize=%u "
            L"firstMoveIndex=%u "
            L"secondMoveIndex=%u "
            L"numericIndexInvalidated=%d "
            L"outwardBothRestored=%d",
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
            g_secondImmediateNeighborsAbsent.load(
                std::memory_order_acquire
            )
                ? 1
                : 0,
            g_secondPredecessorDepth.load(
                std::memory_order_acquire
            ),
            g_secondFollowerDepth.load(
                std::memory_order_acquire
            ),
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
            g_firstMoveTargetIndex.load(
                std::memory_order_acquire
            ) !=
                    g_secondMoveTargetIndex.load(
                        std::memory_order_acquire
                    )
                ? 1
                : 0,
            g_secondOutwardBothRestored.load(
                std::memory_order_acquire
            )
                ? 1
                : 0
        );
    }

    if (
        phase ==
        3
    ) {
        Wh_Log(
            L"OUTWARD_SINGLE_RESULT "
            L"thirdIdentity=%llu "
            L"strategy=\"%s\" "
            L"immediateNeighborsAbsent=%d "
            L"liveNeighborDepth=%u "
            L"outwardSingleRestored=%d",
            static_cast<unsigned long long>(
                targetIdentity
            ),
            strategy,
            g_thirdImmediateNeighborsAbsent.load(
                std::memory_order_acquire
            )
                ? 1
                : 0,
            g_thirdLiveNeighborDepth.load(
                std::memory_order_acquire
            ),
            g_thirdOutwardSingleRestored.load(
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

    std::vector<std::pair<int, std::uint64_t>>
        anchorAdded;

    std::vector<std::uint64_t>
        targetAdded;

    std::vector<std::uint64_t>
        helperAdded;

    for (
        std::uint64_t identity :
        added
    ) {
        const int anchorSlot =
            GetAnchorSlotForIdentity(
                identity
            );

        if (
            anchorSlot !=
            kInvalidAnchorSlot
        ) {
            anchorAdded.push_back(
                {
                    anchorSlot,
                    identity
                }
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
        L"anchorAdded=%llu "
        L"targetAdded=%llu "
        L"helperAdded=%llu",
        callNumber,
        g_addIconContext.callNumber,
        static_cast<unsigned long long>(
            added.size()
        ),
        static_cast<unsigned long long>(
            anchorAdded.size()
        ),
        static_cast<unsigned long long>(
            targetAdded.size()
        ),
        static_cast<unsigned long long>(
            helperAdded.size()
        )
    );

    if (
        anchorAdded.size() ==
        1
    ) {
        CaptureAnchorInterface(
            anchorAdded.front().first,
            callNumber,
            anchorAdded.front().second,
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
            L"OUTWARD_HELPER_OBSERVED "
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
            L"Failed to hook one or more taskbar.dll symbols"
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
        L"0.22.0 initializing"
    );

    if (
        !IsPrimaryShellProcess()
    ) {
        Wh_Log(
            L"OUTWARD_SEARCH_TEST_SKIPPED "
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
        L"OUTWARD_SEARCH_TEST_READY "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    return TRUE;
}

void Wh_ModUninit() {
    for (
        int slot = 0;
        slot <
            kAnchorCount;
        slot++
    ) {
        void* anchorAbi =
            g_anchorAbis[
                slot
            ].exchange(
                nullptr,
                std::memory_order_acq_rel
            );

        if (anchorAbi) {
            reinterpret_cast<IUnknown*>(
                anchorAbi
            )->Release();
        }
    }

    Wh_Log(
        L"Tray Add Path Analyzer stopped; "
        L"addIconCalls=%llu "
        L"visibleAddCalls=%llu "
        L"overflowGetterCalls=%llu "
        L"moveAttempts=%llu "
        L"helperCount=%llu "
        L"firstTargetIdentity=%llu "
        L"secondTargetIdentity=%llu "
        L"thirdTargetIdentity=%llu "
        L"canonicalOrderEstablished=%d "
        L"firstImmediateRelationEstablished=%d "
        L"secondImmediateNeighborsAbsent=%d "
        L"secondOutwardBothRestored=%d "
        L"thirdImmediateNeighborsAbsent=%d "
        L"thirdOutwardSingleRestored=%d "
        L"outwardSearchValidationCompleted=%d",
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
        g_canonicalOrderEstablished.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_firstImmediateRelationEstablished.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_secondImmediateNeighborsAbsent.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_secondOutwardBothRestored.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_thirdImmediateNeighborsAbsent.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_thirdOutwardSingleRestored.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_outwardSearchValidationCompleted.load(
            std::memory_order_acquire
        )
            ? 1
            : 0
    );
}
