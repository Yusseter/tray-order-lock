// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Tests safe no-op behavior when no trusted canonical tray neighbors remain live.
// @version         0.23.0
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

Version 0.23.0 validates the final safety fallback of canonical tray-order
restoration.

Four stable GUID-based anchor icons are created. Their real order in the live
overflow vector is observed rather than assumed.

Version-1.0.0 creates a UID-based target. The analyzer derives a canonical
sequence from the four anchors and places the target between the two middle
anchors with exactly one MoveIcon call.

After Version-1.0.0 exits:

- all four canonical anchors are stopped gracefully,
- three helper icons are created,
- the live overflow collection therefore changes,
- none of the target's saved canonical neighbors remain live.

Version-2.0.0 creates a replacement Windows identity for the same UID-based
logical target.

The analyzer searches outward through the saved canonical sequence on both
sides. Since no trusted canonical anchor remains in the live overflow vector,
the analyzer must not call MoveIcon.

The experiment verifies:

- Two distinct Windows target identities are created.
- The initial canonical relationship is established successfully.
- All four anchors were originally captured.
- Three helper icons change the live collection.
- No canonical anchor remains live when Version-2.0.0 appears.
- No predecessor can be found.
- No follower can be found.
- The replacement target remains untouched by the analyzer.
- The total analyzer MoveIcon count remains exactly one.
- No registry values are written by the analyzer.
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

constexpr int kInvalidAnchorSlot =
    -1;

constexpr wchar_t kAnchorAExecutableName[] =
    L"traysafenoopanchoraprobev230.exe";

constexpr wchar_t kAnchorBExecutableName[] =
    L"traysafenoopanchorbprobev230.exe";

constexpr wchar_t kAnchorCExecutableName[] =
    L"traysafenoopanchorcprobev230.exe";

constexpr wchar_t kAnchorDExecutableName[] =
    L"traysafenoopanchordprobev230.exe";

constexpr const wchar_t* kAnchorExecutableNames[
    kAnchorCount
] = {
    kAnchorAExecutableName,
    kAnchorBExecutableName,
    kAnchorCExecutableName,
    kAnchorDExecutableName,
};

constexpr wchar_t kTargetExecutableName[] =
    L"trayuidsafenoopprobev230.exe";

constexpr wchar_t kHelperExecutableName[] =
    L"traysafenoophelperv230.exe";

constexpr wchar_t kVersion1Marker[] =
    L"\\version-1.0.0\\";

constexpr wchar_t kVersion2Marker[] =
    L"\\version-2.0.0\\";

constexpr DWORD kTargetUid =
    1;

constexpr int kOverflowLocation =
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

std::atomic<unsigned int> g_firstMoveTargetIndex =
    0;

std::atomic<unsigned int> g_secondTargetIndexBefore =
    0;

std::atomic<unsigned int> g_secondTargetIndexAfter =
    0;

std::atomic<unsigned int> g_secondLiveAnchorCount =
    0;

std::atomic<unsigned long long> g_firstUiOrderPosition =
    0;

std::atomic<unsigned long long> g_secondUiOrderPosition =
    0;

std::atomic<unsigned long long> g_moveAttemptsBeforeNoOp =
    0;

std::atomic<unsigned long long> g_moveAttemptsAfterNoOp =
    0;

std::atomic<bool> g_canonicalOrderEstablished =
    false;

std::atomic<bool> g_firstRelationEstablished =
    false;

std::atomic<bool> g_secondPredecessorFound =
    false;

std::atomic<bool> g_secondFollowerFound =
    false;

std::atomic<bool> g_secondTargetStayedAtSameIndex =
    false;

std::atomic<bool> g_safeNoOpObserved =
    false;

std::atomic<bool> g_safeNoOpValidationCompleted =
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
            L"SAFE_NOOP_REQUIRED_SYMBOL_MISSING"
        );

        return false;
    }

    Wh_Log(
        L"SAFE_NOOP_SUPPORT_READY "
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
            kAnchorCount ||
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

unsigned int CountLiveAnchors(
    const OverflowPositions& positions
) {
    unsigned int count =
        0;

    for (
        int slot = 0;
        slot <
            kAnchorCount;
        slot++
    ) {
        if (
            positions.anchorFound[
                slot
            ]
        ) {
            count++;
        }
    }

    return count;
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
                0
            ],
            0
        },
        {
            positions.anchorIndex[
                1
            ],
            1
        },
        {
            positions.anchorIndex[
                2
            ],
            2
        },
        {
            positions.anchorIndex[
                3
            ],
            3
        },
    }};

    std::sort(
        ordered.begin(),
        ordered.end(),
        [](
            const std::pair<
                unsigned int,
                int
            >& left,
            const std::pair<
                unsigned int,
                int
            >& right
        ) {
            return
                left.first <
                right.first;
        }
    );

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
        L"SAFE_NOOP_CANONICAL_ORDER_ESTABLISHED "
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
    const unsigned int desiredIndex =
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

    return false;
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
        L"SAFE_NOOP_ANCHOR_QUERY "
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
            L"SAFE_NOOP_ANCHOR_CAPTURED "
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

void LogSafeNoOpValidation(
    const OverflowPositions& before,
    const OverflowPositions& after,
    std::uint64_t secondIdentity,
    const CanonicalSearchResult& predecessor,
    const CanonicalSearchResult& follower
) {
    const std::uint64_t firstIdentity =
        g_firstTargetIdentity.load(
            std::memory_order_acquire
        );

    DWORD firstUid =
        0;

    DWORD secondUid =
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

    const bool identityChanged =
        firstIdentity !=
            0 &&
        secondIdentity !=
            0 &&
        firstIdentity !=
            secondIdentity;

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

    const unsigned long long movesBefore =
        g_moveAttemptsBeforeNoOp.load(
            std::memory_order_acquire
        );

    const unsigned long long movesAfter =
        g_moveAttemptsAfterNoOp.load(
            std::memory_order_acquire
        );

    const bool exactlyOneAnalyzerMove =
        movesBefore ==
            1 &&
        movesAfter ==
            1 &&
        g_moveAttempts.load(
            std::memory_order_acquire
        ) ==
            1;

    const unsigned int liveAnchorCount =
        CountLiveAnchors(
            before
        );

    const bool noCanonicalNeighborsFound =
        !predecessor.found &&
        !follower.found;

    const bool targetIndexUnchanged =
        before.targetFound &&
        after.targetFound &&
        before.targetIndex ==
            after.targetIndex;

    g_secondLiveAnchorCount.store(
        liveAnchorCount,
        std::memory_order_release
    );

    g_secondTargetIndexBefore.store(
        before.targetIndex,
        std::memory_order_release
    );

    g_secondTargetIndexAfter.store(
        after.targetIndex,
        std::memory_order_release
    );

    g_secondPredecessorFound.store(
        predecessor.found,
        std::memory_order_release
    );

    g_secondFollowerFound.store(
        follower.found,
        std::memory_order_release
    );

    g_secondTargetStayedAtSameIndex.store(
        targetIndexUnchanged,
        std::memory_order_release
    );

    const bool safeNoOpObserved =
        liveAnchorCount ==
            0 &&
        noCanonicalNeighborsFound &&
        exactlyOneAnalyzerMove;

    g_safeNoOpObserved.store(
        safeNoOpObserved,
        std::memory_order_release
    );

    const bool collectionChanged =
        g_firstOverflowSize.load(
            std::memory_order_acquire
        ) !=
        g_secondOverflowSize.load(
            std::memory_order_acquire
        );

    const bool validationCompleted =
        identityChanged &&
        firstUidValid &&
        secondUidValid &&
        firstUid ==
            kTargetUid &&
        secondUid ==
            kTargetUid &&
        version1Path &&
        version2Path &&
        AllAnchorsCaptured() &&
        g_canonicalOrderEstablished.load(
            std::memory_order_acquire
        ) &&
        g_firstRelationEstablished.load(
            std::memory_order_acquire
        ) &&
        g_helperIdentityCount.load(
            std::memory_order_acquire
        ) ==
            3 &&
        collectionChanged &&
        liveAnchorCount ==
            0 &&
        noCanonicalNeighborsFound &&
        exactlyOneAnalyzerMove &&
        safeNoOpObserved;

    g_safeNoOpValidationCompleted.store(
        validationCompleted,
        std::memory_order_release
    );

    Wh_Log(
        L"SAFE_NOOP_RESULT "
        L"firstIdentity=%llu "
        L"secondIdentity=%llu "
        L"identityChanged=%d "
        L"firstUidValid=%d "
        L"firstUid=%u "
        L"secondUidValid=%d "
        L"secondUid=%u "
        L"version1Path=%d "
        L"version2Path=%d "
        L"allAnchorsCaptured=%d "
        L"canonicalOrderEstablished=%d "
        L"firstRelationEstablished=%d "
        L"helperCount=%llu "
        L"firstOverflowSize=%u "
        L"secondOverflowSize=%u "
        L"collectionChanged=%d "
        L"liveAnchorCount=%u "
        L"predecessorFound=%d "
        L"followerFound=%d "
        L"targetIndexBefore=%u "
        L"targetIndexAfter=%u "
        L"targetIndexUnchanged=%d "
        L"moveAttemptsBeforeNoOp=%llu "
        L"moveAttemptsAfterNoOp=%llu "
        L"exactlyOneAnalyzerMove=%d "
        L"safeNoOpObserved=%d "
        L"safeNoOpValidationCompleted=%d",
        static_cast<unsigned long long>(
            firstIdentity
        ),
        static_cast<unsigned long long>(
            secondIdentity
        ),
        identityChanged
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
        version1Path
            ? 1
            : 0,
        version2Path
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
        g_firstRelationEstablished.load(
            std::memory_order_acquire
        )
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
        collectionChanged
            ? 1
            : 0,
        liveAnchorCount,
        predecessor.found
            ? 1
            : 0,
        follower.found
            ? 1
            : 0,
        before.targetIndex,
        after.targetIndex,
        targetIndexUnchanged
            ? 1
            : 0,
        movesBefore,
        movesAfter,
        exactlyOneAnalyzerMove
            ? 1
            : 0,
        safeNoOpObserved
            ? 1
            : 0,
        validationCompleted
            ? 1
            : 0
    );

    Wh_Log(
        L"SAFE_NOOP_SUMMARY "
        L"farPrecedingSlot=%d "
        L"nearPrecedingSlot=%d "
        L"nearFollowingSlot=%d "
        L"farFollowingSlot=%d "
        L"firstTargetIdentity=%llu "
        L"secondTargetIdentity=%llu "
        L"firstUiOrderPosition=%llu "
        L"secondUiOrderPosition=%llu "
        L"moveAttempts=%llu "
        L"helperCount=%llu "
        L"secondLiveAnchorCount=%u "
        L"secondPredecessorFound=%d "
        L"secondFollowerFound=%d "
        L"safeNoOpValidationCompleted=%d",
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
        g_firstUiOrderPosition.load(
            std::memory_order_acquire
        ),
        g_secondUiOrderPosition.load(
            std::memory_order_acquire
        ),
        g_moveAttempts.load(
            std::memory_order_acquire
        ),
        g_helperIdentityCount.load(
            std::memory_order_acquire
        ),
        g_secondLiveAnchorCount.load(
            std::memory_order_acquire
        ),
        g_secondPredecessorFound.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_secondFollowerFound.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
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
            L"SAFE_NOOP_TARGET_SKIPPED "
            L"reason=\"anchors-not-captured\" "
            L"id=%llu",
            static_cast<unsigned long long>(
                targetIdentity
            )
        );

        return;
    }

    const bool firstPhase =
        g_firstTargetIdentity.load(
            std::memory_order_acquire
        ) ==
        0;

    if (
        !firstPhase &&
        g_secondTargetIdentity.load(
            std::memory_order_acquire
        ) !=
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
        L"SAFE_NOOP_TARGET_QUERY "
        L"phase=%d "
        L"id=%llu "
        L"result=0x%08X "
        L"abi=%p",
        firstPhase
            ? 1
            : 2,
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

    if (firstPhase) {
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

        const unsigned int desiredIndex =
            CalculateImmediatelyAfterIndex(
                nearPrecedingIndex,
                before.targetIndex,
                before.size
            );

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

        const unsigned long long moveNumber =
            g_moveAttempts.fetch_add(
                1,
                std::memory_order_relaxed
            ) +
            1;

        Wh_Log(
            L"SAFE_NOOP_INITIAL_MOVE_BEGIN "
            L"move=%llu "
            L"id=%llu "
            L"overflowSize=%u "
            L"targetIndexBefore=%u "
            L"computedTargetIndex=%u",
            moveNumber,
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

        unsigned int nearPrecedingAfter =
            0;

        unsigned int nearFollowingAfter =
            0;

        const bool precedingAfterFound =
            GetAnchorPosition(
                after,
                g_nearPrecedingSlot.load(
                    std::memory_order_acquire
                ),
                &nearPrecedingAfter
            );

        const bool followingAfterFound =
            GetAnchorPosition(
                after,
                g_nearFollowingSlot.load(
                    std::memory_order_acquire
                ),
                &nearFollowingAfter
            );

        const bool relationEstablished =
            after.targetFound &&
            precedingAfterFound &&
            followingAfterFound &&
            nearPrecedingAfter +
                    1 ==
                after.targetIndex &&
            after.targetIndex +
                    1 ==
                nearFollowingAfter;

        const bool moveObserved =
            after.targetFound &&
            before.targetIndex !=
                after.targetIndex;

        const UIOrderSnapshot uiOrder =
            CaptureUIOrderSnapshot();

        const unsigned long long uiOrderPosition =
            FindOneBasedPosition(
                uiOrder,
                targetIdentity
            );

        g_firstUiOrderPosition.store(
            uiOrderPosition,
            std::memory_order_release
        );

        g_firstRelationEstablished.store(
            moveObserved &&
                relationEstablished,
            std::memory_order_release
        );

        Wh_Log(
            L"SAFE_NOOP_INITIAL_MOVE_COMPLETE "
            L"move=%llu "
            L"id=%llu "
            L"afterSize=%u "
            L"targetIndex=%u "
            L"nearPrecedingIndex=%u "
            L"nearFollowingIndex=%u "
            L"moveObserved=%d "
            L"relationEstablished=%d "
            L"uiOrderPosition=%llu",
            moveNumber,
            static_cast<unsigned long long>(
                targetIdentity
            ),
            after.size,
            after.targetIndex,
            nearPrecedingAfter,
            nearFollowingAfter,
            moveObserved
                ? 1
                : 0,
            relationEstablished
                ? 1
                : 0,
            uiOrderPosition
        );

        reinterpret_cast<IUnknown*>(
            targetAbi
        )->Release();

        return;
    }

    const std::uint64_t firstIdentity =
        g_firstTargetIdentity.load(
            std::memory_order_acquire
        );

    if (
        targetIdentity ==
        firstIdentity
    ) {
        reinterpret_cast<IUnknown*>(
            targetAbi
        )->Release();

        return;
    }

    g_secondTargetIdentity.store(
        targetIdentity,
        std::memory_order_release
    );

    g_secondOverflowSize.store(
        before.size,
        std::memory_order_release
    );

    const CanonicalSearchResult predecessor =
        SearchPredecessorOutward(
            before
        );

    const CanonicalSearchResult follower =
        SearchFollowerOutward(
            before
        );

    const unsigned int liveAnchorCount =
        CountLiveAnchors(
            before
        );

    const unsigned long long movesBefore =
        g_moveAttempts.load(
            std::memory_order_acquire
        );

    g_moveAttemptsBeforeNoOp.store(
        movesBefore,
        std::memory_order_release
    );

    Wh_Log(
        L"SAFE_NOOP_SEARCH "
        L"id=%llu "
        L"overflowSize=%u "
        L"targetIndex=%u "
        L"liveAnchorCount=%u "
        L"predecessorFound=%d "
        L"predecessorSlot=%d "
        L"predecessorDepth=%u "
        L"followerFound=%d "
        L"followerSlot=%d "
        L"followerDepth=%u "
        L"moveAttemptsBefore=%llu",
        static_cast<unsigned long long>(
            targetIdentity
        ),
        before.size,
        before.targetIndex,
        liveAnchorCount,
        predecessor.found
            ? 1
            : 0,
        predecessor.anchorSlot,
        predecessor.depth,
        follower.found
            ? 1
            : 0,
        follower.anchorSlot,
        follower.depth,
        movesBefore
    );

    if (
        predecessor.found ||
        follower.found
    ) {
        Wh_Log(
            L"SAFE_NOOP_REJECTED "
            L"reason=\"trusted-canonical-neighbor-still-live\""
        );

        reinterpret_cast<IUnknown*>(
            targetAbi
        )->Release();

        return;
    }

    Wh_Log(
        L"SAFE_NOOP_DECISION "
        L"id=%llu "
        L"reason=\"no-trusted-live-canonical-neighbors\" "
        L"action=\"do-not-call-MoveIcon\"",
        static_cast<unsigned long long>(
            targetIdentity
        )
    );

    const OverflowPositions after =
        QueryOverflowPositions(
            targetAbi
        );

    const unsigned long long movesAfter =
        g_moveAttempts.load(
            std::memory_order_acquire
        );

    g_moveAttemptsAfterNoOp.store(
        movesAfter,
        std::memory_order_release
    );

    const UIOrderSnapshot uiOrder =
        CaptureUIOrderSnapshot();

    g_secondUiOrderPosition.store(
        FindOneBasedPosition(
            uiOrder,
            targetIdentity
        ),
        std::memory_order_release
    );

    LogSafeNoOpValidation(
        before,
        after,
        targetIdentity,
        predecessor,
        follower
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

    std::vector<
        std::pair<
            int,
            std::uint64_t
        >
    > anchorAdded;

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
            L"SAFE_NOOP_HELPER_OBSERVED "
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
        L"0.23.0 initializing"
    );

    if (
        !IsPrimaryShellProcess()
    ) {
        Wh_Log(
            L"SAFE_NOOP_TEST_SKIPPED "
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
        L"SAFE_NOOP_TEST_READY "
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
        L"canonicalOrderEstablished=%d "
        L"firstRelationEstablished=%d "
        L"secondLiveAnchorCount=%u "
        L"secondPredecessorFound=%d "
        L"secondFollowerFound=%d "
        L"safeNoOpObserved=%d "
        L"safeNoOpValidationCompleted=%d",
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
        g_canonicalOrderEstablished.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_firstRelationEstablished.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_secondLiveAnchorCount.load(
            std::memory_order_acquire
        ),
        g_secondPredecessorFound.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_secondFollowerFound.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_safeNoOpObserved.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_safeNoOpValidationCompleted.load(
            std::memory_order_acquire
        )
            ? 1
            : 0
    );
}
