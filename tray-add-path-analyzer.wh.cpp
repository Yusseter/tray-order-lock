// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Tests neighbor-relative tray-order restoration while the live overflow collection changes.
// @version         0.20.0
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

Version 0.20.0 tests neighbor-relative restoration of a replacement UID tray
identity while the live overflow collection changes between application
versions.

The test uses three synthetic applications:

TrayOrderAnchorProbeV200.exe
- Creates one GUID-based anchor icon.
- Remains alive through both target versions.
- The analyzer retains the live INotificationAreaIcon interface for this
  anchor and finds it directly inside the overflow vector.

TrayUidNeighborRestoreProbeV200.exe
- Uses UID 1 and no GUID.
- Version-1.0.0 and Version-2.0.0 therefore create different Windows tray
  identities.
- The first identity is moved immediately after the anchor.
- The replacement identity is also moved immediately after the anchor, using
  the anchor's CURRENT live overflow index rather than a previously saved
  numeric index.

TrayOrderCollectionHelperV200.exe
- Creates three additional UID-based tray icons between the two target runs.
- The helpers remain alive while Version-2.0.0 is added.
- This changes the live overflow size and shifts the anchor's vector index.

The analyzer verifies:

- The first and second target registry identities are different.
- Exactly three helper icons are observed.
- The overflow collection changes between target versions.
- The anchor moves to a different live vector index because of the helpers.
- The numeric target index used in the first run would no longer identify the
  position immediately after the anchor in the second run.
- The replacement target is restored immediately after the anchor by using
  the anchor's current live vector index.
- Exactly two analyzer MoveIcon calls occur: one initial placement and one
  replacement restore.

The analyzer never moves the anchor, helper icons, or any unrelated tray icon.
It performs no registry writes.
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

constexpr wchar_t kAnchorExecutableName[] =
    L"trayorderanchorprobev200.exe";

constexpr wchar_t kTargetExecutableName[] =
    L"trayuidneighborrestoreprobev200.exe";

constexpr wchar_t kHelperExecutableName[] =
    L"trayordercollectionhelperv200.exe";

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

std::atomic<void*> g_anchorAbi =
    nullptr;

std::atomic<std::uint64_t> g_anchorIdentity =
    0;

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

std::atomic<unsigned int> g_firstAnchorIndexBefore =
    0;

std::atomic<unsigned int> g_firstTargetIndexBefore =
    0;

std::atomic<unsigned int> g_firstAnchorIndexAfter =
    0;

std::atomic<unsigned int> g_firstTargetIndexAfter =
    0;

std::atomic<unsigned int> g_secondAnchorIndexBefore =
    0;

std::atomic<unsigned int> g_secondTargetIndexBefore =
    0;

std::atomic<unsigned int> g_secondAnchorIndexAfter =
    0;

std::atomic<unsigned int> g_secondTargetIndexAfter =
    0;

std::atomic<unsigned int> g_firstMoveTargetIndex =
    0;

std::atomic<unsigned int> g_secondMoveTargetIndex =
    0;

std::atomic<unsigned long long> g_firstUiOrderPosition =
    0;

std::atomic<unsigned long long> g_secondUiOrderPosition =
    0;

std::atomic<bool> g_anchorCaptured =
    false;

std::atomic<bool> g_firstMoveObserved =
    false;

std::atomic<bool> g_secondMoveObserved =
    false;

std::atomic<bool> g_neighborRestoreValidated =
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

struct OverflowObjectPositions {
    bool valid =
        false;

    HRESULT getterResult =
        E_FAIL;

    HRESULT vectorQueryResult =
        E_FAIL;

    HRESULT sizeResult =
        E_FAIL;

    unsigned int size =
        0;

    bool anchorFound =
        false;

    unsigned int anchorIndex =
        0;

    bool targetFound =
        false;

    unsigned int targetIndex =
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
        L"NEIGHBOR_RESTORE_SUPPORT_READY "
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

bool IsAnchorIdentity(
    std::uint64_t identity
) {
    return
        IsExecutableIdentity(
            identity,
            kAnchorExecutableName
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

OverflowObjectPositions QueryOverflowObjectPositions(
    void* targetAbi
) {
    OverflowObjectPositions positions;

    void* taskbarModel6 =
        g_taskbarModel6.load(
            std::memory_order_acquire
        );

    void* anchorAbi =
        g_anchorAbi.load(
            std::memory_order_acquire
        );

    if (
        !taskbarModel6 ||
        !anchorAbi ||
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
            !positions.anchorFound &&
            IsSameComObject(
                itemAbi,
                anchorAbi
            )
        ) {
            positions.anchorFound =
                true;

            positions.anchorIndex =
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

        if (
            positions.anchorFound &&
            positions.targetFound
        ) {
            break;
        }
    }

    positions.valid =
        positions.anchorFound &&
        positions.targetFound;

    reinterpret_cast<IUnknown*>(
        vectorAbi
    )->Release();

    reinterpret_cast<IUnknown*>(
        collectionAbi
    )->Release();

    return positions;
}

unsigned int CalculateIndexImmediatelyAfterAnchor(
    const OverflowObjectPositions& positions
) {
    if (
        !positions.valid ||
        positions.size ==
            0
    ) {
        return 0;
    }

    unsigned int desiredIndex =
        0;

    if (
        positions.targetIndex <
        positions.anchorIndex
    ) {
        desiredIndex =
            positions.anchorIndex;
    } else {
        desiredIndex =
            positions.anchorIndex +
            1;
    }

    if (
        desiredIndex >=
        positions.size
    ) {
        desiredIndex =
            positions.size -
            1;
    }

    return desiredIndex;
}

bool IsImmediatelyAfterAnchor(
    const OverflowObjectPositions& positions
) {
    return
        positions.valid &&
        positions.targetIndex ==
            positions.anchorIndex +
                1;
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
    unsigned long long callNumber,
    std::uint64_t identity,
    void* iconImplementation
) {
    if (
        g_anchorAbi.load(
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
        L"ANCHOR_INTERFACE_QUERY "
        L"call=%llu "
        L"id=%llu "
        L"implementation=%p "
        L"result=0x%08X "
        L"queriedAbi=%p",
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
        g_anchorAbi.compare_exchange_strong(
            expected,
            queriedAbi,
            std::memory_order_acq_rel
        )
    ) {
        g_anchorIdentity.store(
            identity,
            std::memory_order_release
        );

        g_anchorCaptured.store(
            true,
            std::memory_order_release
        );

        Wh_Log(
            L"ANCHOR_CAPTURED "
            L"id=%llu "
            L"abi=%p",
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

void HandleTargetIcon(
    unsigned long long callNumber,
    void* pThis,
    std::uint64_t targetIdentity,
    void* iconImplementation
) {
    if (
        !g_anchorAbi.load(
            std::memory_order_acquire
        )
    ) {
        Wh_Log(
            L"NEIGHBOR_TARGET_SKIPPED "
            L"reason=\"anchor-not-captured\" "
            L"id=%llu",
            static_cast<unsigned long long>(
                targetIdentity
            )
        );

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

    if (
        FAILED(
            queryResult
        ) ||
        !targetAbi
    ) {
        Wh_Log(
            L"NEIGHBOR_TARGET_QUERY_FAILED "
            L"id=%llu "
            L"result=0x%08X",
            static_cast<unsigned long long>(
                targetIdentity
            ),
            static_cast<unsigned int>(
                queryResult
            )
        );

        return;
    }

    const bool firstPhase =
        g_firstTargetIdentity.load(
            std::memory_order_acquire
        ) ==
        0;

    if (firstPhase) {
        g_firstTargetIdentity.store(
            targetIdentity,
            std::memory_order_release
        );
    } else {
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
    }

    const OverflowObjectPositions before =
        QueryOverflowObjectPositions(
            targetAbi
        );

    Wh_Log(
        L"NEIGHBOR_POSITION_BEFORE "
        L"phase=\"%s\" "
        L"id=%llu "
        L"valid=%d "
        L"size=%u "
        L"anchorFound=%d "
        L"anchorIndex=%u "
        L"targetFound=%d "
        L"targetIndex=%u "
        L"getterResult=0x%08X "
        L"vectorQueryResult=0x%08X "
        L"sizeResult=0x%08X",
        firstPhase
            ? L"first"
            : L"restore",
        static_cast<unsigned long long>(
            targetIdentity
        ),
        before.valid
            ? 1
            : 0,
        before.size,
        before.anchorFound
            ? 1
            : 0,
        before.anchorIndex,
        before.targetFound
            ? 1
            : 0,
        before.targetIndex,
        static_cast<unsigned int>(
            before.getterResult
        ),
        static_cast<unsigned int>(
            before.vectorQueryResult
        ),
        static_cast<unsigned int>(
            before.sizeResult
        )
    );

    if (!before.valid) {
        reinterpret_cast<IUnknown*>(
            targetAbi
        )->Release();

        return;
    }

    const unsigned int desiredIndex =
        CalculateIndexImmediatelyAfterAnchor(
            before
        );

    if (firstPhase) {
        g_firstOverflowSize.store(
            before.size,
            std::memory_order_release
        );

        g_firstAnchorIndexBefore.store(
            before.anchorIndex,
            std::memory_order_release
        );

        g_firstTargetIndexBefore.store(
            before.targetIndex,
            std::memory_order_release
        );

        g_firstMoveTargetIndex.store(
            desiredIndex,
            std::memory_order_release
        );
    } else {
        g_secondOverflowSize.store(
            before.size,
            std::memory_order_release
        );

        g_secondAnchorIndexBefore.store(
            before.anchorIndex,
            std::memory_order_release
        );

        g_secondTargetIndexBefore.store(
            before.targetIndex,
            std::memory_order_release
        );

        g_secondMoveTargetIndex.store(
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
        L"NEIGHBOR_MOVE_BEGIN "
        L"move=%llu "
        L"phase=\"%s\" "
        L"call=%llu "
        L"id=%llu "
        L"overflowSize=%u "
        L"anchorIndex=%u "
        L"targetIndexBefore=%u "
        L"computedTargetIndex=%u",
        moveNumber,
        firstPhase
            ? L"first"
            : L"restore",
        callNumber,
        static_cast<unsigned long long>(
            targetIdentity
        ),
        before.size,
        before.anchorIndex,
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

    const OverflowObjectPositions after =
        QueryOverflowObjectPositions(
            targetAbi
        );

    const UIOrderSnapshot uiOrder =
        CaptureUIOrderSnapshot();

    const unsigned long long uiOrderPosition =
        FindOneBasedPosition(
            uiOrder,
            targetIdentity
        );

    const bool immediateAfter =
        IsImmediatelyAfterAnchor(
            after
        );

    const bool moveObserved =
        after.valid &&
        before.targetIndex !=
            after.targetIndex;

    if (firstPhase) {
        g_firstAnchorIndexAfter.store(
            after.anchorIndex,
            std::memory_order_release
        );

        g_firstTargetIndexAfter.store(
            after.targetIndex,
            std::memory_order_release
        );

        g_firstUiOrderPosition.store(
            uiOrderPosition,
            std::memory_order_release
        );

        g_firstMoveObserved.store(
            moveObserved &&
                immediateAfter,
            std::memory_order_release
        );
    } else {
        g_secondAnchorIndexAfter.store(
            after.anchorIndex,
            std::memory_order_release
        );

        g_secondTargetIndexAfter.store(
            after.targetIndex,
            std::memory_order_release
        );

        g_secondUiOrderPosition.store(
            uiOrderPosition,
            std::memory_order_release
        );

        g_secondMoveObserved.store(
            moveObserved &&
                immediateAfter,
            std::memory_order_release
        );
    }

    Wh_Log(
        L"NEIGHBOR_MOVE_COMPLETE "
        L"move=%llu "
        L"phase=\"%s\" "
        L"id=%llu "
        L"afterValid=%d "
        L"overflowSize=%u "
        L"anchorIndex=%u "
        L"targetIndex=%u "
        L"immediatelyAfterAnchor=%d "
        L"moveObserved=%d "
        L"uiOrderPosition=%llu",
        moveNumber,
        firstPhase
            ? L"first"
            : L"restore",
        static_cast<unsigned long long>(
            targetIdentity
        ),
        after.valid
            ? 1
            : 0,
        after.size,
        after.anchorIndex,
        after.targetIndex,
        immediateAfter
            ? 1
            : 0,
        moveObserved
            ? 1
            : 0,
        uiOrderPosition
    );

    if (!firstPhase) {
        const std::uint64_t firstIdentity =
            g_firstTargetIdentity.load(
                std::memory_order_acquire
            );

        const std::uint64_t secondIdentity =
            g_secondTargetIdentity.load(
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

        const unsigned int firstOverflowSize =
            g_firstOverflowSize.load(
                std::memory_order_acquire
            );

        const unsigned int secondOverflowSize =
            g_secondOverflowSize.load(
                std::memory_order_acquire
            );

        const unsigned int firstAnchorIndexAfter =
            g_firstAnchorIndexAfter.load(
                std::memory_order_acquire
            );

        const unsigned int secondAnchorIndexBefore =
            g_secondAnchorIndexBefore.load(
                std::memory_order_acquire
            );

        const unsigned int firstSavedTargetIndex =
            g_firstTargetIndexAfter.load(
                std::memory_order_acquire
            );

        const unsigned int secondComputedTargetIndex =
            g_secondMoveTargetIndex.load(
                std::memory_order_acquire
            );

        const unsigned long long helperCount =
            g_helperIdentityCount.load(
                std::memory_order_acquire
            );

        const bool identityChanged =
            firstIdentity !=
            secondIdentity;

        const bool overflowSizeChanged =
            firstOverflowSize !=
            secondOverflowSize;

        const bool anchorIndexChanged =
            firstAnchorIndexAfter !=
            secondAnchorIndexBefore;

        const bool savedNumericIndexDiffers =
            firstSavedTargetIndex !=
            secondComputedTargetIndex;

        const bool firstVersion1 =
            ContainsOrdinalIgnoreCase(
                NormalizeSlashes(
                    firstPath
                ),
                kVersion1Marker
            );

        const bool secondVersion2 =
            ContainsOrdinalIgnoreCase(
                NormalizeSlashes(
                    secondPath
                ),
                kVersion2Marker
            );

        const bool exactlyTwoAnalyzerMoves =
            g_moveAttempts.load(
                std::memory_order_acquire
            ) ==
            2;

        const bool firstRelationEstablished =
            g_firstMoveObserved.load(
                std::memory_order_acquire
            );

        const bool secondRelationRestored =
            g_secondMoveObserved.load(
                std::memory_order_acquire
            );

        const bool neighborRestoreValidated =
            identityChanged &&
            firstUidValid &&
            secondUidValid &&
            firstUid ==
                kTargetUid &&
            secondUid ==
                kTargetUid &&
            firstVersion1 &&
            secondVersion2 &&
            helperCount ==
                3 &&
            overflowSizeChanged &&
            anchorIndexChanged &&
            savedNumericIndexDiffers &&
            exactlyTwoAnalyzerMoves &&
            firstRelationEstablished &&
            secondRelationRestored &&
            after.valid &&
            immediateAfter;

        g_neighborRestoreValidated.store(
            neighborRestoreValidated,
            std::memory_order_release
        );

        Wh_Log(
            L"NEIGHBOR_RESTORE_RESULT "
            L"firstIdentity=%llu "
            L"secondIdentity=%llu "
            L"identityChanged=%d "
            L"firstUidValid=%d "
            L"firstUid=%u "
            L"secondUidValid=%d "
            L"secondUid=%u "
            L"firstVersion1=%d "
            L"secondVersion2=%d "
            L"helperCount=%llu "
            L"firstOverflowSize=%u "
            L"secondOverflowSize=%u "
            L"overflowSizeChanged=%d "
            L"firstAnchorIndexAfter=%u "
            L"secondAnchorIndexBefore=%u "
            L"anchorIndexChanged=%d "
            L"firstSavedTargetIndex=%u "
            L"secondComputedTargetIndex=%u "
            L"savedNumericIndexDiffers=%d "
            L"firstRelationEstablished=%d "
            L"secondRelationRestored=%d "
            L"exactlyTwoAnalyzerMoves=%d "
            L"neighborRestoreValidated=%d",
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
            firstVersion1
                ? 1
                : 0,
            secondVersion2
                ? 1
                : 0,
            helperCount,
            firstOverflowSize,
            secondOverflowSize,
            overflowSizeChanged
                ? 1
                : 0,
            firstAnchorIndexAfter,
            secondAnchorIndexBefore,
            anchorIndexChanged
                ? 1
                : 0,
            firstSavedTargetIndex,
            secondComputedTargetIndex,
            savedNumericIndexDiffers
                ? 1
                : 0,
            firstRelationEstablished
                ? 1
                : 0,
            secondRelationRestored
                ? 1
                : 0,
            exactlyTwoAnalyzerMoves
                ? 1
                : 0,
            neighborRestoreValidated
                ? 1
                : 0
        );

        Wh_Log(
            L"NEIGHBOR_RESTORE_SUMMARY "
            L"anchorIdentity=%llu "
            L"firstTargetIdentity=%llu "
            L"secondTargetIdentity=%llu "
            L"helperCount=%llu "
            L"firstOverflowSize=%u "
            L"secondOverflowSize=%u "
            L"firstAnchorIndexBefore=%u "
            L"firstTargetIndexBefore=%u "
            L"firstAnchorIndexAfter=%u "
            L"firstTargetIndexAfter=%u "
            L"secondAnchorIndexBefore=%u "
            L"secondTargetIndexBefore=%u "
            L"secondAnchorIndexAfter=%u "
            L"secondTargetIndexAfter=%u "
            L"firstMoveTargetIndex=%u "
            L"secondMoveTargetIndex=%u "
            L"firstUiOrderPosition=%llu "
            L"secondUiOrderPosition=%llu "
            L"moveAttempts=%llu "
            L"neighborRestoreValidationCompleted=%d",
            static_cast<unsigned long long>(
                g_anchorIdentity.load(
                    std::memory_order_acquire
                )
            ),
            static_cast<unsigned long long>(
                firstIdentity
            ),
            static_cast<unsigned long long>(
                secondIdentity
            ),
            helperCount,
            firstOverflowSize,
            secondOverflowSize,
            g_firstAnchorIndexBefore.load(
                std::memory_order_acquire
            ),
            g_firstTargetIndexBefore.load(
                std::memory_order_acquire
            ),
            g_firstAnchorIndexAfter.load(
                std::memory_order_acquire
            ),
            g_firstTargetIndexAfter.load(
                std::memory_order_acquire
            ),
            g_secondAnchorIndexBefore.load(
                std::memory_order_acquire
            ),
            g_secondTargetIndexBefore.load(
                std::memory_order_acquire
            ),
            g_secondAnchorIndexAfter.load(
                std::memory_order_acquire
            ),
            g_secondTargetIndexAfter.load(
                std::memory_order_acquire
            ),
            g_firstMoveTargetIndex.load(
                std::memory_order_acquire
            ),
            g_secondMoveTargetIndex.load(
                std::memory_order_acquire
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
            g_neighborRestoreValidated.load(
                std::memory_order_acquire
            )
                ? 1
                : 0
        );
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

    std::vector<std::uint64_t> anchorAdded;
    std::vector<std::uint64_t> targetAdded;
    std::vector<std::uint64_t> helperAdded;

    for (
        std::uint64_t identity :
        added
    ) {
        if (
            IsAnchorIdentity(
                identity
            )
        ) {
            anchorAdded.push_back(
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
            callNumber,
            anchorAdded.front(),
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
            L"HELPER_IDENTITY_OBSERVED "
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
        L"0.20.0 initializing"
    );

    if (
        !IsPrimaryShellProcess()
    ) {
        Wh_Log(
            L"NEIGHBOR_RESTORE_TEST_SKIPPED "
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
        L"NEIGHBOR_RESTORE_TEST_READY "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    return TRUE;
}

void Wh_ModUninit() {
    void* anchorAbi =
        g_anchorAbi.exchange(
            nullptr,
            std::memory_order_acq_rel
        );

    if (anchorAbi) {
        reinterpret_cast<IUnknown*>(
            anchorAbi
        )->Release();
    }

    Wh_Log(
        L"Tray Add Path Analyzer stopped; "
        L"addIconCalls=%llu "
        L"visibleAddCalls=%llu "
        L"overflowGetterCalls=%llu "
        L"moveAttempts=%llu "
        L"anchorCaptured=%d "
        L"helperCount=%llu "
        L"firstTargetIdentity=%llu "
        L"secondTargetIdentity=%llu "
        L"firstMoveObserved=%d "
        L"secondMoveObserved=%d "
        L"neighborRestoreValidated=%d",
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
        g_anchorCaptured.load(
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
        g_firstMoveObserved.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_secondMoveObserved.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_neighborRestoreValidated.load(
            std::memory_order_acquire
        )
            ? 1
            : 0
    );
}
