// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Tests learning a manual tray reorder and restoring a replacement identity to the updated canonical position.
// @version         0.26.0
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

Version 0.26.0 tests the core behavior required by:

Preserve order, allow manual changes

Three stable GUID-based anchor icons remain live throughout the experiment.

Version-1.0.0 creates a UID-based target.

The analyzer observes the real live order of the three anchors and places the
target between the first and second anchors:

anchor 1 -> target -> anchor 2 -> anchor 3

This initial placement uses one analyzer MoveIcon call.

The user then manually drags the target inside the tray overflow to the other
adjacent anchor interval:

anchor 1 -> anchor 2 -> target -> anchor 3

The analyzer hooks the public ITaskbarModel5::MoveNotificationAreaIcon path
used by the taskbar drag/drop UI.

The manual move is NOT blocked.

After Windows processes the drag, the analyzer verifies the new live
relationship and records:

anchor 2 -> target -> anchor 3

as the updated canonical user order.

The first target then closes and its Version-1.0.0 directory is deleted.

Three helper icons are added to change the live overflow geometry.

Version-2.0.0 creates a replacement Windows tray identity for the same UID
logical target.

The analyzer:

1. matches the replacement to the unique historical identity using
   version-normalized executable path + UID;
2. uses the canonical relation learned from the user's manual drag;
3. locates those two anchors at their current live positions;
4. restores the replacement between them with one analyzer MoveIcon call.

The experiment verifies:

- Two distinct target Windows identities are created.
- Both use UID 1.
- Exactly one historical logical identity candidate is found.
- The unique candidate is the first target identity.
- The initial target relation is established.
- A real manual target MoveNotificationAreaIcon call is observed.
- The manual move is allowed to reach Windows.
- The target ends between the second and third canonical anchors.
- That manual relation replaces the initial canonical relation.
- Three helper icons change the collection geometry.
- The replacement is not restored using the old manual numeric index.
- The replacement is restored to the manually learned logical relation.
- Exactly two analyzer MoveIcon calls occur.
- Manual movement is not counted as an analyzer MoveIcon call.
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
    3;

constexpr int kInvalidAnchorSlot =
    -1;

constexpr int kOverflowLocation =
    1;

constexpr DWORD kTargetUid =
    1;

constexpr wchar_t kAnchorAExecutableName[] =
    L"traymanualanchoraprobev260.exe";

constexpr wchar_t kAnchorBExecutableName[] =
    L"traymanualanchorbprobev260.exe";

constexpr wchar_t kAnchorCExecutableName[] =
    L"traymanualanchorcprobev260.exe";

constexpr const wchar_t* kAnchorExecutableNames[
    kAnchorCount
] = {
    kAnchorAExecutableName,
    kAnchorBExecutableName,
    kAnchorCExecutableName,
};

constexpr wchar_t kTargetExecutableName[] =
    L"trayuidmanualrestoreprobev260.exe";

constexpr wchar_t kHelperExecutableName[] =
    L"traymanualcollectionhelperv260.exe";

constexpr wchar_t kVersion1Marker[] =
    L"\\version-1.0.0\\";

constexpr wchar_t kVersion2Marker[] =
    L"\\version-2.0.0\\";

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

using TaskbarModel_MoveNotificationAreaIcon_t =
    int(__cdecl*)(
        void* pThis,
        void* notificationAreaIconAbi,
        int location,
        unsigned int index
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

TaskbarModel_MoveNotificationAreaIcon_t
    TaskbarModel_MoveNotificationAreaIcon_Original =
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

std::atomic<void*> g_firstTargetAbi =
    nullptr;

std::atomic<std::uint64_t> g_firstTargetIdentity =
    0;

std::atomic<std::uint64_t> g_secondTargetIdentity =
    0;

std::atomic<std::uint64_t> g_selectedHistoricalIdentity =
    0;

std::atomic<int> g_initialFirstAnchorSlot =
    kInvalidAnchorSlot;

std::atomic<int> g_initialMiddleAnchorSlot =
    kInvalidAnchorSlot;

std::atomic<int> g_initialLastAnchorSlot =
    kInvalidAnchorSlot;

std::atomic<int> g_initialPrecedingSlot =
    kInvalidAnchorSlot;

std::atomic<int> g_initialFollowingSlot =
    kInvalidAnchorSlot;

std::atomic<int> g_manualPrecedingSlot =
    kInvalidAnchorSlot;

std::atomic<int> g_manualFollowingSlot =
    kInvalidAnchorSlot;

std::atomic<unsigned long long> g_addIconCalls =
    0;

std::atomic<unsigned long long> g_visibleAddCalls =
    0;

std::atomic<unsigned long long> g_overflowGetterCalls =
    0;

std::atomic<unsigned long long> g_analyzerMoveAttempts =
    0;

std::atomic<unsigned long long> g_manualTargetMoveCalls =
    0;

std::atomic<unsigned long long> g_manualRelationUpdates =
    0;

std::atomic<unsigned long long> g_restoreDecisions =
    0;

std::atomic<unsigned long long> g_helperIdentityCount =
    0;

std::atomic<unsigned int> g_candidateCount =
    0;

std::atomic<unsigned int> g_firstOverflowSize =
    0;

std::atomic<unsigned int> g_secondOverflowSize =
    0;

std::atomic<unsigned int> g_initialMoveTargetIndex =
    0;

std::atomic<unsigned int> g_manualSavedTargetIndex =
    0;

std::atomic<unsigned int> g_secondMoveTargetIndex =
    0;

std::atomic<unsigned int> g_manualTargetIndexBefore =
    0;

std::atomic<unsigned int> g_manualTargetIndexAfter =
    0;

std::atomic<unsigned int> g_secondTargetIndexBefore =
    0;

std::atomic<unsigned int> g_secondTargetIndexAfter =
    0;

std::atomic<unsigned int> g_secondPrecedingIndexBefore =
    0;

std::atomic<unsigned int> g_secondFollowingIndexBefore =
    0;

std::atomic<int> g_lastManualLocation =
    -1;

std::atomic<unsigned int> g_lastManualRequestedIndex =
    0;

std::atomic<unsigned long long> g_initialUiOrderPosition =
    0;

std::atomic<unsigned long long> g_manualUiOrderPosition =
    0;

std::atomic<unsigned long long> g_secondUiOrderPosition =
    0;

std::atomic<bool> g_initialRelationEstablished =
    false;

std::atomic<bool> g_manualTargetMoveObserved =
    false;

std::atomic<bool> g_manualCanonicalRelationUpdated =
    false;

std::atomic<bool> g_uniqueCandidateObserved =
    false;

std::atomic<bool> g_uniqueCandidateSelected =
    false;

std::atomic<bool> g_replacementRestoredToManualRelation =
    false;

std::atomic<bool> g_manualRestoreValidationCompleted =
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

bool IsManagerMoveIconSymbol(
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
            IsManagerMoveIconSymbol(
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
                L"MANAGER_MOVE_ICON_SYMBOL "
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
            L"MANUAL_RESTORE_REQUIRED_SYMBOL_MISSING"
        );

        return false;
    }

    Wh_Log(
        L"MANUAL_RESTORE_SUPPORT_READY "
        L"queryFunction=%p "
        L"iconInterfaceId=%p "
        L"vectorInterfaceId=%p "
        L"managerMoveFunction=%p",
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

bool IsTargetDirectlyBetween(
    const OverflowPositions& positions,
    int precedingSlot,
    int followingSlot
) {
    if (
        !positions.targetFound
    ) {
        return false;
    }

    unsigned int precedingIndex =
        0;

    unsigned int followingIndex =
        0;

    if (
        !GetAnchorPosition(
            positions,
            precedingSlot,
            &precedingIndex
        ) ||
        !GetAnchorPosition(
            positions,
            followingSlot,
            &followingIndex
        )
    ) {
        return false;
    }

    return
        precedingIndex +
                1 ==
            positions.targetIndex &&
        positions.targetIndex +
                1 ==
            followingIndex;
}

bool EstablishInitialAnchorOrder(
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

    g_initialFirstAnchorSlot.store(
        ordered[
            0
        ].second,
        std::memory_order_release
    );

    g_initialMiddleAnchorSlot.store(
        ordered[
            1
        ].second,
        std::memory_order_release
    );

    g_initialLastAnchorSlot.store(
        ordered[
            2
        ].second,
        std::memory_order_release
    );

    g_initialPrecedingSlot.store(
        ordered[
            0
        ].second,
        std::memory_order_release
    );

    g_initialFollowingSlot.store(
        ordered[
            1
        ].second,
        std::memory_order_release
    );

    Wh_Log(
        L"MANUAL_RESTORE_INITIAL_ANCHOR_ORDER "
        L"firstSlot=%d "
        L"middleSlot=%d "
        L"lastSlot=%d "
        L"indices=%u,%u,%u",
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
            0
        ].first,
        ordered[
            1
        ].first,
        ordered[
            2
        ].first
    );

    return true;
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
        L"MANUAL_RESTORE_ANCHOR_QUERY "
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
            L"MANUAL_RESTORE_ANCHOR_CAPTURED "
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

void HandleFirstTarget(
    unsigned long long callNumber,
    void* pThis,
    std::uint64_t identity,
    void* iconImplementation
) {
    if (!AllAnchorsCaptured()) {
        Wh_Log(
            L"MANUAL_RESTORE_FIRST_SKIPPED "
            L"reason=\"anchors-not-captured\" "
            L"id=%llu",
            static_cast<unsigned long long>(
                identity
            )
        );

        return;
    }

    void* queriedTargetAbi =
        nullptr;

    const HRESULT queryResult =
        static_cast<HRESULT>(
            NotificationAreaIcon_QueryInterface(
                iconImplementation,
                *g_notificationAreaIconInterfaceId,
                &queriedTargetAbi
            )
        );

    Wh_Log(
        L"MANUAL_RESTORE_TARGET_QUERY "
        L"phase=1 "
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
        queriedTargetAbi
    );

    if (
        FAILED(
            queryResult
        ) ||
        !queriedTargetAbi
    ) {
        return;
    }

    void* expectedTargetAbi =
        nullptr;

    if (
        !g_firstTargetAbi.compare_exchange_strong(
            expectedTargetAbi,
            queriedTargetAbi,
            std::memory_order_acq_rel
        )
    ) {
        reinterpret_cast<IUnknown*>(
            queriedTargetAbi
        )->Release();

        queriedTargetAbi =
            expectedTargetAbi;
    }

    const OverflowPositions before =
        QueryOverflowPositions(
            queriedTargetAbi
        );

    if (
        !before.enumerated ||
        !before.targetFound ||
        !EstablishInitialAnchorOrder(
            before
        )
    ) {
        return;
    }

    const int precedingSlot =
        g_initialPrecedingSlot.load(
            std::memory_order_acquire
        );

    const int followingSlot =
        g_initialFollowingSlot.load(
            std::memory_order_acquire
        );

    unsigned int precedingIndex =
        0;

    unsigned int followingIndex =
        0;

    if (
        !GetAnchorPosition(
            before,
            precedingSlot,
            &precedingIndex
        ) ||
        !GetAnchorPosition(
            before,
            followingSlot,
            &followingIndex
        )
    ) {
        return;
    }

    const unsigned int desiredIndex =
        CalculateImmediatelyAfterIndex(
            precedingIndex,
            before.targetIndex,
            before.size
        );

    g_firstTargetIdentity.store(
        identity,
        std::memory_order_release
    );

    g_firstOverflowSize.store(
        before.size,
        std::memory_order_release
    );

    g_initialMoveTargetIndex.store(
        desiredIndex,
        std::memory_order_release
    );

    const unsigned long long moveNumber =
        g_analyzerMoveAttempts.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    Wh_Log(
        L"MANUAL_RESTORE_INITIAL_MOVE_BEGIN "
        L"move=%llu "
        L"id=%llu "
        L"overflowSize=%u "
        L"precedingSlot=%d "
        L"precedingIndex=%u "
        L"followingSlot=%d "
        L"followingIndex=%u "
        L"targetIndexBefore=%u "
        L"computedTargetIndex=%u",
        moveNumber,
        static_cast<unsigned long long>(
            identity
        ),
        before.size,
        precedingSlot,
        precedingIndex,
        followingSlot,
        followingIndex,
        before.targetIndex,
        desiredIndex
    );

    void* iconArgumentStorage =
        queriedTargetAbi;

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
            queriedTargetAbi
        );

    const bool relationEstablished =
        IsTargetDirectlyBetween(
            after,
            precedingSlot,
            followingSlot
        );

    const bool moveObserved =
        after.targetFound &&
        before.targetIndex !=
            after.targetIndex;

    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    const unsigned long long uiOrderPosition =
        FindOneBasedPosition(
            snapshot,
            identity
        );

    g_initialUiOrderPosition.store(
        uiOrderPosition,
        std::memory_order_release
    );

    g_initialRelationEstablished.store(
        relationEstablished &&
            moveObserved,
        std::memory_order_release
    );

    Wh_Log(
        L"MANUAL_RESTORE_INITIAL_MOVE_COMPLETE "
        L"move=%llu "
        L"id=%llu "
        L"afterSize=%u "
        L"targetIndex=%u "
        L"moveObserved=%d "
        L"relationEstablished=%d "
        L"uiOrderPosition=%llu",
        moveNumber,
        static_cast<unsigned long long>(
            identity
        ),
        after.size,
        after.targetIndex,
        moveObserved
            ? 1
            : 0,
        relationEstablished
            ? 1
            : 0,
        uiOrderPosition
    );

    Wh_Log(
        L"MANUAL_RESTORE_USER_ACTION_READY "
        L"initialFirstSlot=%d "
        L"initialMiddleSlot=%d "
        L"initialLastSlot=%d "
        L"expectedManualPrecedingSlot=%d "
        L"expectedManualFollowingSlot=%d",
        g_initialFirstAnchorSlot.load(
            std::memory_order_acquire
        ),
        g_initialMiddleAnchorSlot.load(
            std::memory_order_acquire
        ),
        g_initialLastAnchorSlot.load(
            std::memory_order_acquire
        ),
        g_initialMiddleAnchorSlot.load(
            std::memory_order_acquire
        ),
        g_initialLastAnchorSlot.load(
            std::memory_order_acquire
        )
    );
}

int __cdecl
TaskbarModel_MoveNotificationAreaIcon_Hook(
    void* pThis,
    void* notificationAreaIconAbi,
    int location,
    unsigned int index
) {
    void* firstTargetAbi =
        g_firstTargetAbi.load(
            std::memory_order_acquire
        );

    const bool isTrackedTarget =
        firstTargetAbi &&
        notificationAreaIconAbi &&
        g_firstTargetIdentity.load(
            std::memory_order_acquire
        ) !=
            0 &&
        g_secondTargetIdentity.load(
            std::memory_order_acquire
        ) ==
            0 &&
        IsSameComObject(
            notificationAreaIconAbi,
            firstTargetAbi
        );

    OverflowPositions before;

    if (isTrackedTarget) {
        before =
            QueryOverflowPositions(
                firstTargetAbi
            );

        Wh_Log(
            L"MANUAL_RESTORE_USER_MOVE_BEGIN "
            L"location=%d "
            L"requestedIndex=%u "
            L"beforeEnumerated=%d "
            L"beforeSize=%u "
            L"targetFound=%d "
            L"targetIndex=%u "
            L"analyzerMoveAttempts=%llu",
            location,
            index,
            before.enumerated
                ? 1
                : 0,
            before.size,
            before.targetFound
                ? 1
                : 0,
            before.targetIndex,
            g_analyzerMoveAttempts.load(
                std::memory_order_acquire
            )
        );
    }

    const int originalResult =
        TaskbarModel_MoveNotificationAreaIcon_Original(
            pThis,
            notificationAreaIconAbi,
            location,
            index
        );

    if (!isTrackedTarget) {
        return originalResult;
    }

    const unsigned long long manualMoveNumber =
        g_manualTargetMoveCalls.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    g_manualTargetMoveObserved.store(
        true,
        std::memory_order_release
    );

    g_lastManualLocation.store(
        location,
        std::memory_order_release
    );

    g_lastManualRequestedIndex.store(
        index,
        std::memory_order_release
    );

    const OverflowPositions after =
        QueryOverflowPositions(
            firstTargetAbi
        );

    g_manualTargetIndexBefore.store(
        before.targetIndex,
        std::memory_order_release
    );

    g_manualTargetIndexAfter.store(
        after.targetIndex,
        std::memory_order_release
    );

    const int expectedPrecedingSlot =
        g_initialMiddleAnchorSlot.load(
            std::memory_order_acquire
        );

    const int expectedFollowingSlot =
        g_initialLastAnchorSlot.load(
            std::memory_order_acquire
        );

    const bool expectedManualRelation =
        SUCCEEDED(
            static_cast<HRESULT>(
                originalResult
            )
        ) &&
        location ==
            kOverflowLocation &&
        after.enumerated &&
        IsTargetDirectlyBetween(
            after,
            expectedPrecedingSlot,
            expectedFollowingSlot
        );

    Wh_Log(
        L"MANUAL_RESTORE_USER_MOVE_COMPLETE "
        L"manualMove=%llu "
        L"result=0x%08X "
        L"location=%d "
        L"requestedIndex=%u "
        L"afterEnumerated=%d "
        L"afterSize=%u "
        L"targetFound=%d "
        L"targetIndex=%u "
        L"expectedPrecedingSlot=%d "
        L"expectedFollowingSlot=%d "
        L"expectedManualRelation=%d "
        L"analyzerMoveAttempts=%llu",
        manualMoveNumber,
        static_cast<unsigned int>(
            static_cast<HRESULT>(
                originalResult
            )
        ),
        location,
        index,
        after.enumerated
            ? 1
            : 0,
        after.size,
        after.targetFound
            ? 1
            : 0,
        after.targetIndex,
        expectedPrecedingSlot,
        expectedFollowingSlot,
        expectedManualRelation
            ? 1
            : 0,
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire
        )
    );

    if (!expectedManualRelation) {
        Wh_Log(
            L"MANUAL_RESTORE_USER_RELATION_NOT_UPDATED "
            L"manualMove=%llu "
            L"reason=\"target-not-between-expected-second-and-third-anchors\"",
            manualMoveNumber
        );

        return originalResult;
    }

    g_manualPrecedingSlot.store(
        expectedPrecedingSlot,
        std::memory_order_release
    );

    g_manualFollowingSlot.store(
        expectedFollowingSlot,
        std::memory_order_release
    );

    g_manualSavedTargetIndex.store(
        after.targetIndex,
        std::memory_order_release
    );

    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    const unsigned long long manualUiOrderPosition =
        FindOneBasedPosition(
            snapshot,
            g_firstTargetIdentity.load(
                std::memory_order_acquire
            )
        );

    g_manualUiOrderPosition.store(
        manualUiOrderPosition,
        std::memory_order_release
    );

    g_manualRelationUpdates.fetch_add(
        1,
        std::memory_order_relaxed
    );

    g_manualCanonicalRelationUpdated.store(
        true,
        std::memory_order_release
    );

    Wh_Log(
        L"MANUAL_RESTORE_CANONICAL_UPDATED "
        L"manualMove=%llu "
        L"precedingSlot=%d "
        L"followingSlot=%d "
        L"savedTargetIndex=%u "
        L"uiOrderPosition=%llu "
        L"analyzerMoveAttempts=%llu",
        manualMoveNumber,
        expectedPrecedingSlot,
        expectedFollowingSlot,
        after.targetIndex,
        manualUiOrderPosition,
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire
        )
    );

    return originalResult;
}

void LogFinalValidation(
    const HistoricalCandidate& candidate,
    const OverflowPositions& before,
    const OverflowPositions& after
) {
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

    const std::wstring firstNormalized =
        NormalizeVersionedExecutablePath(
            firstPath
        );

    const std::wstring secondNormalized =
        NormalizeVersionedExecutablePath(
            secondPath
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

    const bool normalizedPathsEqual =
        !firstNormalized.empty() &&
        firstNormalized ==
            secondNormalized;

    const bool firstPathExists =
        FileExists(
            firstPath
        );

    const bool secondPathExists =
        FileExists(
            secondPath
        );

    const bool candidateMatchesFirst =
        candidate.identity ==
        firstIdentity;

    const bool exactlyOneCandidate =
        g_candidateCount.load(
            std::memory_order_acquire
        ) ==
        1;

    const bool collectionChanged =
        g_firstOverflowSize.load(
            std::memory_order_acquire
        ) !=
        g_secondOverflowSize.load(
            std::memory_order_acquire
        );

    const bool numericIndexInvalidated =
        g_manualSavedTargetIndex.load(
            std::memory_order_acquire
        ) !=
        g_secondMoveTargetIndex.load(
            std::memory_order_acquire
        );

    const bool manualRelationChanged =
        g_initialPrecedingSlot.load(
            std::memory_order_acquire
        ) !=
            g_manualPrecedingSlot.load(
                std::memory_order_acquire
            ) ||
        g_initialFollowingSlot.load(
            std::memory_order_acquire
        ) !=
            g_manualFollowingSlot.load(
                std::memory_order_acquire
            );

    const bool manualRelationMatchesExpected =
        g_manualPrecedingSlot.load(
            std::memory_order_acquire
        ) ==
            g_initialMiddleAnchorSlot.load(
                std::memory_order_acquire
            ) &&
        g_manualFollowingSlot.load(
            std::memory_order_acquire
        ) ==
            g_initialLastAnchorSlot.load(
                std::memory_order_acquire
            );

    const bool replacementBetweenManualAnchors =
        IsTargetDirectlyBetween(
            after,
            g_manualPrecedingSlot.load(
                std::memory_order_acquire
            ),
            g_manualFollowingSlot.load(
                std::memory_order_acquire
            )
        );

    const bool exactlyTwoAnalyzerMoves =
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire
        ) ==
        2;

    const bool manualMoveObserved =
        g_manualTargetMoveCalls.load(
            std::memory_order_acquire
        ) >=
        1;

    const bool exactlyOneRestoreDecision =
        g_restoreDecisions.load(
            std::memory_order_acquire
        ) ==
        1;

    const bool validationCompleted =
        identityChanged &&
        firstUidValid &&
        secondUidValid &&
        firstUid ==
            kTargetUid &&
        secondUid ==
            kTargetUid &&
        firstVersion1 &&
        secondVersion2 &&
        normalizedPathsEqual &&
        !firstPathExists &&
        secondPathExists &&
        AllAnchorsCaptured() &&
        g_initialRelationEstablished.load(
            std::memory_order_acquire
        ) &&
        manualMoveObserved &&
        g_manualCanonicalRelationUpdated.load(
            std::memory_order_acquire
        ) &&
        g_manualRelationUpdates.load(
            std::memory_order_acquire
        ) >=
            1 &&
        manualRelationChanged &&
        manualRelationMatchesExpected &&
        g_helperIdentityCount.load(
            std::memory_order_acquire
        ) ==
            3 &&
        exactlyOneCandidate &&
        candidateMatchesFirst &&
        !candidate.pathExists &&
        g_uniqueCandidateObserved.load(
            std::memory_order_acquire
        ) &&
        g_uniqueCandidateSelected.load(
            std::memory_order_acquire
        ) &&
        collectionChanged &&
        numericIndexInvalidated &&
        replacementBetweenManualAnchors &&
        g_replacementRestoredToManualRelation.load(
            std::memory_order_acquire
        ) &&
        exactlyOneRestoreDecision &&
        exactlyTwoAnalyzerMoves;

    g_manualRestoreValidationCompleted.store(
        validationCompleted,
        std::memory_order_release
    );

    Wh_Log(
        L"MANUAL_RESTORE_RESULT "
        L"firstIdentity=%llu "
        L"secondIdentity=%llu "
        L"identityChanged=%d "
        L"firstUidValid=%d "
        L"firstUid=%u "
        L"secondUidValid=%d "
        L"secondUid=%u "
        L"firstVersion1=%d "
        L"secondVersion2=%d "
        L"normalizedPathsEqual=%d "
        L"firstPathExists=%d "
        L"secondPathExists=%d "
        L"allAnchorsCaptured=%d "
        L"initialRelationEstablished=%d "
        L"manualTargetMoveCalls=%llu "
        L"manualRelationUpdates=%llu "
        L"manualCanonicalRelationUpdated=%d "
        L"manualRelationChanged=%d "
        L"manualRelationMatchesExpected=%d "
        L"helperCount=%llu "
        L"candidateCount=%u "
        L"candidateIdentity=%llu "
        L"candidateMatchesFirst=%d "
        L"candidatePathExists=%d "
        L"uniqueCandidateObserved=%d "
        L"uniqueCandidateSelected=%d "
        L"firstOverflowSize=%u "
        L"secondOverflowSize=%u "
        L"collectionChanged=%d "
        L"manualSavedTargetIndex=%u "
        L"secondMoveTargetIndex=%u "
        L"numericIndexInvalidated=%d "
        L"secondTargetIndexBefore=%u "
        L"secondTargetIndexAfter=%u "
        L"replacementBetweenManualAnchors=%d "
        L"replacementRestoredToManualRelation=%d "
        L"restoreDecisions=%llu "
        L"analyzerMoveAttempts=%llu "
        L"exactlyTwoAnalyzerMoves=%d "
        L"manualRestoreValidationCompleted=%d",
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
        normalizedPathsEqual
            ? 1
            : 0,
        firstPathExists
            ? 1
            : 0,
        secondPathExists
            ? 1
            : 0,
        AllAnchorsCaptured()
            ? 1
            : 0,
        g_initialRelationEstablished.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_manualTargetMoveCalls.load(
            std::memory_order_acquire
        ),
        g_manualRelationUpdates.load(
            std::memory_order_acquire
        ),
        g_manualCanonicalRelationUpdated.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        manualRelationChanged
            ? 1
            : 0,
        manualRelationMatchesExpected
            ? 1
            : 0,
        g_helperIdentityCount.load(
            std::memory_order_acquire
        ),
        g_candidateCount.load(
            std::memory_order_acquire
        ),
        static_cast<unsigned long long>(
            candidate.identity
        ),
        candidateMatchesFirst
            ? 1
            : 0,
        candidate.pathExists
            ? 1
            : 0,
        g_uniqueCandidateObserved.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_uniqueCandidateSelected.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_firstOverflowSize.load(
            std::memory_order_acquire
        ),
        g_secondOverflowSize.load(
            std::memory_order_acquire
        ),
        collectionChanged
            ? 1
            : 0,
        g_manualSavedTargetIndex.load(
            std::memory_order_acquire
        ),
        g_secondMoveTargetIndex.load(
            std::memory_order_acquire
        ),
        numericIndexInvalidated
            ? 1
            : 0,
        before.targetIndex,
        after.targetIndex,
        replacementBetweenManualAnchors
            ? 1
            : 0,
        g_replacementRestoredToManualRelation.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_restoreDecisions.load(
            std::memory_order_acquire
        ),
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire
        ),
        exactlyTwoAnalyzerMoves
            ? 1
            : 0,
        validationCompleted
            ? 1
            : 0
    );

    Wh_Log(
        L"MANUAL_RESTORE_SUMMARY "
        L"initialFirstAnchorSlot=%d "
        L"initialMiddleAnchorSlot=%d "
        L"initialLastAnchorSlot=%d "
        L"initialPrecedingSlot=%d "
        L"initialFollowingSlot=%d "
        L"manualPrecedingSlot=%d "
        L"manualFollowingSlot=%d "
        L"firstTargetIdentity=%llu "
        L"secondTargetIdentity=%llu "
        L"selectedHistoricalIdentity=%llu "
        L"initialMoveTargetIndex=%u "
        L"manualTargetIndexBefore=%u "
        L"manualTargetIndexAfter=%u "
        L"manualSavedTargetIndex=%u "
        L"secondMoveTargetIndex=%u "
        L"secondPrecedingIndexBefore=%u "
        L"secondFollowingIndexBefore=%u "
        L"initialUiOrderPosition=%llu "
        L"manualUiOrderPosition=%llu "
        L"secondUiOrderPosition=%llu "
        L"lastManualLocation=%d "
        L"lastManualRequestedIndex=%u "
        L"manualTargetMoveCalls=%llu "
        L"manualRelationUpdates=%llu "
        L"restoreDecisions=%llu "
        L"analyzerMoveAttempts=%llu "
        L"manualRestoreValidationCompleted=%d",
        g_initialFirstAnchorSlot.load(
            std::memory_order_acquire
        ),
        g_initialMiddleAnchorSlot.load(
            std::memory_order_acquire
        ),
        g_initialLastAnchorSlot.load(
            std::memory_order_acquire
        ),
        g_initialPrecedingSlot.load(
            std::memory_order_acquire
        ),
        g_initialFollowingSlot.load(
            std::memory_order_acquire
        ),
        g_manualPrecedingSlot.load(
            std::memory_order_acquire
        ),
        g_manualFollowingSlot.load(
            std::memory_order_acquire
        ),
        static_cast<unsigned long long>(
            firstIdentity
        ),
        static_cast<unsigned long long>(
            secondIdentity
        ),
        static_cast<unsigned long long>(
            g_selectedHistoricalIdentity.load(
                std::memory_order_acquire
            )
        ),
        g_initialMoveTargetIndex.load(
            std::memory_order_acquire
        ),
        g_manualTargetIndexBefore.load(
            std::memory_order_acquire
        ),
        g_manualTargetIndexAfter.load(
            std::memory_order_acquire
        ),
        g_manualSavedTargetIndex.load(
            std::memory_order_acquire
        ),
        g_secondMoveTargetIndex.load(
            std::memory_order_acquire
        ),
        g_secondPrecedingIndexBefore.load(
            std::memory_order_acquire
        ),
        g_secondFollowingIndexBefore.load(
            std::memory_order_acquire
        ),
        g_initialUiOrderPosition.load(
            std::memory_order_acquire
        ),
        g_manualUiOrderPosition.load(
            std::memory_order_acquire
        ),
        g_secondUiOrderPosition.load(
            std::memory_order_acquire
        ),
        g_lastManualLocation.load(
            std::memory_order_acquire
        ),
        g_lastManualRequestedIndex.load(
            std::memory_order_acquire
        ),
        g_manualTargetMoveCalls.load(
            std::memory_order_acquire
        ),
        g_manualRelationUpdates.load(
            std::memory_order_acquire
        ),
        g_restoreDecisions.load(
            std::memory_order_acquire
        ),
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire
        ),
        validationCompleted
            ? 1
            : 0
    );
}

void HandleReplacementTarget(
    unsigned long long callNumber,
    void* pThis,
    std::uint64_t identity,
    void* iconImplementation
) {
    if (
        !g_manualCanonicalRelationUpdated.load(
            std::memory_order_acquire
        )
    ) {
        Wh_Log(
            L"MANUAL_RESTORE_REPLACEMENT_SKIPPED "
            L"reason=\"manual-canonical-relation-not-updated\" "
            L"id=%llu",
            static_cast<unsigned long long>(
                identity
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

    Wh_Log(
        L"MANUAL_RESTORE_TARGET_QUERY "
        L"phase=2 "
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

    g_secondTargetIdentity.store(
        identity,
        std::memory_order_release
    );

    g_secondOverflowSize.store(
        before.size,
        std::memory_order_release
    );

    g_secondTargetIndexBefore.store(
        before.targetIndex,
        std::memory_order_release
    );

    const std::wstring currentPath =
        QueryExecutablePath(
            identity
        );

    const std::wstring normalizedPath =
        NormalizeVersionedExecutablePath(
            currentPath
        );

    const std::vector<HistoricalCandidate> candidates =
        FindHistoricalCandidates(
            identity,
            normalizedPath
        );

    g_candidateCount.store(
        static_cast<unsigned int>(
            candidates.size()
        ),
        std::memory_order_release
    );

    g_restoreDecisions.fetch_add(
        1,
        std::memory_order_relaxed
    );

    Wh_Log(
        L"MANUAL_RESTORE_MATCH_SEARCH "
        L"currentIdentity=%llu "
        L"candidateCount=%llu "
        L"currentPathExists=%d "
        L"normalizedPath=\"%s\"",
        static_cast<unsigned long long>(
            identity
        ),
        static_cast<unsigned long long>(
            candidates.size()
        ),
        FileExists(
            currentPath
        )
            ? 1
            : 0,
        normalizedPath.c_str()
    );

    for (
        std::size_t candidateIndex = 0;
        candidateIndex <
            candidates.size();
        candidateIndex++
    ) {
        const HistoricalCandidate& candidate =
            candidates[
                candidateIndex
            ];

        Wh_Log(
            L"MANUAL_RESTORE_MATCH_CANDIDATE "
            L"candidate=%llu "
            L"id=%llu "
            L"uidValid=%d "
            L"uid=%u "
            L"uiOrderPosition=%llu "
            L"pathExists=%d "
            L"path=\"%s\" "
            L"normalizedPath=\"%s\"",
            static_cast<unsigned long long>(
                candidateIndex +
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

    const bool exactlyOneCandidate =
        candidates.size() ==
        1;

    g_uniqueCandidateObserved.store(
        exactlyOneCandidate,
        std::memory_order_release
    );

    if (!exactlyOneCandidate) {
        Wh_Log(
            L"MANUAL_RESTORE_MATCH_REJECTED "
            L"candidateCount=%llu "
            L"reason=\"logical-match-not-unique\" "
            L"action=\"do-not-call-MoveIcon\"",
            static_cast<unsigned long long>(
                candidates.size()
            )
        );

        reinterpret_cast<IUnknown*>(
            targetAbi
        )->Release();

        return;
    }

    const HistoricalCandidate& candidate =
        candidates.front();

    if (
        candidate.identity !=
        g_firstTargetIdentity.load(
            std::memory_order_acquire
        )
    ) {
        Wh_Log(
            L"MANUAL_RESTORE_MATCH_REJECTED "
            L"candidateIdentity=%llu "
            L"expectedIdentity=%llu "
            L"reason=\"unique-candidate-is-not-recorded-first-target\"",
            static_cast<unsigned long long>(
                candidate.identity
            ),
            static_cast<unsigned long long>(
                g_firstTargetIdentity.load(
                    std::memory_order_acquire
                )
            )
        );

        reinterpret_cast<IUnknown*>(
            targetAbi
        )->Release();

        return;
    }

    g_selectedHistoricalIdentity.store(
        candidate.identity,
        std::memory_order_release
    );

    g_uniqueCandidateSelected.store(
        true,
        std::memory_order_release
    );

    Wh_Log(
        L"MANUAL_RESTORE_MATCH_SELECTED "
        L"currentIdentity=%llu "
        L"historicalIdentity=%llu "
        L"candidateCount=1",
        static_cast<unsigned long long>(
            identity
        ),
        static_cast<unsigned long long>(
            candidate.identity
        )
    );

    const int precedingSlot =
        g_manualPrecedingSlot.load(
            std::memory_order_acquire
        );

    const int followingSlot =
        g_manualFollowingSlot.load(
            std::memory_order_acquire
        );

    unsigned int precedingIndex =
        0;

    unsigned int followingIndex =
        0;

    const bool precedingFound =
        GetAnchorPosition(
            before,
            precedingSlot,
            &precedingIndex
        );

    const bool followingFound =
        GetAnchorPosition(
            before,
            followingSlot,
            &followingIndex
        );

    Wh_Log(
        L"MANUAL_RESTORE_LIVE_MANUAL_NEIGHBORS "
        L"precedingSlot=%d "
        L"precedingFound=%d "
        L"precedingIndex=%u "
        L"followingSlot=%d "
        L"followingFound=%d "
        L"followingIndex=%u "
        L"targetIndex=%u "
        L"overflowSize=%u",
        precedingSlot,
        precedingFound
            ? 1
            : 0,
        precedingIndex,
        followingSlot,
        followingFound
            ? 1
            : 0,
        followingIndex,
        before.targetIndex,
        before.size
    );

    if (
        !precedingFound ||
        !followingFound ||
        precedingIndex >=
            followingIndex
    ) {
        Wh_Log(
            L"MANUAL_RESTORE_ORDER_REJECTED "
            L"reason=\"manually-learned-live-neighbor-interval-unavailable\""
        );

        reinterpret_cast<IUnknown*>(
            targetAbi
        )->Release();

        return;
    }

    g_secondPrecedingIndexBefore.store(
        precedingIndex,
        std::memory_order_release
    );

    g_secondFollowingIndexBefore.store(
        followingIndex,
        std::memory_order_release
    );

    const unsigned int desiredIndex =
        CalculateImmediatelyAfterIndex(
            precedingIndex,
            before.targetIndex,
            before.size
        );

    g_secondMoveTargetIndex.store(
        desiredIndex,
        std::memory_order_release
    );

    const unsigned long long moveNumber =
        g_analyzerMoveAttempts.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    Wh_Log(
        L"MANUAL_RESTORE_REPLACEMENT_MOVE_BEGIN "
        L"move=%llu "
        L"id=%llu "
        L"historicalIdentity=%llu "
        L"manualSavedTargetIndex=%u "
        L"overflowSize=%u "
        L"precedingIndex=%u "
        L"followingIndex=%u "
        L"targetIndexBefore=%u "
        L"computedTargetIndex=%u",
        moveNumber,
        static_cast<unsigned long long>(
            identity
        ),
        static_cast<unsigned long long>(
            candidate.identity
        ),
        g_manualSavedTargetIndex.load(
            std::memory_order_acquire
        ),
        before.size,
        precedingIndex,
        followingIndex,
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

    const bool relationRestored =
        IsTargetDirectlyBetween(
            after,
            precedingSlot,
            followingSlot
        );

    const bool moveObserved =
        after.targetFound &&
        before.targetIndex !=
            after.targetIndex;

    g_secondTargetIndexAfter.store(
        after.targetIndex,
        std::memory_order_release
    );

    g_replacementRestoredToManualRelation.store(
        relationRestored &&
            moveObserved,
        std::memory_order_release
    );

    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    const unsigned long long secondUiOrderPosition =
        FindOneBasedPosition(
            snapshot,
            identity
        );

    g_secondUiOrderPosition.store(
        secondUiOrderPosition,
        std::memory_order_release
    );

    Wh_Log(
        L"MANUAL_RESTORE_REPLACEMENT_MOVE_COMPLETE "
        L"move=%llu "
        L"id=%llu "
        L"afterSize=%u "
        L"targetIndex=%u "
        L"moveObserved=%d "
        L"relationRestored=%d "
        L"uiOrderPosition=%llu",
        moveNumber,
        static_cast<unsigned long long>(
            identity
        ),
        after.size,
        after.targetIndex,
        moveObserved
            ? 1
            : 0,
        relationRestored
            ? 1
            : 0,
        secondUiOrderPosition
    );

    LogFinalValidation(
        candidate,
        before,
        after
    );

    reinterpret_cast<IUnknown*>(
        targetAbi
    )->Release();
}

void HandleTargetIcon(
    unsigned long long callNumber,
    void* pThis,
    std::uint64_t identity,
    void* iconImplementation
) {
    const std::uint64_t firstIdentity =
        g_firstTargetIdentity.load(
            std::memory_order_acquire
        );

    if (
        firstIdentity ==
        0
    ) {
        HandleFirstTarget(
            callNumber,
            pThis,
            identity,
            iconImplementation
        );

        return;
    }

    if (
        identity ==
            firstIdentity ||
        g_secondTargetIdentity.load(
            std::memory_order_acquire
        ) !=
            0
    ) {
        return;
    }

    HandleReplacementTarget(
        callNumber,
        pThis,
        identity,
        iconImplementation
    );
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
            L"MANUAL_RESTORE_HELPER_OBSERVED "
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
        {
            {
                LR"(public: virtual int __cdecl winrt::impl::produce<struct winrt::WindowsUdk::UI::Shell::implementation::TaskbarModel,struct winrt::WindowsUdk::UI::Shell::ITaskbarModel5>::MoveNotificationAreaIcon(void *,int,unsigned int))"
            },
            &TaskbarModel_MoveNotificationAreaIcon_Original,
            TaskbarModel_MoveNotificationAreaIcon_Hook,
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
        L"0.26.0 initializing"
    );

    if (
        !IsPrimaryShellProcess()
    ) {
        Wh_Log(
            L"MANUAL_RESTORE_TEST_SKIPPED "
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
        L"MANUAL_RESTORE_TEST_READY "
        L"processId=%lu",
        GetCurrentProcessId()
    );

    return TRUE;
}

void Wh_ModUninit() {
    void* firstTargetAbi =
        g_firstTargetAbi.exchange(
            nullptr,
            std::memory_order_acq_rel
        );

    if (firstTargetAbi) {
        reinterpret_cast<IUnknown*>(
            firstTargetAbi
        )->Release();
    }

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
        L"analyzerMoveAttempts=%llu "
        L"manualTargetMoveCalls=%llu "
        L"manualRelationUpdates=%llu "
        L"restoreDecisions=%llu "
        L"helperCount=%llu "
        L"candidateCount=%u "
        L"initialRelationEstablished=%d "
        L"manualCanonicalRelationUpdated=%d "
        L"uniqueCandidateObserved=%d "
        L"uniqueCandidateSelected=%d "
        L"replacementRestoredToManualRelation=%d "
        L"manualRestoreValidationCompleted=%d",
        g_addIconCalls.load(
            std::memory_order_acquire
        ),
        g_visibleAddCalls.load(
            std::memory_order_acquire
        ),
        g_overflowGetterCalls.load(
            std::memory_order_acquire
        ),
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire
        ),
        g_manualTargetMoveCalls.load(
            std::memory_order_acquire
        ),
        g_manualRelationUpdates.load(
            std::memory_order_acquire
        ),
        g_restoreDecisions.load(
            std::memory_order_acquire
        ),
        g_helperIdentityCount.load(
            std::memory_order_acquire
        ),
        g_candidateCount.load(
            std::memory_order_acquire
        ),
        g_initialRelationEstablished.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_manualCanonicalRelationUpdated.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_uniqueCandidateObserved.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_uniqueCandidateSelected.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_replacementRestoredToManualRelation.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_manualRestoreValidationCompleted.load(
            std::memory_order_acquire
        )
            ? 1
            : 0
    );
}
