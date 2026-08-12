// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Tests persistence of manually learned canonical tray order across a full mod reload.
// @version         0.27.0
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

Version 0.27.0 validates persistent canonical tray-order state across a full
Windhawk mod unload/reload.

Phase 1:

- Three GUID-based anchor icons are created.
- Version-1.0.0 creates a UID=1 target.
- The analyzer places the target between the first two live anchors.
- The user manually drags the target into the other anchor interval.
- The public MoveNotificationAreaIcon path is allowed to execute normally.
- The resulting canonical relation is learned.
- The following state is written to Windhawk mod local storage:
  - first Windows target identity,
  - manually selected predecessor anchor slot,
  - manually selected follower anchor slot,
  - manual target index for diagnostic comparison,
  - first-session overflow size,
  - manual UIOrderList position,
  - first-session analyzer MoveIcon count,
  - first-session manual target move count,
  - version-normalized logical target path.

The target and anchors are then stopped.

The Windhawk mod is manually disabled and enabled again. This destroys all
in-process analyzer state and starts a new mod instance.

Phase 2:

- Wh_ModInit loads the persisted binary and string state from Windhawk local
  storage.
- Three new GUID-based instances of the same logical anchor executables are
  created and captured.
- Three helper icons change the live overflow geometry.
- Version-2.0.0 creates a new UID=1 Windows tray identity.
- The replacement is matched to exactly one historical identity using
  version-normalized executable path + UID.
- That historical identity must equal the first target identity loaded from
  persistent storage.
- The persisted predecessor/follower logical anchor slots are resolved to
  their CURRENT live anchor objects.
- The replacement is restored between those anchors using their current
  live positions.

The experiment verifies that the learned manual order survives a complete
mod reload and is not dependent on C++ globals or the old numeric index.

No UIOrderList registry values are written by the analyzer.
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

constexpr wchar_t kPersistentStateValueName[] =
    L"CanonicalStateV270";

constexpr wchar_t kPersistentPathValueName[] =
    L"CanonicalNormalizedPathV270";

constexpr std::uint32_t kPersistentStateMagic =
    0x56373230;

constexpr std::uint32_t kPersistentStateVersion =
    1;

constexpr int kAnchorCount =
    3;

constexpr int kInvalidAnchorSlot =
    -1;

constexpr int kOverflowLocation =
    1;

constexpr DWORD kTargetUid =
    1;

constexpr wchar_t kAnchorAExecutableName[] =
    L"traypersistentanchoraprobev270.exe";

constexpr wchar_t kAnchorBExecutableName[] =
    L"traypersistentanchorbprobev270.exe";

constexpr wchar_t kAnchorCExecutableName[] =
    L"traypersistentanchorcprobev270.exe";

constexpr const wchar_t* kAnchorExecutableNames[
    kAnchorCount
] = {
    kAnchorAExecutableName,
    kAnchorBExecutableName,
    kAnchorCExecutableName,
};

constexpr wchar_t kTargetExecutableName[] =
    L"trayuidpersistentrestoreprobev270.exe";

constexpr wchar_t kHelperExecutableName[] =
    L"traypersistentcollectionhelperv270.exe";

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

struct PersistedCanonicalState {
    std::uint32_t magic =
        0;

    std::uint32_t version =
        0;

    std::uint64_t firstTargetIdentity =
        0;

    std::int32_t precedingSlot =
        kInvalidAnchorSlot;

    std::int32_t followingSlot =
        kInvalidAnchorSlot;

    std::uint32_t manualSavedTargetIndex =
        0;

    std::uint32_t firstSessionOverflowSize =
        0;

    std::uint64_t manualUiOrderPosition =
        0;

    std::uint64_t firstSessionAnalyzerMoveAttempts =
        0;

    std::uint64_t firstSessionManualTargetMoveCalls =
        0;
};

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

std::atomic<unsigned int> g_secondTargetIndexBefore =
    0;

std::atomic<unsigned int> g_secondTargetIndexAfter =
    0;

std::atomic<unsigned int> g_secondPrecedingIndexBefore =
    0;

std::atomic<unsigned int> g_secondFollowingIndexBefore =
    0;

std::atomic<unsigned long long> g_initialUiOrderPosition =
    0;

std::atomic<unsigned long long> g_manualUiOrderPosition =
    0;

std::atomic<unsigned long long> g_secondUiOrderPosition =
    0;

std::atomic<bool> g_initialRelationEstablished =
    false;

std::atomic<bool> g_manualCanonicalRelationUpdated =
    false;

std::atomic<bool> g_persistentWriteSucceeded =
    false;

std::atomic<bool> g_persistentImmediateReadbackSucceeded =
    false;

std::atomic<bool> g_persistedStateLoadedAtInit =
    false;

std::atomic<bool> g_uniqueCandidateObserved =
    false;

std::atomic<bool> g_uniqueCandidateSelected =
    false;

std::atomic<bool> g_replacementRestoredToPersistedRelation =
    false;

std::atomic<bool> g_persistenceValidationCompleted =
    false;

PersistedCanonicalState g_loadedPersistentState;

std::wstring g_loadedNormalizedPath;

thread_local unsigned int g_internalMoveDepth =
    0;

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
        if (
            std::towlower(
                value[
                    offset +
                    index
                ]
            ) !=
            std::towlower(
                suffix[
                    index
                ]
            )
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

bool IsValidAnchorSlot(
    int slot
) {
    return
        slot >=
            0 &&
        slot <
            kAnchorCount;
}

bool IsValidPersistedState(
    const PersistedCanonicalState& state
) {
    return
        state.magic ==
            kPersistentStateMagic &&
        state.version ==
            kPersistentStateVersion &&
        state.firstTargetIdentity !=
            0 &&
        IsValidAnchorSlot(
            state.precedingSlot
        ) &&
        IsValidAnchorSlot(
            state.followingSlot
        ) &&
        state.precedingSlot !=
            state.followingSlot &&
        state.firstSessionAnalyzerMoveAttempts ==
            1 &&
        state.firstSessionManualTargetMoveCalls >=
            1;
}

bool ReadPersistentState(
    PersistedCanonicalState* state,
    std::wstring* normalizedPath,
    size_t* binaryBytes,
    size_t* pathChars
) {
    if (
        !state ||
        !normalizedPath
    ) {
        return false;
    }

    *state =
        {};

    normalizedPath->clear();

    const size_t bytes =
        Wh_GetBinaryValue(
            kPersistentStateValueName,
            state,
            sizeof(
                *state
            )
        );

    wchar_t pathBuffer[
        2048
    ]{};

    const size_t chars =
        Wh_GetStringValue(
            kPersistentPathValueName,
            pathBuffer,
            ARRAYSIZE(
                pathBuffer
            )
        );

    if (binaryBytes) {
        *binaryBytes =
            bytes;
    }

    if (pathChars) {
        *pathChars =
            chars;
    }

    if (
        bytes !=
            sizeof(
                *state
            ) ||
        chars ==
            0 ||
        !IsValidPersistedState(
            *state
        )
    ) {
        *state =
            {};

        normalizedPath->clear();

        return false;
    }

    *normalizedPath =
        pathBuffer;

    return true;
}

void ResetPersistentStateForFreshPhase1() {
    const BOOL binaryDeleteResult =
        Wh_DeleteValue(
            kPersistentStateValueName
        );

    const BOOL pathDeleteResult =
        Wh_DeleteValue(
            kPersistentPathValueName
        );

    g_loadedPersistentState =
        {};

    g_loadedNormalizedPath.clear();

    g_persistedStateLoadedAtInit.store(
        false,
        std::memory_order_release
    );

    g_firstTargetIdentity.store(
        0,
        std::memory_order_release
    );

    g_manualPrecedingSlot.store(
        kInvalidAnchorSlot,
        std::memory_order_release
    );

    g_manualFollowingSlot.store(
        kInvalidAnchorSlot,
        std::memory_order_release
    );

    g_manualSavedTargetIndex.store(
        0,
        std::memory_order_release
    );

    Wh_Log(
        L"PERSISTENCE_PHASE1_STORAGE_RESET "
        L"binaryDeleteResult=%d "
        L"pathDeleteResult=%d",
        binaryDeleteResult
            ? 1
            : 0,
        pathDeleteResult
            ? 1
            : 0
    );
}

bool PersistManualCanonicalState(
    const std::wstring& normalizedPath
) {
    PersistedCanonicalState state;

    state.magic =
        kPersistentStateMagic;

    state.version =
        kPersistentStateVersion;

    state.firstTargetIdentity =
        g_firstTargetIdentity.load(
            std::memory_order_acquire
        );

    state.precedingSlot =
        g_manualPrecedingSlot.load(
            std::memory_order_acquire
        );

    state.followingSlot =
        g_manualFollowingSlot.load(
            std::memory_order_acquire
        );

    state.manualSavedTargetIndex =
        g_manualSavedTargetIndex.load(
            std::memory_order_acquire
        );

    state.firstSessionOverflowSize =
        g_firstOverflowSize.load(
            std::memory_order_acquire
        );

    state.manualUiOrderPosition =
        g_manualUiOrderPosition.load(
            std::memory_order_acquire
        );

    state.firstSessionAnalyzerMoveAttempts =
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire
        );

    state.firstSessionManualTargetMoveCalls =
        g_manualTargetMoveCalls.load(
            std::memory_order_acquire
        );

    const BOOL binaryWriteResult =
        Wh_SetBinaryValue(
            kPersistentStateValueName,
            &state,
            sizeof(
                state
            )
        );

    const BOOL pathWriteResult =
        Wh_SetStringValue(
            kPersistentPathValueName,
            normalizedPath.c_str()
        );

    const bool writeSucceeded =
        binaryWriteResult &&
        pathWriteResult;

    g_persistentWriteSucceeded.store(
        writeSucceeded,
        std::memory_order_release
    );

    PersistedCanonicalState readbackState;
    std::wstring readbackPath;

    size_t readbackBytes =
        0;

    size_t readbackChars =
        0;

    const bool readbackSucceeded =
        ReadPersistentState(
            &readbackState,
            &readbackPath,
            &readbackBytes,
            &readbackChars
        ) &&
        readbackState.firstTargetIdentity ==
            state.firstTargetIdentity &&
        readbackState.precedingSlot ==
            state.precedingSlot &&
        readbackState.followingSlot ==
            state.followingSlot &&
        readbackState.manualSavedTargetIndex ==
            state.manualSavedTargetIndex &&
        readbackPath ==
            normalizedPath;

    g_persistentImmediateReadbackSucceeded.store(
        readbackSucceeded,
        std::memory_order_release
    );

    Wh_Log(
        L"PERSISTENCE_STATE_WRITE "
        L"binaryWriteResult=%d "
        L"pathWriteResult=%d "
        L"writeSucceeded=%d "
        L"readbackSucceeded=%d "
        L"readbackBytes=%llu "
        L"readbackChars=%llu "
        L"firstTargetIdentity=%llu "
        L"precedingSlot=%d "
        L"followingSlot=%d "
        L"manualSavedTargetIndex=%u "
        L"firstSessionOverflowSize=%u "
        L"manualUiOrderPosition=%llu "
        L"firstSessionAnalyzerMoveAttempts=%llu "
        L"firstSessionManualTargetMoveCalls=%llu "
        L"normalizedPath=\"%s\"",
        binaryWriteResult
            ? 1
            : 0,
        pathWriteResult
            ? 1
            : 0,
        writeSucceeded
            ? 1
            : 0,
        readbackSucceeded
            ? 1
            : 0,
        static_cast<unsigned long long>(
            readbackBytes
        ),
        static_cast<unsigned long long>(
            readbackChars
        ),
        static_cast<unsigned long long>(
            state.firstTargetIdentity
        ),
        state.precedingSlot,
        state.followingSlot,
        state.manualSavedTargetIndex,
        state.firstSessionOverflowSize,
        state.manualUiOrderPosition,
        state.firstSessionAnalyzerMoveAttempts,
        state.firstSessionManualTargetMoveCalls,
        normalizedPath.c_str()
    );

    return
        writeSucceeded &&
        readbackSucceeded;
}

void LoadPersistentStateAtInit() {
    PersistedCanonicalState state;
    std::wstring normalizedPath;

    size_t binaryBytes =
        0;

    size_t pathChars =
        0;

    const bool loaded =
        ReadPersistentState(
            &state,
            &normalizedPath,
            &binaryBytes,
            &pathChars
        );

    if (loaded) {
        g_loadedPersistentState =
            state;

        g_loadedNormalizedPath =
            normalizedPath;

        g_persistedStateLoadedAtInit.store(
            true,
            std::memory_order_release
        );

        g_firstTargetIdentity.store(
            state.firstTargetIdentity,
            std::memory_order_release
        );

        g_manualPrecedingSlot.store(
            state.precedingSlot,
            std::memory_order_release
        );

        g_manualFollowingSlot.store(
            state.followingSlot,
            std::memory_order_release
        );

        g_manualSavedTargetIndex.store(
            state.manualSavedTargetIndex,
            std::memory_order_release
        );

        g_firstOverflowSize.store(
            state.firstSessionOverflowSize,
            std::memory_order_release
        );

        g_manualUiOrderPosition.store(
            state.manualUiOrderPosition,
            std::memory_order_release
        );
    }

    Wh_Log(
        L"PERSISTENCE_STATE_LOAD_AT_INIT "
        L"loaded=%d "
        L"binaryBytes=%llu "
        L"pathChars=%llu "
        L"firstTargetIdentity=%llu "
        L"precedingSlot=%d "
        L"followingSlot=%d "
        L"manualSavedTargetIndex=%u "
        L"firstSessionOverflowSize=%u "
        L"firstSessionAnalyzerMoveAttempts=%llu "
        L"firstSessionManualTargetMoveCalls=%llu "
        L"normalizedPath=\"%s\"",
        loaded
            ? 1
            : 0,
        static_cast<unsigned long long>(
            binaryBytes
        ),
        static_cast<unsigned long long>(
            pathChars
        ),
        static_cast<unsigned long long>(
            loaded
                ? state.firstTargetIdentity
                : 0
        ),
        loaded
            ? state.precedingSlot
            : kInvalidAnchorSlot,
        loaded
            ? state.followingSlot
            : kInvalidAnchorSlot,
        loaded
            ? state.manualSavedTargetIndex
            : 0,
        loaded
            ? state.firstSessionOverflowSize
            : 0,
        loaded
            ? state.firstSessionAnalyzerMoveAttempts
            : 0,
        loaded
            ? state.firstSessionManualTargetMoveCalls
            : 0,
        loaded
            ? normalizedPath.c_str()
            : L""
    );
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
            L"PERSISTENCE_REQUIRED_SYMBOL_MISSING"
        );

        return false;
    }

    Wh_Log(
        L"PERSISTENCE_SUPPORT_READY "
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

int GetTargetPhase(
    std::uint64_t identity
) {
    const std::wstring path =
        NormalizeSlashes(
            QueryExecutablePath(
                identity
            )
        );

    if (
        ContainsOrdinalIgnoreCase(
            path,
            kVersion1Marker
        )
    ) {
        return 1;
    }

    if (
        ContainsOrdinalIgnoreCase(
            path,
            kVersion2Marker
        )
    ) {
        return 2;
    }

    return 0;
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
        !IsValidAnchorSlot(
            slot
        ) ||
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

    return
        std::min(
            index,
            size -
                1
        );
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
            const auto& left,
            const auto& right
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

    Wh_Log(
        L"PERSISTENCE_INITIAL_ANCHOR_ORDER "
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
    std::uint64_t identity,
    void* iconImplementation
) {
    if (
        !IsValidAnchorSlot(
            anchorSlot
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
            L"PERSISTENCE_ANCHOR_CAPTURED "
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
    void* pThis,
    std::uint64_t identity,
    void* iconImplementation
) {
    ResetPersistentStateForFreshPhase1();

    if (!AllAnchorsCaptured()) {
        Wh_Log(
            L"PERSISTENCE_PHASE1_SKIPPED "
            L"reason=\"anchors-not-captured\""
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
        return;
    }

    g_firstTargetAbi.store(
        targetAbi,
        std::memory_order_release
    );

    const OverflowPositions before =
        QueryOverflowPositions(
            targetAbi
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
        g_initialFirstAnchorSlot.load(
            std::memory_order_acquire
        );

    const int followingSlot =
        g_initialMiddleAnchorSlot.load(
            std::memory_order_acquire
        );

    unsigned int precedingIndex =
        0;

    if (
        !GetAnchorPosition(
            before,
            precedingSlot,
            &precedingIndex
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
        L"PERSISTENCE_INITIAL_MOVE_BEGIN "
        L"move=%llu "
        L"id=%llu "
        L"overflowSize=%u "
        L"targetIndexBefore=%u "
        L"computedTargetIndex=%u",
        moveNumber,
        static_cast<unsigned long long>(
            identity
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

    g_initialUiOrderPosition.store(
        FindOneBasedPosition(
            snapshot,
            identity
        ),
        std::memory_order_release
    );

    g_initialRelationEstablished.store(
        relationEstablished &&
            moveObserved,
        std::memory_order_release
    );

    Wh_Log(
        L"PERSISTENCE_INITIAL_MOVE_COMPLETE "
        L"move=%llu "
        L"targetIndex=%u "
        L"moveObserved=%d "
        L"relationEstablished=%d",
        moveNumber,
        after.targetIndex,
        moveObserved
            ? 1
            : 0,
        relationEstablished
            ? 1
            : 0
    );

    Wh_Log(
        L"PERSISTENCE_USER_ACTION_READY "
        L"expectedManualPrecedingSlot=%d "
        L"expectedManualFollowingSlot=%d",
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

    const bool trackedTarget =
        firstTargetAbi &&
        notificationAreaIconAbi &&
        IsSameComObject(
            notificationAreaIconAbi,
            firstTargetAbi
        );

    const int originalResult =
        TaskbarModel_MoveNotificationAreaIcon_Original(
            pThis,
            notificationAreaIconAbi,
            location,
            index
        );

    if (!trackedTarget) {
        return originalResult;
    }

    const unsigned long long manualMoveNumber =
        g_manualTargetMoveCalls.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    const OverflowPositions after =
        QueryOverflowPositions(
            firstTargetAbi
        );

    const int expectedPrecedingSlot =
        g_initialMiddleAnchorSlot.load(
            std::memory_order_acquire
        );

    const int expectedFollowingSlot =
        g_initialLastAnchorSlot.load(
            std::memory_order_acquire
        );

    const bool expectedRelation =
        SUCCEEDED(
            static_cast<HRESULT>(
                originalResult
            )
        ) &&
        location ==
            kOverflowLocation &&
        IsTargetDirectlyBetween(
            after,
            expectedPrecedingSlot,
            expectedFollowingSlot
        );

    Wh_Log(
        L"PERSISTENCE_USER_MOVE_COMPLETE "
        L"manualMove=%llu "
        L"result=0x%08X "
        L"location=%d "
        L"requestedIndex=%u "
        L"targetIndex=%u "
        L"expectedRelation=%d "
        L"analyzerMoveAttempts=%llu",
        manualMoveNumber,
        static_cast<unsigned int>(
            static_cast<HRESULT>(
                originalResult
            )
        ),
        location,
        index,
        after.targetIndex,
        expectedRelation
            ? 1
            : 0,
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire
        )
    );

    if (!expectedRelation) {
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

    const std::wstring normalizedPath =
        NormalizeVersionedExecutablePath(
            QueryExecutablePath(
                g_firstTargetIdentity.load(
                    std::memory_order_acquire
                )
            )
        );

    const bool persistenceResult =
        PersistManualCanonicalState(
            normalizedPath
        );

    Wh_Log(
        L"PERSISTENCE_CANONICAL_UPDATED_AND_SAVED "
        L"precedingSlot=%d "
        L"followingSlot=%d "
        L"savedTargetIndex=%u "
        L"uiOrderPosition=%llu "
        L"persistenceResult=%d",
        expectedPrecedingSlot,
        expectedFollowingSlot,
        after.targetIndex,
        manualUiOrderPosition,
        persistenceResult
            ? 1
            : 0
    );

    return originalResult;
}

void LogFinalValidation(
    const HistoricalCandidate& candidate,
    const OverflowPositions& before,
    const OverflowPositions& after,
    const std::wstring& currentNormalizedPath
) {
    const bool persistedPathMatchesCurrent =
        !g_loadedNormalizedPath.empty() &&
        g_loadedNormalizedPath ==
            currentNormalizedPath;

    const bool candidateMatchesPersistedFirst =
        candidate.identity ==
        g_loadedPersistentState.firstTargetIdentity;

    const bool collectionChanged =
        g_loadedPersistentState.firstSessionOverflowSize !=
        g_secondOverflowSize.load(
            std::memory_order_acquire
        );

    const bool numericIndexInvalidated =
        g_loadedPersistentState.manualSavedTargetIndex !=
        g_secondMoveTargetIndex.load(
            std::memory_order_acquire
        );

    const bool replacementBetweenPersistedAnchors =
        IsTargetDirectlyBetween(
            after,
            g_loadedPersistentState.precedingSlot,
            g_loadedPersistentState.followingSlot
        );

    const bool exactlyOneSecondSessionAnalyzerMove =
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire
        ) ==
        1;

    const bool validationCompleted =
        g_persistedStateLoadedAtInit.load(
            std::memory_order_acquire
        ) &&
        IsValidPersistedState(
            g_loadedPersistentState
        ) &&
        persistedPathMatchesCurrent &&
        g_loadedPersistentState.firstSessionAnalyzerMoveAttempts ==
            1 &&
        g_loadedPersistentState.firstSessionManualTargetMoveCalls >=
            1 &&
        g_candidateCount.load(
            std::memory_order_acquire
        ) ==
            1 &&
        candidateMatchesPersistedFirst &&
        !candidate.pathExists &&
        g_uniqueCandidateObserved.load(
            std::memory_order_acquire
        ) &&
        g_uniqueCandidateSelected.load(
            std::memory_order_acquire
        ) &&
        g_helperIdentityCount.load(
            std::memory_order_acquire
        ) ==
            3 &&
        collectionChanged &&
        numericIndexInvalidated &&
        replacementBetweenPersistedAnchors &&
        g_replacementRestoredToPersistedRelation.load(
            std::memory_order_acquire
        ) &&
        g_restoreDecisions.load(
            std::memory_order_acquire
        ) ==
            1 &&
        exactlyOneSecondSessionAnalyzerMove;

    g_persistenceValidationCompleted.store(
        validationCompleted,
        std::memory_order_release
    );

    Wh_Log(
        L"PERSISTENCE_RESULT "
        L"persistedStateLoadedAtInit=%d "
        L"persistedFirstTargetIdentity=%llu "
        L"persistedPrecedingSlot=%d "
        L"persistedFollowingSlot=%d "
        L"persistedManualSavedTargetIndex=%u "
        L"persistedFirstSessionOverflowSize=%u "
        L"persistedFirstSessionAnalyzerMoves=%llu "
        L"persistedFirstSessionManualMoves=%llu "
        L"persistedPathMatchesCurrent=%d "
        L"candidateCount=%u "
        L"candidateIdentity=%llu "
        L"candidateMatchesPersistedFirst=%d "
        L"candidatePathExists=%d "
        L"uniqueCandidateObserved=%d "
        L"uniqueCandidateSelected=%d "
        L"helperCount=%llu "
        L"secondOverflowSize=%u "
        L"collectionChanged=%d "
        L"persistedManualSavedTargetIndex=%u "
        L"secondMoveTargetIndex=%u "
        L"numericIndexInvalidated=%d "
        L"secondTargetIndexBefore=%u "
        L"secondTargetIndexAfter=%u "
        L"replacementBetweenPersistedAnchors=%d "
        L"replacementRestoredToPersistedRelation=%d "
        L"restoreDecisions=%llu "
        L"secondSessionAnalyzerMoveAttempts=%llu "
        L"exactlyOneSecondSessionAnalyzerMove=%d "
        L"persistenceValidationCompleted=%d",
        g_persistedStateLoadedAtInit.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        static_cast<unsigned long long>(
            g_loadedPersistentState.firstTargetIdentity
        ),
        g_loadedPersistentState.precedingSlot,
        g_loadedPersistentState.followingSlot,
        g_loadedPersistentState.manualSavedTargetIndex,
        g_loadedPersistentState.firstSessionOverflowSize,
        g_loadedPersistentState.firstSessionAnalyzerMoveAttempts,
        g_loadedPersistentState.firstSessionManualTargetMoveCalls,
        persistedPathMatchesCurrent
            ? 1
            : 0,
        g_candidateCount.load(
            std::memory_order_acquire
        ),
        static_cast<unsigned long long>(
            candidate.identity
        ),
        candidateMatchesPersistedFirst
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
        g_helperIdentityCount.load(
            std::memory_order_acquire
        ),
        g_secondOverflowSize.load(
            std::memory_order_acquire
        ),
        collectionChanged
            ? 1
            : 0,
        g_loadedPersistentState.manualSavedTargetIndex,
        g_secondMoveTargetIndex.load(
            std::memory_order_acquire
        ),
        numericIndexInvalidated
            ? 1
            : 0,
        before.targetIndex,
        after.targetIndex,
        replacementBetweenPersistedAnchors
            ? 1
            : 0,
        g_replacementRestoredToPersistedRelation.load(
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
        exactlyOneSecondSessionAnalyzerMove
            ? 1
            : 0,
        validationCompleted
            ? 1
            : 0
    );

    Wh_Log(
        L"PERSISTENCE_SUMMARY "
        L"firstTargetIdentity=%llu "
        L"secondTargetIdentity=%llu "
        L"selectedHistoricalIdentity=%llu "
        L"persistedPrecedingSlot=%d "
        L"persistedFollowingSlot=%d "
        L"persistedManualSavedTargetIndex=%u "
        L"secondMoveTargetIndex=%u "
        L"secondPrecedingIndexBefore=%u "
        L"secondFollowingIndexBefore=%u "
        L"secondUiOrderPosition=%llu "
        L"helperCount=%llu "
        L"candidateCount=%u "
        L"restoreDecisions=%llu "
        L"secondSessionAnalyzerMoveAttempts=%llu "
        L"persistenceValidationCompleted=%d",
        static_cast<unsigned long long>(
            g_loadedPersistentState.firstTargetIdentity
        ),
        static_cast<unsigned long long>(
            g_secondTargetIdentity.load(
                std::memory_order_acquire
            )
        ),
        static_cast<unsigned long long>(
            g_selectedHistoricalIdentity.load(
                std::memory_order_acquire
            )
        ),
        g_loadedPersistentState.precedingSlot,
        g_loadedPersistentState.followingSlot,
        g_loadedPersistentState.manualSavedTargetIndex,
        g_secondMoveTargetIndex.load(
            std::memory_order_acquire
        ),
        g_secondPrecedingIndexBefore.load(
            std::memory_order_acquire
        ),
        g_secondFollowingIndexBefore.load(
            std::memory_order_acquire
        ),
        g_secondUiOrderPosition.load(
            std::memory_order_acquire
        ),
        g_helperIdentityCount.load(
            std::memory_order_acquire
        ),
        g_candidateCount.load(
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

    if (validationCompleted) {
        const BOOL binaryDeleteResult =
            Wh_DeleteValue(
                kPersistentStateValueName
            );

        const BOOL pathDeleteResult =
            Wh_DeleteValue(
                kPersistentPathValueName
            );

        Wh_Log(
            L"PERSISTENCE_TEST_STORAGE_CLEANUP "
            L"binaryDeleteResult=%d "
            L"pathDeleteResult=%d",
            binaryDeleteResult
                ? 1
                : 0,
            pathDeleteResult
                ? 1
                : 0
        );
    }
}

void HandleReplacementTarget(
    void* pThis,
    std::uint64_t identity,
    void* iconImplementation
) {
    if (
        !g_persistedStateLoadedAtInit.load(
            std::memory_order_acquire
        )
    ) {
        Wh_Log(
            L"PERSISTENCE_REPLACEMENT_REJECTED "
            L"reason=\"persistent-state-not-loaded-at-init\""
        );

        return;
    }

    if (!AllAnchorsCaptured()) {
        Wh_Log(
            L"PERSISTENCE_REPLACEMENT_REJECTED "
            L"reason=\"phase2-anchors-not-captured\""
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

    const std::wstring currentNormalizedPath =
        NormalizeVersionedExecutablePath(
            QueryExecutablePath(
                identity
            )
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

    g_restoreDecisions.fetch_add(
        1,
        std::memory_order_relaxed
    );

    Wh_Log(
        L"PERSISTENCE_MATCH_SEARCH "
        L"currentIdentity=%llu "
        L"candidateCount=%llu "
        L"persistedPathMatchesCurrent=%d",
        static_cast<unsigned long long>(
            identity
        ),
        static_cast<unsigned long long>(
            candidates.size()
        ),
        currentNormalizedPath ==
                g_loadedNormalizedPath
            ? 1
            : 0
    );

    if (
        candidates.size() !=
        1
    ) {
        Wh_Log(
            L"PERSISTENCE_MATCH_REJECTED "
            L"reason=\"logical-match-not-unique\""
        );

        reinterpret_cast<IUnknown*>(
            targetAbi
        )->Release();

        return;
    }

    const HistoricalCandidate& candidate =
        candidates.front();

    Wh_Log(
        L"PERSISTENCE_MATCH_CANDIDATE "
        L"id=%llu "
        L"uid=%u "
        L"pathExists=%d "
        L"uiOrderPosition=%llu",
        static_cast<unsigned long long>(
            candidate.identity
        ),
        candidate.uid,
        candidate.pathExists
            ? 1
            : 0,
        candidate.uiOrderPosition
    );

    g_uniqueCandidateObserved.store(
        true,
        std::memory_order_release
    );

    if (
        candidate.identity !=
        g_loadedPersistentState.firstTargetIdentity ||
        currentNormalizedPath !=
        g_loadedNormalizedPath
    ) {
        Wh_Log(
            L"PERSISTENCE_MATCH_REJECTED "
            L"reason=\"candidate-or-logical-path-does-not-match-persisted-state\""
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
        L"PERSISTENCE_MATCH_SELECTED "
        L"currentIdentity=%llu "
        L"historicalIdentity=%llu "
        L"precedingSlot=%d "
        L"followingSlot=%d",
        static_cast<unsigned long long>(
            identity
        ),
        static_cast<unsigned long long>(
            candidate.identity
        ),
        g_loadedPersistentState.precedingSlot,
        g_loadedPersistentState.followingSlot
    );

    unsigned int precedingIndex =
        0;

    unsigned int followingIndex =
        0;

    const bool precedingFound =
        GetAnchorPosition(
            before,
            g_loadedPersistentState.precedingSlot,
            &precedingIndex
        );

    const bool followingFound =
        GetAnchorPosition(
            before,
            g_loadedPersistentState.followingSlot,
            &followingIndex
        );

    Wh_Log(
        L"PERSISTENCE_LIVE_PERSISTED_NEIGHBORS "
        L"precedingFound=%d "
        L"precedingIndex=%u "
        L"followingFound=%d "
        L"followingIndex=%u "
        L"targetIndex=%u "
        L"overflowSize=%u",
        precedingFound
            ? 1
            : 0,
        precedingIndex,
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
            L"PERSISTENCE_ORDER_REJECTED "
            L"reason=\"persisted-neighbor-interval-unavailable\""
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
        L"PERSISTENCE_REPLACEMENT_MOVE_BEGIN "
        L"move=%llu "
        L"persistedManualSavedTargetIndex=%u "
        L"computedTargetIndex=%u "
        L"targetIndexBefore=%u",
        moveNumber,
        g_loadedPersistentState.manualSavedTargetIndex,
        desiredIndex,
        before.targetIndex
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
            g_loadedPersistentState.precedingSlot,
            g_loadedPersistentState.followingSlot
        );

    const bool moveObserved =
        after.targetFound &&
        before.targetIndex !=
            after.targetIndex;

    g_secondTargetIndexAfter.store(
        after.targetIndex,
        std::memory_order_release
    );

    g_replacementRestoredToPersistedRelation.store(
        relationRestored &&
            moveObserved,
        std::memory_order_release
    );

    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    g_secondUiOrderPosition.store(
        FindOneBasedPosition(
            snapshot,
            identity
        ),
        std::memory_order_release
    );

    Wh_Log(
        L"PERSISTENCE_REPLACEMENT_MOVE_COMPLETE "
        L"move=%llu "
        L"targetIndex=%u "
        L"moveObserved=%d "
        L"relationRestored=%d",
        moveNumber,
        after.targetIndex,
        moveObserved
            ? 1
            : 0,
        relationRestored
            ? 1
            : 0
    );

    LogFinalValidation(
        candidate,
        before,
        after,
        currentNormalizedPath
    );

    reinterpret_cast<IUnknown*>(
        targetAbi
    )->Release();
}

void HandleTargetIcon(
    void* pThis,
    std::uint64_t identity,
    void* iconImplementation
) {
    const int phase =
        GetTargetPhase(
            identity
        );

    if (
        phase ==
        1
    ) {
        HandleFirstTarget(
            pThis,
            identity,
            iconImplementation
        );

        return;
    }

    if (
        phase ==
        2
    ) {
        HandleReplacementTarget(
            pThis,
            identity,
            iconImplementation
        );
    }
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
        L"result=0x%08X",
        callNumber,
        static_cast<unsigned int>(
            static_cast<HRESULT>(
                originalResult
            )
        )
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

    NotificationAreaIconManager_AddIcon_Original(
        pThis,
        trayNotifyData
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
    g_visibleAddCalls.fetch_add(
        1,
        std::memory_order_relaxed
    );

    NotificationAreaIconManager_AddVisible_Original(
        pThis,
        iconImplementation
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

    if (
        anchorAdded.size() ==
        1
    ) {
        CaptureAnchorInterface(
            anchorAdded.front().first,
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
            L"PERSISTENCE_HELPER_OBSERVED "
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

    return
        WindhawkUtils::HookSymbols(
            taskbarModule,
            symbolHooks,
            ARRAYSIZE(
                symbolHooks
            )
        );
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
        L"0.27.0 initializing"
    );

    if (!IsPrimaryShellProcess()) {
        return TRUE;
    }

    LoadPersistentStateAtInit();

    HMODULE taskbarModule =
        GetModuleHandleW(
            L"taskbar.dll"
        );

    if (!taskbarModule) {
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
        L"PERSISTENCE_TEST_READY "
        L"processId=%lu "
        L"persistedStateLoadedAtInit=%d",
        GetCurrentProcessId(),
        g_persistedStateLoadedAtInit.load(
            std::memory_order_acquire
        )
            ? 1
            : 0
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
        L"analyzerMoveAttempts=%llu "
        L"manualTargetMoveCalls=%llu "
        L"manualRelationUpdates=%llu "
        L"helperCount=%llu "
        L"candidateCount=%u "
        L"persistentWriteSucceeded=%d "
        L"persistentImmediateReadbackSucceeded=%d "
        L"persistedStateLoadedAtInit=%d "
        L"uniqueCandidateSelected=%d "
        L"replacementRestoredToPersistedRelation=%d "
        L"persistenceValidationCompleted=%d",
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire
        ),
        g_manualTargetMoveCalls.load(
            std::memory_order_acquire
        ),
        g_manualRelationUpdates.load(
            std::memory_order_acquire
        ),
        g_helperIdentityCount.load(
            std::memory_order_acquire
        ),
        g_candidateCount.load(
            std::memory_order_acquire
        ),
        g_persistentWriteSucceeded.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_persistentImmediateReadbackSucceeded.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_persistedStateLoadedAtInit.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_uniqueCandidateSelected.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_replacementRestoredToPersistedRelation.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_persistenceValidationCompleted.load(
            std::memory_order_acquire
        )
            ? 1
            : 0
    );
}
