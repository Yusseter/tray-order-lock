// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Tests Explorer restart persistence with delayed primary-shell taskbar hook initialization.
// @version         0.28.1
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

Version 0.28.1 validates that manually learned canonical tray-order state
survives a complete Explorer process restart.

Phase 1:

- Three stable logical anchor executables create fresh GUID identities.
- Version-1.0.0 creates a UID=1 target.
- The analyzer places it between the first and second live anchors.
- The user manually drags it into the second anchor interval.
- The resulting relation is saved with Windhawk local storage.
- The persisted state includes the current Explorer PID.

Phase 1 applications are then closed.

The user restarts Windows Explorer from Task Manager.

This destroys the original Explorer process and therefore all analyzer C++
globals, COM references and process-local state.

Windhawk injects the analyzer into the replacement Explorer process.

At the new Wh_ModInit:

- the persistent state must load successfully;
- the current Explorer PID must differ from the persisted phase-1 PID.

Phase 2:

- Fresh anchor GUID identities are created.
- Three helper icons alter the live overflow geometry.
- Version-2.0.0 creates a replacement UID identity.
- Exactly one historical target candidate is expected.
- It must equal the persisted phase-1 Windows target identity.
- The persisted predecessor/follower logical anchor slots are resolved against
  the new Explorer process's CURRENT live anchor objects.
- The replacement is restored between them.

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
    L"CanonicalStateV281";

constexpr wchar_t kPersistentPathValueName[] =
    L"CanonicalNormalizedPathV281";

constexpr std::uint32_t kPersistentStateMagic =
    0x56323831;

constexpr std::uint32_t kPersistentStateVersion =
    1;

constexpr int kAnchorCount = 3;
constexpr int kInvalidAnchorSlot = -1;
constexpr int kOverflowLocation = 1;
constexpr DWORD kTargetUid = 1;

constexpr wchar_t kAnchorAExecutableName[] =
    L"trayrestartanchoraprobev280.exe";

constexpr wchar_t kAnchorBExecutableName[] =
    L"trayrestartanchorbprobev280.exe";

constexpr wchar_t kAnchorCExecutableName[] =
    L"trayrestartanchorcprobev280.exe";

constexpr const wchar_t* kAnchorExecutableNames[kAnchorCount] = {
    kAnchorAExecutableName,
    kAnchorBExecutableName,
    kAnchorCExecutableName,
};

constexpr wchar_t kTargetExecutableName[] =
    L"trayuidrestartrestoreprobev280.exe";

constexpr wchar_t kHelperExecutableName[] =
    L"trayrestartcollectionhelperv280.exe";

constexpr wchar_t kVersion1Marker[] =
    L"\\version-1.0.0\\";

constexpr wchar_t kVersion2Marker[] =
    L"\\version-2.0.0\\";

using NotificationAreaIconManager_AddIcon_t =
    void(__cdecl*)(void*, void*);

using NotificationAreaIconManager_AddVisible_t =
    void(__cdecl*)(void*, void*);

using NotificationAreaIconManager_MoveIcon_t =
    void(__cdecl*)(void*, void*, int, unsigned int);

using NotificationAreaIcon_QueryInterface_t =
    int(__cdecl*)(void*, const GUID&, void**);

using TaskbarModel_GetOverflowIcons_t =
    int(__cdecl*)(void*, void**);

using TaskbarModel_MoveNotificationAreaIcon_t =
    int(__cdecl*)(void*, void*, int, unsigned int);

using Vector_GetAt_t =
    HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int, void**);

using Vector_GetSize_t =
    HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int*);

using CreateWindowExW_t =
    decltype(&CreateWindowExW);

struct PersistedCanonicalState {
    std::uint32_t magic = 0;
    std::uint32_t version = 0;

    std::uint64_t firstTargetIdentity = 0;

    std::int32_t precedingSlot = kInvalidAnchorSlot;
    std::int32_t followingSlot = kInvalidAnchorSlot;

    std::uint32_t manualSavedTargetIndex = 0;
    std::uint32_t firstSessionOverflowSize = 0;

    std::uint64_t manualUiOrderPosition = 0;
    std::uint64_t firstSessionAnalyzerMoveAttempts = 0;
    std::uint64_t firstSessionManualTargetMoveCalls = 0;

    std::uint32_t firstExplorerProcessId = 0;
    std::uint32_t reserved = 0;
};

struct UIOrderSnapshot {
    bool valid = false;
    LONG status = ERROR_SUCCESS;
    std::vector<std::uint64_t> entries;
};

struct AddIconContext {
    bool active = false;
    UIOrderSnapshot before;
};

struct OverflowPositions {
    bool enumerated = false;
    HRESULT getterResult = E_FAIL;
    HRESULT vectorQueryResult = E_FAIL;
    HRESULT sizeResult = E_FAIL;

    unsigned int size = 0;

    bool anchorFound[kAnchorCount]{};
    unsigned int anchorIndex[kAnchorCount]{};

    bool targetFound = false;
    unsigned int targetIndex = 0;
};

struct HistoricalCandidate {
    std::uint64_t identity = 0;
    std::wstring executablePath;
    std::wstring normalizedPath;
    DWORD uid = 0;
    bool uidValid = false;
    bool pathExists = false;
    unsigned long long uiOrderPosition = 0;
};

NotificationAreaIconManager_AddIcon_t
    NotificationAreaIconManager_AddIcon_Original = nullptr;

NotificationAreaIconManager_AddVisible_t
    NotificationAreaIconManager_AddVisible_Original = nullptr;

NotificationAreaIconManager_MoveIcon_t
    NotificationAreaIconManager_MoveIcon = nullptr;

NotificationAreaIcon_QueryInterface_t
    NotificationAreaIcon_QueryInterface = nullptr;

TaskbarModel_GetOverflowIcons_t
    TaskbarModel_GetOverflowIcons_Original = nullptr;

TaskbarModel_MoveNotificationAreaIcon_t
    TaskbarModel_MoveNotificationAreaIcon_Original = nullptr;

CreateWindowExW_t
    CreateWindowExW_Original = nullptr;

const GUID* g_notificationAreaIconInterfaceId = nullptr;
const GUID* g_notificationAreaIconVectorId = nullptr;

std::atomic<void*> g_taskbarModel6 = nullptr;

std::atomic<void*> g_anchorAbis[kAnchorCount]{};
std::atomic<bool> g_anchorCaptured[kAnchorCount]{};

std::atomic<void*> g_firstTargetAbi = nullptr;

std::atomic<std::uint64_t> g_firstTargetIdentity = 0;
std::atomic<std::uint64_t> g_secondTargetIdentity = 0;
std::atomic<std::uint64_t> g_selectedHistoricalIdentity = 0;

std::atomic<int> g_initialFirstAnchorSlot = kInvalidAnchorSlot;
std::atomic<int> g_initialMiddleAnchorSlot = kInvalidAnchorSlot;
std::atomic<int> g_initialLastAnchorSlot = kInvalidAnchorSlot;

std::atomic<int> g_manualPrecedingSlot = kInvalidAnchorSlot;
std::atomic<int> g_manualFollowingSlot = kInvalidAnchorSlot;

std::atomic<unsigned long long> g_analyzerMoveAttempts = 0;
std::atomic<unsigned long long> g_manualTargetMoveCalls = 0;
std::atomic<unsigned long long> g_manualRelationUpdates = 0;
std::atomic<unsigned long long> g_helperIdentityCount = 0;
std::atomic<unsigned long long> g_restoreDecisions = 0;

std::atomic<unsigned int> g_candidateCount = 0;

std::atomic<unsigned int> g_firstOverflowSize = 0;
std::atomic<unsigned int> g_secondOverflowSize = 0;

std::atomic<unsigned int> g_manualSavedTargetIndex = 0;
std::atomic<unsigned int> g_secondMoveTargetIndex = 0;

std::atomic<unsigned int> g_secondTargetIndexBefore = 0;
std::atomic<unsigned int> g_secondTargetIndexAfter = 0;

std::atomic<unsigned int> g_secondPrecedingIndexBefore = 0;
std::atomic<unsigned int> g_secondFollowingIndexBefore = 0;

std::atomic<unsigned long long> g_manualUiOrderPosition = 0;
std::atomic<unsigned long long> g_secondUiOrderPosition = 0;

std::atomic<bool> g_initialRelationEstablished = false;
std::atomic<bool> g_manualCanonicalRelationUpdated = false;

std::atomic<bool> g_persistentWriteSucceeded = false;
std::atomic<bool> g_persistentImmediateReadbackSucceeded = false;
std::atomic<bool> g_persistedStateLoadedAtInit = false;

std::atomic<bool> g_explorerProcessChanged = false;

std::atomic<bool> g_taskbarHooksInitializing = false;
std::atomic<bool> g_taskbarHooksInitialized = false;

std::atomic<bool> g_uniqueCandidateObserved = false;
std::atomic<bool> g_uniqueCandidateSelected = false;

std::atomic<bool> g_replacementRestoredToPersistedRelation = false;
std::atomic<bool> g_restartPersistenceValidationCompleted = false;

PersistedCanonicalState g_loadedPersistentState;
std::wstring g_loadedNormalizedPath;

thread_local unsigned int g_internalMoveDepth = 0;
thread_local AddIconContext g_addIconContext;

std::wstring ToLower(std::wstring value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](wchar_t c) {
            return static_cast<wchar_t>(std::towlower(c));
        });

    return value;
}

std::wstring NormalizeSlashes(std::wstring path) {
    std::replace(path.begin(), path.end(), L'/', L'\\');
    return path;
}

bool ContainsText(const wchar_t* text, const wchar_t* expected) {
    return
        text &&
        expected &&
        std::wcsstr(text, expected) != nullptr;
}

bool ContainsOrdinalIgnoreCase(
    const std::wstring& value,
    const std::wstring& expected) {
    return
        ToLower(value).find(ToLower(expected)) !=
        std::wstring::npos;
}

bool EndsWithOrdinalIgnoreCase(
    const std::wstring& value,
    const std::wstring& suffix) {
    if (value.size() < suffix.size()) {
        return false;
    }

    const std::size_t offset =
        value.size() - suffix.size();

    for (std::size_t i = 0; i < suffix.size(); i++) {
        if (
            std::towlower(value[offset + i]) !=
            std::towlower(suffix[i])) {
            return false;
        }
    }

    return true;
}

bool StartsWithOrdinalIgnoreCase(
    const std::wstring& value,
    const std::wstring& prefix) {
    if (value.size() < prefix.size()) {
        return false;
    }

    for (std::size_t i = 0; i < prefix.size(); i++) {
        if (
            std::towlower(value[i]) !=
            std::towlower(prefix[i])) {
            return false;
        }
    }

    return true;
}

bool IsVersionDirectoryName(const std::wstring& directoryName) {
    constexpr wchar_t prefix[] = L"version-";

    if (!StartsWithOrdinalIgnoreCase(directoryName, prefix)) {
        return false;
    }

    const std::size_t prefixLength =
        std::wcslen(prefix);

    if (directoryName.size() <= prefixLength) {
        return false;
    }

    bool digitSeen = false;

    for (
        std::size_t i = prefixLength;
        i < directoryName.size();
        i++) {
        const wchar_t c = directoryName[i];

        if (c >= L'0' && c <= L'9') {
            digitSeen = true;
            continue;
        }

        if (c == L'.') {
            continue;
        }

        return false;
    }

    return digitSeen;
}

std::wstring NormalizeVersionedExecutablePath(
    const std::wstring& executablePath) {
    std::wstring normalized =
        ToLower(NormalizeSlashes(executablePath));

    const std::size_t fileSeparator =
        normalized.find_last_of(L'\\');

    if (
        fileSeparator == std::wstring::npos ||
        fileSeparator == 0) {
        return normalized;
    }

    const std::size_t parentSeparator =
        normalized.find_last_of(
            L'\\',
            fileSeparator - 1);

    if (parentSeparator == std::wstring::npos) {
        return normalized;
    }

    const std::size_t parentStart =
        parentSeparator + 1;

    const std::size_t parentLength =
        fileSeparator - parentStart;

    const std::wstring parentDirectory =
        normalized.substr(
            parentStart,
            parentLength);

    if (!IsVersionDirectoryName(parentDirectory)) {
        return normalized;
    }

    normalized.replace(
        parentStart,
        parentLength,
        L"<version>");

    return normalized;
}

bool FileExists(const std::wstring& path) {
    if (path.empty()) {
        return false;
    }

    const DWORD attributes =
        GetFileAttributesW(path.c_str());

    return
        attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool IsValidAnchorSlot(int slot) {
    return
        slot >= 0 &&
        slot < kAnchorCount;
}

bool IsValidPersistedState(
    const PersistedCanonicalState& state) {
    return
        state.magic == kPersistentStateMagic &&
        state.version == kPersistentStateVersion &&
        state.firstTargetIdentity != 0 &&
        IsValidAnchorSlot(state.precedingSlot) &&
        IsValidAnchorSlot(state.followingSlot) &&
        state.precedingSlot != state.followingSlot &&
        state.firstSessionAnalyzerMoveAttempts == 1 &&
        state.firstSessionManualTargetMoveCalls >= 1 &&
        state.firstExplorerProcessId != 0;
}

bool ReadPersistentState(
    PersistedCanonicalState* state,
    std::wstring* normalizedPath,
    size_t* binaryBytes = nullptr,
    size_t* pathChars = nullptr) {
    if (!state || !normalizedPath) {
        return false;
    }

    *state = {};
    normalizedPath->clear();

    const size_t bytes =
        Wh_GetBinaryValue(
            kPersistentStateValueName,
            state,
            sizeof(*state));

    wchar_t pathBuffer[2048]{};

    const size_t chars =
        Wh_GetStringValue(
            kPersistentPathValueName,
            pathBuffer,
            ARRAYSIZE(pathBuffer));

    if (binaryBytes) {
        *binaryBytes = bytes;
    }

    if (pathChars) {
        *pathChars = chars;
    }

    if (
        bytes != sizeof(*state) ||
        chars == 0 ||
        !IsValidPersistedState(*state)) {
        *state = {};
        return false;
    }

    *normalizedPath = pathBuffer;
    return true;
}

void ResetPersistentStateForFreshPhase1() {
    Wh_DeleteValue(kPersistentStateValueName);
    Wh_DeleteValue(kPersistentPathValueName);

    g_loadedPersistentState = {};
    g_loadedNormalizedPath.clear();

    g_persistedStateLoadedAtInit.store(
        false,
        std::memory_order_release);

    Wh_Log(
        L"RESTART_PERSISTENCE_PHASE1_STORAGE_RESET");
}

bool PersistManualCanonicalState(
    const std::wstring& normalizedPath) {
    PersistedCanonicalState state;

    state.magic =
        kPersistentStateMagic;

    state.version =
        kPersistentStateVersion;

    state.firstTargetIdentity =
        g_firstTargetIdentity.load(
            std::memory_order_acquire);

    state.precedingSlot =
        g_manualPrecedingSlot.load(
            std::memory_order_acquire);

    state.followingSlot =
        g_manualFollowingSlot.load(
            std::memory_order_acquire);

    state.manualSavedTargetIndex =
        g_manualSavedTargetIndex.load(
            std::memory_order_acquire);

    state.firstSessionOverflowSize =
        g_firstOverflowSize.load(
            std::memory_order_acquire);

    state.manualUiOrderPosition =
        g_manualUiOrderPosition.load(
            std::memory_order_acquire);

    state.firstSessionAnalyzerMoveAttempts =
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire);

    state.firstSessionManualTargetMoveCalls =
        g_manualTargetMoveCalls.load(
            std::memory_order_acquire);

    state.firstExplorerProcessId =
        GetCurrentProcessId();

    const BOOL binaryWrite =
        Wh_SetBinaryValue(
            kPersistentStateValueName,
            &state,
            sizeof(state));

    const BOOL pathWrite =
        Wh_SetStringValue(
            kPersistentPathValueName,
            normalizedPath.c_str());

    const bool writeSucceeded =
        binaryWrite &&
        pathWrite;

    g_persistentWriteSucceeded.store(
        writeSucceeded,
        std::memory_order_release);

    PersistedCanonicalState readbackState;
    std::wstring readbackPath;

    size_t readbackBytes = 0;
    size_t readbackChars = 0;

    const bool readbackSucceeded =
        ReadPersistentState(
            &readbackState,
            &readbackPath,
            &readbackBytes,
            &readbackChars) &&
        readbackState.firstTargetIdentity ==
            state.firstTargetIdentity &&
        readbackState.precedingSlot ==
            state.precedingSlot &&
        readbackState.followingSlot ==
            state.followingSlot &&
        readbackState.firstExplorerProcessId ==
            state.firstExplorerProcessId &&
        readbackPath ==
            normalizedPath;

    g_persistentImmediateReadbackSucceeded.store(
        readbackSucceeded,
        std::memory_order_release);

    Wh_Log(
        L"RESTART_PERSISTENCE_STATE_WRITE "
        L"writeSucceeded=%d "
        L"readbackSucceeded=%d "
        L"readbackBytes=%llu "
        L"readbackChars=%llu "
        L"firstTargetIdentity=%llu "
        L"precedingSlot=%d "
        L"followingSlot=%d "
        L"manualSavedTargetIndex=%u "
        L"firstSessionOverflowSize=%u "
        L"firstSessionAnalyzerMoves=%llu "
        L"firstSessionManualMoves=%llu "
        L"firstExplorerProcessId=%lu "
        L"normalizedPath=\"%s\"",
        writeSucceeded ? 1 : 0,
        readbackSucceeded ? 1 : 0,
        static_cast<unsigned long long>(readbackBytes),
        static_cast<unsigned long long>(readbackChars),
        static_cast<unsigned long long>(
            state.firstTargetIdentity),
        state.precedingSlot,
        state.followingSlot,
        state.manualSavedTargetIndex,
        state.firstSessionOverflowSize,
        state.firstSessionAnalyzerMoveAttempts,
        state.firstSessionManualTargetMoveCalls,
        state.firstExplorerProcessId,
        normalizedPath.c_str());

    return
        writeSucceeded &&
        readbackSucceeded;
}

void LoadPersistentStateAtInit() {
    PersistedCanonicalState state;
    std::wstring normalizedPath;

    size_t binaryBytes = 0;
    size_t pathChars = 0;

    const bool loaded =
        ReadPersistentState(
            &state,
            &normalizedPath,
            &binaryBytes,
            &pathChars);

    if (loaded) {
        g_loadedPersistentState = state;
        g_loadedNormalizedPath = normalizedPath;

        g_persistedStateLoadedAtInit.store(
            true,
            std::memory_order_release);

        g_firstTargetIdentity.store(
            state.firstTargetIdentity,
            std::memory_order_release);

        g_manualPrecedingSlot.store(
            state.precedingSlot,
            std::memory_order_release);

        g_manualFollowingSlot.store(
            state.followingSlot,
            std::memory_order_release);

        g_manualSavedTargetIndex.store(
            state.manualSavedTargetIndex,
            std::memory_order_release);

        g_firstOverflowSize.store(
            state.firstSessionOverflowSize,
            std::memory_order_release);

        g_manualUiOrderPosition.store(
            state.manualUiOrderPosition,
            std::memory_order_release);

        g_explorerProcessChanged.store(
            state.firstExplorerProcessId !=
                GetCurrentProcessId(),
            std::memory_order_release);
    }

    Wh_Log(
        L"RESTART_PERSISTENCE_STATE_LOAD_AT_INIT "
        L"loaded=%d "
        L"binaryBytes=%llu "
        L"pathChars=%llu "
        L"persistedExplorerPid=%lu "
        L"currentExplorerPid=%lu "
        L"explorerProcessChanged=%d "
        L"firstTargetIdentity=%llu "
        L"precedingSlot=%d "
        L"followingSlot=%d "
        L"manualSavedTargetIndex=%u",
        loaded ? 1 : 0,
        static_cast<unsigned long long>(binaryBytes),
        static_cast<unsigned long long>(pathChars),
        loaded ? state.firstExplorerProcessId : 0,
        GetCurrentProcessId(),
        g_explorerProcessChanged.load(
            std::memory_order_acquire)
            ? 1
            : 0,
        static_cast<unsigned long long>(
            loaded
                ? state.firstTargetIdentity
                : 0),
        loaded
            ? state.precedingSlot
            : kInvalidAnchorSlot,
        loaded
            ? state.followingSlot
            : kInvalidAnchorSlot,
        loaded
            ? state.manualSavedTargetIndex
            : 0);
}

bool IsNotificationAreaIconQueryInterfaceSymbol(
    const wchar_t* symbol) {
    return
        ContainsText(symbol, L"root_implements<") &&
        ContainsText(symbol, L"NotificationAreaIcon2") &&
        ContainsText(symbol, L">::query_interface(") &&
        ContainsText(symbol, L"winrt::guid const &") &&
        ContainsText(symbol, L"void * *") &&
        !ContainsText(symbol, L"query_interface_common") &&
        !ContainsText(symbol, L"query_interface_tearoff");
}

bool IsNotificationAreaIconIidSymbol(
    const wchar_t* symbol) {
    constexpr wchar_t expected[] =
        L"struct guid::guid const "
        L"winrt::impl::guid_v<struct "
        L"winrt::WindowsUdk::UI::Shell::"
        L"INotificationAreaIcon>";

    return
        symbol &&
        std::wcscmp(symbol, expected) == 0;
}

bool IsNotificationAreaIconVectorIidSymbol(
    const wchar_t* symbol) {
    constexpr wchar_t expected[] =
        L"struct guid::guid const "
        L"winrt::impl::guid_v<struct "
        L"winrt::Windows::Foundation::Collections::"
        L"IVector<struct "
        L"winrt::WindowsUdk::UI::Shell::"
        L"NotificationAreaIcon> >";

    return
        symbol &&
        std::wcscmp(symbol, expected) == 0;
}

bool IsManagerMoveIconSymbol(
    const wchar_t* symbol) {
    constexpr wchar_t expected[] =
        L"public: void __cdecl "
        L"NotificationAreaIconManager2::MoveIcon("
        L"struct winrt::WindowsUdk::UI::Shell::"
        L"NotificationAreaIcon,"
        L"enum winrt::WindowsUdk::UI::Shell::"
        L"NotificationAreaIconLocation,"
        L"unsigned int)";

    return
        symbol &&
        std::wcscmp(symbol, expected) == 0;
}

bool ResolveRequiredSymbols(HMODULE taskbarModule) {
    WH_FIND_SYMBOL_OPTIONS options{};
    options.optionsSize = sizeof(options);
    options.noUndecoratedSymbols = FALSE;

    WH_FIND_SYMBOL symbol{};

    HANDLE search =
        Wh_FindFirstSymbol(
            taskbarModule,
            &options,
            &symbol);

    if (!search) {
        return false;
    }

    do {
        if (
            !NotificationAreaIcon_QueryInterface &&
            IsNotificationAreaIconQueryInterfaceSymbol(
                symbol.symbol)) {
            NotificationAreaIcon_QueryInterface =
                reinterpret_cast<
                    NotificationAreaIcon_QueryInterface_t>(
                    symbol.address);
        }

        if (
            !g_notificationAreaIconInterfaceId &&
            IsNotificationAreaIconIidSymbol(
                symbol.symbol)) {
            g_notificationAreaIconInterfaceId =
                reinterpret_cast<const GUID*>(
                    symbol.address);
        }

        if (
            !g_notificationAreaIconVectorId &&
            IsNotificationAreaIconVectorIidSymbol(
                symbol.symbol)) {
            g_notificationAreaIconVectorId =
                reinterpret_cast<const GUID*>(
                    symbol.address);
        }

        if (
            !NotificationAreaIconManager_MoveIcon &&
            IsManagerMoveIconSymbol(
                symbol.symbol)) {
            NotificationAreaIconManager_MoveIcon =
                reinterpret_cast<
                    NotificationAreaIconManager_MoveIcon_t>(
                    symbol.address);
        }

        if (
            NotificationAreaIcon_QueryInterface &&
            g_notificationAreaIconInterfaceId &&
            g_notificationAreaIconVectorId &&
            NotificationAreaIconManager_MoveIcon) {
            break;
        }
    } while (Wh_FindNextSymbol(search, &symbol));

    Wh_FindCloseSymbol(search);

    return
        NotificationAreaIcon_QueryInterface &&
        g_notificationAreaIconInterfaceId &&
        g_notificationAreaIconVectorId &&
        NotificationAreaIconManager_MoveIcon;
}

UIOrderSnapshot CaptureUIOrderSnapshot() {
    UIOrderSnapshot snapshot;

    DWORD type = REG_NONE;
    DWORD bytes = 0;

    LONG status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            kNotifyIconSettingsPath,
            kUIOrderListValueName,
            RRF_RT_REG_BINARY,
            &type,
            nullptr,
            &bytes);

    snapshot.status = status;

    if (status != ERROR_SUCCESS) {
        return snapshot;
    }

    std::vector<BYTE> data(bytes);

    status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            kNotifyIconSettingsPath,
            kUIOrderListValueName,
            RRF_RT_REG_BINARY,
            &type,
            data.data(),
            &bytes);

    snapshot.status = status;

    if (
        status != ERROR_SUCCESS ||
        bytes % sizeof(std::uint64_t) != 0) {
        return snapshot;
    }

    snapshot.entries.resize(
        bytes / sizeof(std::uint64_t));

    if (bytes) {
        std::memcpy(
            snapshot.entries.data(),
            data.data(),
            bytes);
    }

    snapshot.valid = true;
    return snapshot;
}

std::vector<std::uint64_t> FindAddedIdentities(
    const UIOrderSnapshot& before,
    const UIOrderSnapshot& after) {
    std::vector<std::uint64_t> added;

    if (!before.valid || !after.valid) {
        return added;
    }

    for (std::uint64_t identity : after.entries) {
        if (
            std::find(
                before.entries.begin(),
                before.entries.end(),
                identity) ==
            before.entries.end()) {
            added.push_back(identity);
        }
    }

    return added;
}

unsigned long long FindOneBasedPosition(
    const UIOrderSnapshot& snapshot,
    std::uint64_t identity) {
    if (!snapshot.valid) {
        return 0;
    }

    const auto it =
        std::find(
            snapshot.entries.begin(),
            snapshot.entries.end(),
            identity);

    if (it == snapshot.entries.end()) {
        return 0;
    }

    return
        static_cast<unsigned long long>(
            std::distance(
                snapshot.entries.begin(),
                it)) +
        1;
}

std::wstring MakeTrayEntrySubkey(
    std::uint64_t identity) {
    return
        std::wstring(kNotifyIconSettingsPath) +
        L"\\" +
        std::to_wstring(identity);
}

std::wstring QueryStringValue(
    const std::wstring& subkey,
    const wchar_t* valueName) {
    DWORD type = REG_NONE;
    DWORD bytes = 0;

    LONG status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            valueName,
            RRF_RT_REG_SZ |
                RRF_RT_REG_EXPAND_SZ,
            &type,
            nullptr,
            &bytes);

    if (
        status != ERROR_SUCCESS ||
        bytes == 0) {
        return L"";
    }

    std::vector<wchar_t> buffer(
        bytes / sizeof(wchar_t) + 1,
        L'\0');

    status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            valueName,
            RRF_RT_REG_SZ |
                RRF_RT_REG_EXPAND_SZ,
            &type,
            buffer.data(),
            &bytes);

    if (status != ERROR_SUCCESS) {
        return L"";
    }

    return std::wstring(buffer.data());
}

bool QueryDwordValue(
    const std::wstring& subkey,
    const wchar_t* valueName,
    DWORD* value) {
    DWORD type = REG_NONE;
    DWORD bytes = sizeof(DWORD);
    DWORD result = 0;

    const LONG status =
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.c_str(),
            valueName,
            RRF_RT_REG_DWORD,
            &type,
            &result,
            &bytes);

    if (
        status != ERROR_SUCCESS ||
        type != REG_DWORD) {
        return false;
    }

    *value = result;
    return true;
}

std::wstring QueryExecutablePath(
    std::uint64_t identity) {
    return
        QueryStringValue(
            MakeTrayEntrySubkey(identity),
            L"ExecutablePath");
}

bool QueryIdentityUid(
    std::uint64_t identity,
    DWORD* uid) {
    return
        QueryDwordValue(
            MakeTrayEntrySubkey(identity),
            L"UID",
            uid);
}

bool IsExecutableIdentity(
    std::uint64_t identity,
    const wchar_t* executableName) {
    return
        EndsWithOrdinalIgnoreCase(
            QueryExecutablePath(identity),
            executableName);
}

int GetAnchorSlotForIdentity(
    std::uint64_t identity) {
    for (int slot = 0; slot < kAnchorCount; slot++) {
        if (
            IsExecutableIdentity(
                identity,
                kAnchorExecutableNames[slot])) {
            return slot;
        }
    }

    return kInvalidAnchorSlot;
}

bool IsTargetIdentity(std::uint64_t identity) {
    if (
        !IsExecutableIdentity(
            identity,
            kTargetExecutableName)) {
        return false;
    }

    DWORD uid = 0;

    return
        QueryIdentityUid(identity, &uid) &&
        uid == kTargetUid;
}

bool IsHelperIdentity(std::uint64_t identity) {
    return
        IsExecutableIdentity(
            identity,
            kHelperExecutableName);
}

int GetTargetPhase(std::uint64_t identity) {
    const std::wstring path =
        NormalizeSlashes(
            QueryExecutablePath(identity));

    if (
        ContainsOrdinalIgnoreCase(
            path,
            kVersion1Marker)) {
        return 1;
    }

    if (
        ContainsOrdinalIgnoreCase(
            path,
            kVersion2Marker)) {
        return 2;
    }

    return 0;
}

bool IsSameComObject(
    void* left,
    void* right) {
    if (!left || !right) {
        return false;
    }

    IUnknown* leftUnknown = nullptr;
    IUnknown* rightUnknown = nullptr;

    const HRESULT leftResult =
        reinterpret_cast<IUnknown*>(left)
            ->QueryInterface(
                IID_IUnknown,
                reinterpret_cast<void**>(
                    &leftUnknown));

    const HRESULT rightResult =
        reinterpret_cast<IUnknown*>(right)
            ->QueryInterface(
                IID_IUnknown,
                reinterpret_cast<void**>(
                    &rightUnknown));

    const bool same =
        SUCCEEDED(leftResult) &&
        SUCCEEDED(rightResult) &&
        leftUnknown &&
        rightUnknown &&
        leftUnknown == rightUnknown;

    if (leftUnknown) {
        leftUnknown->Release();
    }

    if (rightUnknown) {
        rightUnknown->Release();
    }

    return same;
}

OverflowPositions QueryOverflowPositions(
    void* targetAbi) {
    OverflowPositions positions;

    void* taskbarModel =
        g_taskbarModel6.load(
            std::memory_order_acquire);

    if (
        !taskbarModel ||
        !targetAbi ||
        !TaskbarModel_GetOverflowIcons_Original ||
        !g_notificationAreaIconVectorId) {
        return positions;
    }

    void* collectionAbi = nullptr;

    positions.getterResult =
        static_cast<HRESULT>(
            TaskbarModel_GetOverflowIcons_Original(
                taskbarModel,
                &collectionAbi));

    if (
        FAILED(positions.getterResult) ||
        !collectionAbi) {
        return positions;
    }

    void* vectorAbi = nullptr;

    positions.vectorQueryResult =
        reinterpret_cast<IUnknown*>(collectionAbi)
            ->QueryInterface(
                *g_notificationAreaIconVectorId,
                &vectorAbi);

    if (
        FAILED(positions.vectorQueryResult) ||
        !vectorAbi) {
        reinterpret_cast<IUnknown*>(
            collectionAbi)->Release();

        return positions;
    }

    void** vtable =
        *reinterpret_cast<void***>(vectorAbi);

    Vector_GetAt_t getAt =
        reinterpret_cast<Vector_GetAt_t>(
            vtable[6]);

    Vector_GetSize_t getSize =
        reinterpret_cast<Vector_GetSize_t>(
            vtable[7]);

    positions.sizeResult =
        getSize(
            vectorAbi,
            &positions.size);

    if (FAILED(positions.sizeResult)) {
        reinterpret_cast<IUnknown*>(
            vectorAbi)->Release();

        reinterpret_cast<IUnknown*>(
            collectionAbi)->Release();

        return positions;
    }

    positions.enumerated = true;

    void* anchors[kAnchorCount]{};

    for (int slot = 0; slot < kAnchorCount; slot++) {
        anchors[slot] =
            g_anchorAbis[slot].load(
                std::memory_order_acquire);
    }

    for (
        unsigned int index = 0;
        index < positions.size;
        index++) {
        void* itemAbi = nullptr;

        const HRESULT result =
            getAt(
                vectorAbi,
                index,
                &itemAbi);

        if (
            FAILED(result) ||
            !itemAbi) {
            continue;
        }

        for (int slot = 0; slot < kAnchorCount; slot++) {
            if (
                anchors[slot] &&
                !positions.anchorFound[slot] &&
                IsSameComObject(
                    itemAbi,
                    anchors[slot])) {
                positions.anchorFound[slot] = true;
                positions.anchorIndex[slot] = index;
            }
        }

        if (
            !positions.targetFound &&
            IsSameComObject(
                itemAbi,
                targetAbi)) {
            positions.targetFound = true;
            positions.targetIndex = index;
        }

        reinterpret_cast<IUnknown*>(
            itemAbi)->Release();
    }

    reinterpret_cast<IUnknown*>(
        vectorAbi)->Release();

    reinterpret_cast<IUnknown*>(
        collectionAbi)->Release();

    return positions;
}

bool GetAnchorPosition(
    const OverflowPositions& positions,
    int slot,
    unsigned int* index) {
    if (
        !IsValidAnchorSlot(slot) ||
        !positions.anchorFound[slot]) {
        return false;
    }

    *index = positions.anchorIndex[slot];
    return true;
}

bool AllAnchorsCaptured() {
    for (int slot = 0; slot < kAnchorCount; slot++) {
        if (
            !g_anchorCaptured[slot].load(
                std::memory_order_acquire)) {
            return false;
        }
    }

    return true;
}

unsigned int CalculateImmediatelyAfterIndex(
    unsigned int anchorIndex,
    unsigned int targetIndex,
    unsigned int size) {
    if (!size) {
        return 0;
    }

    unsigned int desired =
        targetIndex < anchorIndex
            ? anchorIndex
            : anchorIndex + 1;

    return std::min(
        desired,
        size - 1);
}

bool IsTargetDirectlyBetween(
    const OverflowPositions& positions,
    int precedingSlot,
    int followingSlot) {
    if (!positions.targetFound) {
        return false;
    }

    unsigned int precedingIndex = 0;
    unsigned int followingIndex = 0;

    if (
        !GetAnchorPosition(
            positions,
            precedingSlot,
            &precedingIndex) ||
        !GetAnchorPosition(
            positions,
            followingSlot,
            &followingIndex)) {
        return false;
    }

    return
        precedingIndex + 1 ==
            positions.targetIndex &&
        positions.targetIndex + 1 ==
            followingIndex;
}

bool EstablishInitialAnchorOrder(
    const OverflowPositions& positions) {
    for (int slot = 0; slot < kAnchorCount; slot++) {
        if (!positions.anchorFound[slot]) {
            return false;
        }
    }

    std::array<
        std::pair<unsigned int, int>,
        kAnchorCount>
        ordered{{
            {positions.anchorIndex[0], 0},
            {positions.anchorIndex[1], 1},
            {positions.anchorIndex[2], 2},
        }};

    std::sort(
        ordered.begin(),
        ordered.end());

    g_initialFirstAnchorSlot.store(
        ordered[0].second,
        std::memory_order_release);

    g_initialMiddleAnchorSlot.store(
        ordered[1].second,
        std::memory_order_release);

    g_initialLastAnchorSlot.store(
        ordered[2].second,
        std::memory_order_release);

    Wh_Log(
        L"RESTART_PERSISTENCE_INITIAL_ANCHOR_ORDER "
        L"firstSlot=%d middleSlot=%d lastSlot=%d "
        L"indices=%u,%u,%u",
        ordered[0].second,
        ordered[1].second,
        ordered[2].second,
        ordered[0].first,
        ordered[1].first,
        ordered[2].first);

    return true;
}

std::vector<HistoricalCandidate>
FindHistoricalCandidates(
    std::uint64_t currentIdentity,
    const std::wstring& currentNormalizedPath) {
    std::vector<HistoricalCandidate> candidates;

    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    if (!snapshot.valid) {
        return candidates;
    }

    for (
        std::size_t i = 0;
        i < snapshot.entries.size();
        i++) {
        const std::uint64_t identity =
            snapshot.entries[i];

        if (identity == currentIdentity) {
            continue;
        }

        const std::wstring path =
            QueryExecutablePath(identity);

        if (
            path.empty() ||
            !EndsWithOrdinalIgnoreCase(
                path,
                kTargetExecutableName)) {
            continue;
        }

        DWORD uid = 0;

        if (
            !QueryIdentityUid(identity, &uid) ||
            uid != kTargetUid) {
            continue;
        }

        const std::wstring normalized =
            NormalizeVersionedExecutablePath(path);

        if (normalized != currentNormalizedPath) {
            continue;
        }

        HistoricalCandidate candidate;
        candidate.identity = identity;
        candidate.executablePath = path;
        candidate.normalizedPath = normalized;
        candidate.uid = uid;
        candidate.uidValid = true;
        candidate.pathExists = FileExists(path);
        candidate.uiOrderPosition = i + 1;

        candidates.push_back(
            std::move(candidate));
    }

    return candidates;
}

void CaptureAnchorInterface(
    int slot,
    void* iconImplementation) {
    if (!IsValidAnchorSlot(slot)) {
        return;
    }

    void* abi = nullptr;

    const HRESULT result =
        static_cast<HRESULT>(
            NotificationAreaIcon_QueryInterface(
                iconImplementation,
                *g_notificationAreaIconInterfaceId,
                &abi));

    if (
        FAILED(result) ||
        !abi) {
        return;
    }

    void* expected = nullptr;

    if (
        g_anchorAbis[slot].compare_exchange_strong(
            expected,
            abi,
            std::memory_order_acq_rel)) {
        g_anchorCaptured[slot].store(
            true,
            std::memory_order_release);

        Wh_Log(
            L"RESTART_PERSISTENCE_ANCHOR_CAPTURED "
            L"slot=%d abi=%p",
            slot,
            abi);

        return;
    }

    reinterpret_cast<IUnknown*>(
        abi)->Release();
}

void HandleFirstTarget(
    void* manager,
    std::uint64_t identity,
    void* implementation) {
    ResetPersistentStateForFreshPhase1();

    if (!AllAnchorsCaptured()) {
        return;
    }

    void* targetAbi = nullptr;

    const HRESULT query =
        static_cast<HRESULT>(
            NotificationAreaIcon_QueryInterface(
                implementation,
                *g_notificationAreaIconInterfaceId,
                &targetAbi));

    if (
        FAILED(query) ||
        !targetAbi) {
        return;
    }

    g_firstTargetAbi.store(
        targetAbi,
        std::memory_order_release);

    const OverflowPositions before =
        QueryOverflowPositions(targetAbi);

    if (
        !before.enumerated ||
        !before.targetFound ||
        !EstablishInitialAnchorOrder(before)) {
        return;
    }

    const int preceding =
        g_initialFirstAnchorSlot.load(
            std::memory_order_acquire);

    const int following =
        g_initialMiddleAnchorSlot.load(
            std::memory_order_acquire);

    unsigned int precedingIndex = 0;

    if (
        !GetAnchorPosition(
            before,
            preceding,
            &precedingIndex)) {
        return;
    }

    const unsigned int desiredIndex =
        CalculateImmediatelyAfterIndex(
            precedingIndex,
            before.targetIndex,
            before.size);

    g_firstTargetIdentity.store(
        identity,
        std::memory_order_release);

    g_firstOverflowSize.store(
        before.size,
        std::memory_order_release);

    const unsigned long long moveNumber =
        g_analyzerMoveAttempts.fetch_add(
            1,
            std::memory_order_relaxed) +
        1;

    Wh_Log(
        L"RESTART_PERSISTENCE_INITIAL_MOVE_BEGIN "
        L"move=%llu pid=%lu "
        L"targetIndexBefore=%u computedTargetIndex=%u",
        moveNumber,
        GetCurrentProcessId(),
        before.targetIndex,
        desiredIndex);

    void* storage = targetAbi;

    g_internalMoveDepth++;

    NotificationAreaIconManager_MoveIcon(
        manager,
        &storage,
        kOverflowLocation,
        desiredIndex);

    g_internalMoveDepth--;

    const OverflowPositions after =
        QueryOverflowPositions(targetAbi);

    const bool relationEstablished =
        IsTargetDirectlyBetween(
            after,
            preceding,
            following);

    const bool moved =
        after.targetFound &&
        after.targetIndex != before.targetIndex;

    g_initialRelationEstablished.store(
        moved &&
            relationEstablished,
        std::memory_order_release);

    Wh_Log(
        L"RESTART_PERSISTENCE_INITIAL_MOVE_COMPLETE "
        L"move=%llu targetIndex=%u "
        L"moveObserved=%d relationEstablished=%d",
        moveNumber,
        after.targetIndex,
        moved ? 1 : 0,
        relationEstablished ? 1 : 0);

    Wh_Log(
        L"RESTART_PERSISTENCE_USER_ACTION_READY "
        L"expectedManualPrecedingSlot=%d "
        L"expectedManualFollowingSlot=%d",
        g_initialMiddleAnchorSlot.load(
            std::memory_order_acquire),
        g_initialLastAnchorSlot.load(
            std::memory_order_acquire));
}

int __cdecl
TaskbarModel_MoveNotificationAreaIcon_Hook(
    void* pThis,
    void* iconAbi,
    int location,
    unsigned int index) {
    void* tracked =
        g_firstTargetAbi.load(
            std::memory_order_acquire);

    const bool isTracked =
        tracked &&
        iconAbi &&
        IsSameComObject(
            tracked,
            iconAbi);

    const int result =
        TaskbarModel_MoveNotificationAreaIcon_Original(
            pThis,
            iconAbi,
            location,
            index);

    if (!isTracked) {
        return result;
    }

    const unsigned long long manualMove =
        g_manualTargetMoveCalls.fetch_add(
            1,
            std::memory_order_relaxed) +
        1;

    const OverflowPositions after =
        QueryOverflowPositions(tracked);

    const int preceding =
        g_initialMiddleAnchorSlot.load(
            std::memory_order_acquire);

    const int following =
        g_initialLastAnchorSlot.load(
            std::memory_order_acquire);

    const bool relation =
        SUCCEEDED(
            static_cast<HRESULT>(result)) &&
        location == kOverflowLocation &&
        IsTargetDirectlyBetween(
            after,
            preceding,
            following);

    Wh_Log(
        L"RESTART_PERSISTENCE_USER_MOVE_COMPLETE "
        L"manualMove=%llu result=0x%08X "
        L"targetIndex=%u expectedRelation=%d "
        L"analyzerMoveAttempts=%llu",
        manualMove,
        static_cast<unsigned int>(
            static_cast<HRESULT>(result)),
        after.targetIndex,
        relation ? 1 : 0,
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire));

    if (!relation) {
        return result;
    }

    g_manualPrecedingSlot.store(
        preceding,
        std::memory_order_release);

    g_manualFollowingSlot.store(
        following,
        std::memory_order_release);

    g_manualSavedTargetIndex.store(
        after.targetIndex,
        std::memory_order_release);

    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    g_manualUiOrderPosition.store(
        FindOneBasedPosition(
            snapshot,
            g_firstTargetIdentity.load(
                std::memory_order_acquire)),
        std::memory_order_release);

    g_manualRelationUpdates.fetch_add(
        1,
        std::memory_order_relaxed);

    g_manualCanonicalRelationUpdated.store(
        true,
        std::memory_order_release);

    const std::wstring normalized =
        NormalizeVersionedExecutablePath(
            QueryExecutablePath(
                g_firstTargetIdentity.load(
                    std::memory_order_acquire)));

    const bool persisted =
        PersistManualCanonicalState(
            normalized);

    Wh_Log(
        L"RESTART_PERSISTENCE_CANONICAL_SAVED "
        L"precedingSlot=%d followingSlot=%d "
        L"savedTargetIndex=%u persisted=%d",
        preceding,
        following,
        after.targetIndex,
        persisted ? 1 : 0);

    return result;
}

void LogFinalValidation(
    const HistoricalCandidate& candidate,
    const OverflowPositions& before,
    const OverflowPositions& after,
    const std::wstring& currentNormalizedPath) {
    const bool explorerChanged =
        g_loadedPersistentState.firstExplorerProcessId !=
            GetCurrentProcessId();

    const bool pathMatches =
        currentNormalizedPath ==
            g_loadedNormalizedPath;

    const bool candidateMatches =
        candidate.identity ==
            g_loadedPersistentState.firstTargetIdentity;

    const bool collectionChanged =
        g_loadedPersistentState.firstSessionOverflowSize !=
            g_secondOverflowSize.load(
                std::memory_order_acquire);

    const bool numericIndexInvalidated =
        g_loadedPersistentState.manualSavedTargetIndex !=
            g_secondMoveTargetIndex.load(
                std::memory_order_acquire);

    const bool correctRelation =
        IsTargetDirectlyBetween(
            after,
            g_loadedPersistentState.precedingSlot,
            g_loadedPersistentState.followingSlot);

    const bool oneSecondSessionMove =
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire) ==
        1;

    const bool validation =
        g_persistedStateLoadedAtInit.load(
            std::memory_order_acquire) &&
        explorerChanged &&
        pathMatches &&
        g_candidateCount.load(
            std::memory_order_acquire) ==
            1 &&
        candidateMatches &&
        !candidate.pathExists &&
        g_uniqueCandidateObserved.load(
            std::memory_order_acquire) &&
        g_uniqueCandidateSelected.load(
            std::memory_order_acquire) &&
        g_helperIdentityCount.load(
            std::memory_order_acquire) ==
            3 &&
        collectionChanged &&
        numericIndexInvalidated &&
        correctRelation &&
        g_replacementRestoredToPersistedRelation.load(
            std::memory_order_acquire) &&
        g_restoreDecisions.load(
            std::memory_order_acquire) ==
            1 &&
        oneSecondSessionMove;

    g_restartPersistenceValidationCompleted.store(
        validation,
        std::memory_order_release);

    Wh_Log(
        L"RESTART_PERSISTENCE_RESULT "
        L"persistedStateLoadedAtInit=%d "
        L"persistedExplorerPid=%lu "
        L"currentExplorerPid=%lu "
        L"explorerProcessChanged=%d "
        L"persistedFirstTargetIdentity=%llu "
        L"candidateIdentity=%llu "
        L"candidateMatchesPersistedFirst=%d "
        L"persistedPathMatchesCurrent=%d "
        L"candidateCount=%u "
        L"helperCount=%llu "
        L"persistedFirstOverflowSize=%u "
        L"secondOverflowSize=%u "
        L"collectionChanged=%d "
        L"persistedManualSavedTargetIndex=%u "
        L"secondMoveTargetIndex=%u "
        L"numericIndexInvalidated=%d "
        L"replacementBetweenPersistedAnchors=%d "
        L"replacementRestoredToPersistedRelation=%d "
        L"restoreDecisions=%llu "
        L"secondSessionAnalyzerMoveAttempts=%llu "
        L"restartPersistenceValidationCompleted=%d",
        g_persistedStateLoadedAtInit.load(
            std::memory_order_acquire)
            ? 1
            : 0,
        g_loadedPersistentState.firstExplorerProcessId,
        GetCurrentProcessId(),
        explorerChanged ? 1 : 0,
        static_cast<unsigned long long>(
            g_loadedPersistentState.firstTargetIdentity),
        static_cast<unsigned long long>(
            candidate.identity),
        candidateMatches ? 1 : 0,
        pathMatches ? 1 : 0,
        g_candidateCount.load(
            std::memory_order_acquire),
        g_helperIdentityCount.load(
            std::memory_order_acquire),
        g_loadedPersistentState.firstSessionOverflowSize,
        g_secondOverflowSize.load(
            std::memory_order_acquire),
        collectionChanged ? 1 : 0,
        g_loadedPersistentState.manualSavedTargetIndex,
        g_secondMoveTargetIndex.load(
            std::memory_order_acquire),
        numericIndexInvalidated ? 1 : 0,
        correctRelation ? 1 : 0,
        g_replacementRestoredToPersistedRelation.load(
            std::memory_order_acquire)
            ? 1
            : 0,
        g_restoreDecisions.load(
            std::memory_order_acquire),
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire),
        validation ? 1 : 0);

    if (validation) {
        Wh_DeleteValue(
            kPersistentStateValueName);

        Wh_DeleteValue(
            kPersistentPathValueName);

        Wh_Log(
            L"RESTART_PERSISTENCE_TEST_STORAGE_CLEANUP completed=1");
    }
}

void HandleReplacementTarget(
    void* manager,
    std::uint64_t identity,
    void* implementation) {
    if (
        !g_persistedStateLoadedAtInit.load(
            std::memory_order_acquire) ||
        !g_explorerProcessChanged.load(
            std::memory_order_acquire) ||
        !AllAnchorsCaptured()) {
        Wh_Log(
            L"RESTART_PERSISTENCE_REPLACEMENT_REJECTED "
            L"stateLoaded=%d explorerProcessChanged=%d anchors=%d",
            g_persistedStateLoadedAtInit.load(
                std::memory_order_acquire)
                ? 1
                : 0,
            g_explorerProcessChanged.load(
                std::memory_order_acquire)
                ? 1
                : 0,
            AllAnchorsCaptured() ? 1 : 0);

        return;
    }

    void* targetAbi = nullptr;

    const HRESULT query =
        static_cast<HRESULT>(
            NotificationAreaIcon_QueryInterface(
                implementation,
                *g_notificationAreaIconInterfaceId,
                &targetAbi));

    if (
        FAILED(query) ||
        !targetAbi) {
        return;
    }

    const OverflowPositions before =
        QueryOverflowPositions(targetAbi);

    if (
        !before.enumerated ||
        !before.targetFound) {
        reinterpret_cast<IUnknown*>(
            targetAbi)->Release();

        return;
    }

    g_secondTargetIdentity.store(
        identity,
        std::memory_order_release);

    g_secondOverflowSize.store(
        before.size,
        std::memory_order_release);

    g_secondTargetIndexBefore.store(
        before.targetIndex,
        std::memory_order_release);

    const std::wstring normalized =
        NormalizeVersionedExecutablePath(
            QueryExecutablePath(identity));

    const auto candidates =
        FindHistoricalCandidates(
            identity,
            normalized);

    g_candidateCount.store(
        static_cast<unsigned int>(
            candidates.size()),
        std::memory_order_release);

    g_restoreDecisions.fetch_add(
        1,
        std::memory_order_relaxed);

    Wh_Log(
        L"RESTART_PERSISTENCE_MATCH_SEARCH "
        L"currentIdentity=%llu candidateCount=%llu "
        L"pathMatchesPersisted=%d",
        static_cast<unsigned long long>(identity),
        static_cast<unsigned long long>(
            candidates.size()),
        normalized == g_loadedNormalizedPath
            ? 1
            : 0);

    if (candidates.size() != 1) {
        reinterpret_cast<IUnknown*>(
            targetAbi)->Release();

        return;
    }

    const HistoricalCandidate& candidate =
        candidates.front();

    g_uniqueCandidateObserved.store(
        true,
        std::memory_order_release);

    if (
        candidate.identity !=
            g_loadedPersistentState.firstTargetIdentity ||
        normalized !=
            g_loadedNormalizedPath) {
        reinterpret_cast<IUnknown*>(
            targetAbi)->Release();

        return;
    }

    g_selectedHistoricalIdentity.store(
        candidate.identity,
        std::memory_order_release);

    g_uniqueCandidateSelected.store(
        true,
        std::memory_order_release);

    Wh_Log(
        L"RESTART_PERSISTENCE_MATCH_SELECTED "
        L"historicalIdentity=%llu "
        L"precedingSlot=%d followingSlot=%d",
        static_cast<unsigned long long>(
            candidate.identity),
        g_loadedPersistentState.precedingSlot,
        g_loadedPersistentState.followingSlot);

    unsigned int precedingIndex = 0;
    unsigned int followingIndex = 0;

    const bool precedingFound =
        GetAnchorPosition(
            before,
            g_loadedPersistentState.precedingSlot,
            &precedingIndex);

    const bool followingFound =
        GetAnchorPosition(
            before,
            g_loadedPersistentState.followingSlot,
            &followingIndex);

    Wh_Log(
        L"RESTART_PERSISTENCE_LIVE_NEIGHBORS "
        L"precedingFound=%d precedingIndex=%u "
        L"followingFound=%d followingIndex=%u "
        L"targetIndex=%u overflowSize=%u",
        precedingFound ? 1 : 0,
        precedingIndex,
        followingFound ? 1 : 0,
        followingIndex,
        before.targetIndex,
        before.size);

    if (
        !precedingFound ||
        !followingFound ||
        precedingIndex >= followingIndex) {
        reinterpret_cast<IUnknown*>(
            targetAbi)->Release();

        return;
    }

    g_secondPrecedingIndexBefore.store(
        precedingIndex,
        std::memory_order_release);

    g_secondFollowingIndexBefore.store(
        followingIndex,
        std::memory_order_release);

    const unsigned int desiredIndex =
        CalculateImmediatelyAfterIndex(
            precedingIndex,
            before.targetIndex,
            before.size);

    g_secondMoveTargetIndex.store(
        desiredIndex,
        std::memory_order_release);

    const unsigned long long move =
        g_analyzerMoveAttempts.fetch_add(
            1,
            std::memory_order_relaxed) +
        1;

    Wh_Log(
        L"RESTART_PERSISTENCE_REPLACEMENT_MOVE_BEGIN "
        L"move=%llu persistedIndex=%u "
        L"computedTargetIndex=%u targetIndexBefore=%u",
        move,
        g_loadedPersistentState.manualSavedTargetIndex,
        desiredIndex,
        before.targetIndex);

    void* storage = targetAbi;

    g_internalMoveDepth++;

    NotificationAreaIconManager_MoveIcon(
        manager,
        &storage,
        kOverflowLocation,
        desiredIndex);

    g_internalMoveDepth--;

    const OverflowPositions after =
        QueryOverflowPositions(targetAbi);

    const bool relationRestored =
        IsTargetDirectlyBetween(
            after,
            g_loadedPersistentState.precedingSlot,
            g_loadedPersistentState.followingSlot);

    const bool moved =
        after.targetFound &&
        after.targetIndex !=
            before.targetIndex;

    g_secondTargetIndexAfter.store(
        after.targetIndex,
        std::memory_order_release);

    g_replacementRestoredToPersistedRelation.store(
        moved &&
            relationRestored,
        std::memory_order_release);

    const UIOrderSnapshot snapshot =
        CaptureUIOrderSnapshot();

    g_secondUiOrderPosition.store(
        FindOneBasedPosition(
            snapshot,
            identity),
        std::memory_order_release);

    Wh_Log(
        L"RESTART_PERSISTENCE_REPLACEMENT_MOVE_COMPLETE "
        L"move=%llu targetIndex=%u "
        L"moveObserved=%d relationRestored=%d",
        move,
        after.targetIndex,
        moved ? 1 : 0,
        relationRestored ? 1 : 0);

    LogFinalValidation(
        candidate,
        before,
        after,
        normalized);

    reinterpret_cast<IUnknown*>(
        targetAbi)->Release();
}

void HandleTargetIcon(
    void* manager,
    std::uint64_t identity,
    void* implementation) {
    switch (GetTargetPhase(identity)) {
        case 1:
            HandleFirstTarget(
                manager,
                identity,
                implementation);
            break;

        case 2:
            HandleReplacementTarget(
                manager,
                identity,
                implementation);
            break;
    }
}

int __cdecl
TaskbarModel_GetOverflowIcons_Hook(
    void* pThis,
    void** result) {
    const int originalResult =
        TaskbarModel_GetOverflowIcons_Original(
            pThis,
            result);

    if (
        SUCCEEDED(
            static_cast<HRESULT>(
                originalResult)) &&
        result &&
        *result) {
        g_taskbarModel6.store(
            pThis,
            std::memory_order_release);
    }

    return originalResult;
}

void __cdecl
NotificationAreaIconManager_AddIcon_Hook(
    void* pThis,
    void* data) {
    AddIconContext previous =
        std::move(g_addIconContext);

    g_addIconContext = {};
    g_addIconContext.active = true;
    g_addIconContext.before =
        CaptureUIOrderSnapshot();

    NotificationAreaIconManager_AddIcon_Original(
        pThis,
        data);

    g_addIconContext =
        std::move(previous);
}

void __cdecl
NotificationAreaIconManager_AddVisible_Hook(
    void* pThis,
    void* implementation) {
    NotificationAreaIconManager_AddVisible_Original(
        pThis,
        implementation);

    if (
        g_internalMoveDepth ||
        !g_addIconContext.active) {
        return;
    }

    const UIOrderSnapshot current =
        CaptureUIOrderSnapshot();

    const auto added =
        FindAddedIdentities(
            g_addIconContext.before,
            current);

    std::vector<std::pair<int, std::uint64_t>>
        anchors;

    std::vector<std::uint64_t> targets;
    std::vector<std::uint64_t> helpers;

    for (std::uint64_t identity : added) {
        const int slot =
            GetAnchorSlotForIdentity(identity);

        if (slot != kInvalidAnchorSlot) {
            anchors.emplace_back(
                slot,
                identity);
        }

        if (IsTargetIdentity(identity)) {
            targets.push_back(identity);
        }

        if (IsHelperIdentity(identity)) {
            helpers.push_back(identity);
        }
    }

    if (anchors.size() == 1) {
        CaptureAnchorInterface(
            anchors.front().first,
            implementation);

        return;
    }

    if (helpers.size() == 1) {
        const auto helper =
            g_helperIdentityCount.fetch_add(
                1,
                std::memory_order_relaxed) +
            1;

        Wh_Log(
            L"RESTART_PERSISTENCE_HELPER_OBSERVED "
            L"helper=%llu",
            helper);

        return;
    }

    if (targets.size() == 1) {
        HandleTargetIcon(
            pThis,
            targets.front(),
            implementation);
    }
}

bool HookTaskbarSymbols(
    HMODULE taskbarModule) {
    WindhawkUtils::SYMBOL_HOOK hooks[] = {
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
            hooks,
            ARRAYSIZE(hooks));
}

BOOL CALLBACK EnumCurrentProcessTaskbarWindowProc(
    HWND hWnd,
    LPARAM lParam) {
    DWORD processId = 0;

    if (
        !GetWindowThreadProcessId(
            hWnd,
            &processId) ||
        processId !=
            GetCurrentProcessId()) {
        return TRUE;
    }

    wchar_t className[64]{};

    if (
        GetClassNameW(
            hWnd,
            className,
            ARRAYSIZE(className)) ==
        0) {
        return TRUE;
    }

    if (
        _wcsicmp(
            className,
            L"Shell_TrayWnd") !=
        0) {
        return TRUE;
    }

    *reinterpret_cast<HWND*>(
        lParam) =
        hWnd;

    return FALSE;
}

HWND FindCurrentProcessTaskbarWindow() {
    HWND result =
        nullptr;

    EnumWindows(
        EnumCurrentProcessTaskbarWindowProc,
        reinterpret_cast<LPARAM>(
            &result));

    return result;
}

void LogRestartPersistenceTestReady() {
    Wh_Log(
        L"RESTART_PERSISTENCE_TEST_READY "
        L"processId=%lu "
        L"persistedStateLoadedAtInit=%d "
        L"explorerProcessChanged=%d "
        L"taskbarHooksInitialized=%d",
        GetCurrentProcessId(),
        g_persistedStateLoadedAtInit.load(
            std::memory_order_acquire)
            ? 1
            : 0,
        g_explorerProcessChanged.load(
            std::memory_order_acquire)
            ? 1
            : 0,
        g_taskbarHooksInitialized.load(
            std::memory_order_acquire)
            ? 1
            : 0);
}

bool TryInitializeTaskbarHooks(
    bool applyImmediately) {
    if (
        g_taskbarHooksInitialized.load(
            std::memory_order_acquire)) {
        return true;
    }

    bool expected =
        false;

    if (
        !g_taskbarHooksInitializing.compare_exchange_strong(
            expected,
            true,
            std::memory_order_acq_rel)) {
        return false;
    }

    HMODULE taskbarModule =
        GetModuleHandleW(
            L"taskbar.dll");

    if (!taskbarModule) {
        Wh_Log(
            L"RESTART_PERSISTENCE_TASKBAR_DLL_NOT_READY "
            L"processId=%lu",
            GetCurrentProcessId());

        g_taskbarHooksInitializing.store(
            false,
            std::memory_order_release);

        return false;
    }

    if (
        !ResolveRequiredSymbols(
            taskbarModule)) {
        Wh_Log(
            L"RESTART_PERSISTENCE_SYMBOL_RESOLUTION_FAILED "
            L"processId=%lu",
            GetCurrentProcessId());

        g_taskbarHooksInitializing.store(
            false,
            std::memory_order_release);

        return false;
    }

    if (
        !HookTaskbarSymbols(
            taskbarModule)) {
        Wh_Log(
            L"RESTART_PERSISTENCE_TASKBAR_HOOK_REGISTRATION_FAILED "
            L"processId=%lu",
            GetCurrentProcessId());

        g_taskbarHooksInitializing.store(
            false,
            std::memory_order_release);

        return false;
    }

    if (applyImmediately) {
        if (!Wh_ApplyHookOperations()) {
            Wh_Log(
                L"RESTART_PERSISTENCE_TASKBAR_HOOK_APPLY_FAILED "
                L"processId=%lu",
                GetCurrentProcessId());

            g_taskbarHooksInitializing.store(
                false,
                std::memory_order_release);

            return false;
        }
    }

    g_taskbarHooksInitialized.store(
        true,
        std::memory_order_release);

    g_taskbarHooksInitializing.store(
        false,
        std::memory_order_release);

    if (applyImmediately) {
        Wh_Log(
            L"RESTART_PERSISTENCE_TASKBAR_HOOKS_READY "
            L"processId=%lu applyImmediately=1",
            GetCurrentProcessId());
    } else {
        Wh_Log(
            L"RESTART_PERSISTENCE_TASKBAR_HOOKS_REGISTERED "
            L"processId=%lu applyImmediately=0",
            GetCurrentProcessId());
    }

    return true;
}

HWND WINAPI CreateWindowExW_Hook(
    DWORD dwExStyle,
    LPCWSTR lpClassName,
    LPCWSTR lpWindowName,
    DWORD dwStyle,
    int X,
    int Y,
    int nWidth,
    int nHeight,
    HWND hWndParent,
    HMENU hMenu,
    HINSTANCE hInstance,
    LPVOID lpParam) {
    HWND hWnd =
        CreateWindowExW_Original(
            dwExStyle,
            lpClassName,
            lpWindowName,
            dwStyle,
            X,
            Y,
            nWidth,
            nHeight,
            hWndParent,
            hMenu,
            hInstance,
            lpParam);

    if (!hWnd) {
        return hWnd;
    }

    const bool textualClassName =
        (
            reinterpret_cast<ULONG_PTR>(
                lpClassName) &
            ~static_cast<ULONG_PTR>(
                0xffff)
        ) !=
        0;

    if (
        !textualClassName ||
        _wcsicmp(
            lpClassName,
            L"Shell_TrayWnd") !=
            0) {
        return hWnd;
    }

    DWORD processId =
        0;

    GetWindowThreadProcessId(
        hWnd,
        &processId);

    if (
        processId !=
        GetCurrentProcessId()) {
        return hWnd;
    }

    Wh_Log(
        L"RESTART_PERSISTENCE_SHELL_WINDOW_CREATED "
        L"processId=%lu "
        L"hWnd=%p",
        processId,
        hWnd);

    if (
        !g_taskbarHooksInitialized.load(
            std::memory_order_acquire)) {
        if (
            TryInitializeTaskbarHooks(
                true)) {
            LogRestartPersistenceTestReady();
        }
    }

    return hWnd;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Add Path Analyzer 0.28.1 initializing "
        L"processId=%lu",
        GetCurrentProcessId());

    LoadPersistentStateAtInit();

    if (
        !WindhawkUtils::SetFunctionHook(
            CreateWindowExW,
            CreateWindowExW_Hook,
            &CreateWindowExW_Original)) {
        Wh_Log(
            L"RESTART_PERSISTENCE_CREATEWINDOW_HOOK_FAILED "
            L"processId=%lu",
            GetCurrentProcessId());

        return FALSE;
    }

    HWND existingTaskbarWindow =
        FindCurrentProcessTaskbarWindow();

    if (existingTaskbarWindow) {
        Wh_Log(
            L"RESTART_PERSISTENCE_EXISTING_PRIMARY_SHELL "
            L"processId=%lu "
            L"hWnd=%p",
            GetCurrentProcessId(),
            existingTaskbarWindow);

        if (
            !TryInitializeTaskbarHooks(
                false)) {
            return FALSE;
        }
    } else {
        Wh_Log(
            L"RESTART_PERSISTENCE_TASKBAR_HOOKS_DEFERRED "
            L"processId=%lu "
            L"reason=\"Shell_TrayWnd-not-created-yet\"",
            GetCurrentProcessId());
    }

    Wh_Log(
        L"RESTART_PERSISTENCE_BOOTSTRAP_READY "
        L"processId=%lu "
        L"persistedStateLoadedAtInit=%d "
        L"explorerProcessChanged=%d",
        GetCurrentProcessId(),
        g_persistedStateLoadedAtInit.load(
            std::memory_order_acquire)
            ? 1
            : 0,
        g_explorerProcessChanged.load(
            std::memory_order_acquire)
            ? 1
            : 0);

    return TRUE;
}

void Wh_ModAfterInit() {
    if (
        g_taskbarHooksInitialized.load(
            std::memory_order_acquire)) {
        LogRestartPersistenceTestReady();
    }
}

void Wh_ModUninit() {
    void* target =
        g_firstTargetAbi.exchange(
            nullptr,
            std::memory_order_acq_rel);

    if (target) {
        reinterpret_cast<IUnknown*>(
            target)->Release();
    }

    for (int slot = 0; slot < kAnchorCount; slot++) {
        void* anchor =
            g_anchorAbis[slot].exchange(
                nullptr,
                std::memory_order_acq_rel);

        if (anchor) {
            reinterpret_cast<IUnknown*>(
                anchor)->Release();
        }
    }

    Wh_Log(
        L"Tray Add Path Analyzer stopped; "
        L"processId=%lu "
        L"analyzerMoveAttempts=%llu "
        L"manualTargetMoveCalls=%llu "
        L"helperCount=%llu "
        L"candidateCount=%u "
        L"persistedStateLoadedAtInit=%d "
        L"explorerProcessChanged=%d "
        L"replacementRestoredToPersistedRelation=%d "
        L"restartPersistenceValidationCompleted=%d",
        GetCurrentProcessId(),
        g_analyzerMoveAttempts.load(
            std::memory_order_acquire),
        g_manualTargetMoveCalls.load(
            std::memory_order_acquire),
        g_helperIdentityCount.load(
            std::memory_order_acquire),
        g_candidateCount.load(
            std::memory_order_acquire),
        g_persistedStateLoadedAtInit.load(
            std::memory_order_acquire)
            ? 1
            : 0,
        g_explorerProcessChanged.load(
            std::memory_order_acquire)
            ? 1
            : 0,
        g_replacementRestoredToPersistedRelation.load(
            std::memory_order_acquire)
            ? 1
            : 0,
        g_restartPersistenceValidationCompleted.load(
            std::memory_order_acquire)
            ? 1
            : 0);
}
