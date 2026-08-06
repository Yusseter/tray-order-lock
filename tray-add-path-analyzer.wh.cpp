// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Tests dynamic automatic movement of a new tray icon to the final position.
// @version         0.5.0
// @author          Yusseter
// @github          https://github.com/Yusseter
// @homepage        https://github.com/Yusseter/tray-order-lock
// @license         MIT
// @include         explorer.exe
// @architecture    x86-64
// @compilerOptions -ladvapi32
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# Tray Add Path Analyzer

A temporary one-shot diagnostic mod.

Version 0.5.0 moves a dedicated newly added test icon to the actual final tray
position without using a fixed target index.

It repeatedly uses the verified `NotificationAreaIconManager2::MoveIcon` path
with valid consecutive indexes. After every move, it reads `UIOrderList` and
stops as soon as the test icon reaches the final persistent position.

The test applies only to an executable named:

`TrayDynamicEndTest.exe`

The mod prevents recursive processing of visible-collection updates triggered
by its own moves.
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
    L"traydynamicendtest.exe";

constexpr int kOverflowLocation =
    1;

constexpr unsigned int kMaximumMoveSteps =
    128;

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

NotificationAreaIconManager_AddVisible_t
    NotificationAreaIconManager_AddVisible_Original =
        nullptr;

NotificationAreaIconManager_MoveIcon_t
    NotificationAreaIconManager_MoveIcon =
        nullptr;

NotificationAreaIcon_QueryInterface_t
    NotificationAreaIcon_QueryInterface =
        nullptr;

const GUID* g_notificationAreaIconInterfaceId =
    nullptr;

std::atomic<unsigned long long> g_visibleAddCallCount =
    0;

std::atomic<unsigned long long> g_moveStepCount =
    0;

std::atomic<bool> g_testConsumed =
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
                reinterpret_cast<
                    const GUID*
                >(
                    symbol.address
                );

            Wh_Log(
                L"INTERFACE_ID_SYMBOL "
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
            L"INotificationAreaIcon IID symbol not found"
        );

        return false;
    }

    if (!NotificationAreaIconManager_MoveIcon) {
        Wh_Log(
            L"NotificationAreaIconManager2::MoveIcon "
            L"symbol not found"
        );

        return false;
    }

    Wh_Log(
        L"DYNAMIC_END_SUPPORT_READY "
        L"queryFunction=%p "
        L"interfaceId=%p "
        L"moveFunction=%p",
        NotificationAreaIcon_QueryInterface,
        g_notificationAreaIconInterfaceId,
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

        if (status != ERROR_SUCCESS) {
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

        if (status == ERROR_MORE_DATA) {
            continue;
        }

        snapshot.status =
            status;

        if (status != ERROR_SUCCESS) {
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

        if (actualBytes != 0) {
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
        status != ERROR_SUCCESS ||
        requiredBytes == 0
    ) {
        return L"";
    }

    std::vector<wchar_t> buffer(
        requiredBytes /
            sizeof(wchar_t) +
        1
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

    if (status != ERROR_SUCCESS) {
        return L"";
    }

    buffer.back() =
        L'\0';

    return
        std::wstring(
            buffer.data()
        );
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
                    suffix[index]
                )
            );

        if (left != right) {
            return false;
        }
    }

    return true;
}

unsigned long long FindOneBasedPosition(
    const UIOrderSnapshot& snapshot,
    std::uint64_t identity
) {
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

void TryDynamicEndMove(
    void* manager,
    void* iconImplementation,
    unsigned long long visibleAddCall
) {
    UIOrderSnapshot currentSnapshot =
        CaptureUIOrderSnapshot();

    if (
        !currentSnapshot.valid ||
        currentSnapshot.entries.empty()
    ) {
        Wh_Log(
            L"DYNAMIC_END_SKIPPED "
            L"reason=invalid-order-snapshot "
            L"visibleAddCall=%llu "
            L"status=%ld",
            visibleAddCall,
            currentSnapshot.status
        );

        return;
    }

    const std::uint64_t candidateIdentity =
        currentSnapshot.entries.front();

    const std::wstring executablePath =
        QueryStringValue(
            MakeTrayEntrySubkey(
                candidateIdentity
            ),
            L"ExecutablePath"
        );

    if (
        !EndsWithOrdinalIgnoreCase(
            executablePath,
            kTargetExecutableName
        )
    ) {
        Wh_Log(
            L"VISIBLE_ADD_IGNORED "
            L"call=%llu "
            L"id=%llu "
            L"path=\"%s\"",
            visibleAddCall,
            static_cast<unsigned long long>(
                candidateIdentity
            ),
            executablePath.c_str()
        );

        return;
    }

    bool expected =
        false;

    if (
        !g_testConsumed.compare_exchange_strong(
            expected,
            true,
            std::memory_order_acq_rel
        )
    ) {
        Wh_Log(
            L"DYNAMIC_END_SKIPPED "
            L"reason=test-already-consumed "
            L"visibleAddCall=%llu",
            visibleAddCall
        );

        return;
    }

    void* queriedAbi =
        nullptr;

    const int queryResult =
        NotificationAreaIcon_QueryInterface(
            iconImplementation,
            *g_notificationAreaIconInterfaceId,
            &queriedAbi
        );

    Wh_Log(
        L"DYNAMIC_END_QUERY "
        L"visibleAddCall=%llu "
        L"implementation=%p "
        L"result=0x%08X "
        L"queriedAbi=%p",
        visibleAddCall,
        iconImplementation,
        static_cast<unsigned int>(
            queryResult
        ),
        queriedAbi
    );

    if (
        FAILED(queryResult) ||
        !queriedAbi
    ) {
        return;
    }

    void* iconArgumentStorage =
        queriedAbi;

    unsigned int completedSteps =
        0;

    bool reachedEnd =
        false;

    const unsigned long long initialPosition =
        FindOneBasedPosition(
            currentSnapshot,
            candidateIdentity
        );

    Wh_Log(
        L"DYNAMIC_END_BEGIN "
        L"visibleAddCall=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"implementation=%p "
        L"iconAbi=%p "
        L"id=%llu "
        L"initialPosition=%llu "
        L"entryCount=%llu",
        visibleAddCall,
        GetCurrentThreadId(),
        manager,
        iconImplementation,
        queriedAbi,
        static_cast<unsigned long long>(
            candidateIdentity
        ),
        initialPosition,
        static_cast<unsigned long long>(
            currentSnapshot.entries.size()
        )
    );

    if (
        initialPosition ==
        currentSnapshot.entries.size()
    ) {
        reachedEnd =
            true;
    }

    for (
        unsigned int targetIndex = 1;
        !reachedEnd &&
        targetIndex <= kMaximumMoveSteps;
        targetIndex++
    ) {
        const unsigned long long beforePosition =
            FindOneBasedPosition(
                currentSnapshot,
                candidateIdentity
            );

        const unsigned long long beforeCount =
            static_cast<unsigned long long>(
                currentSnapshot.entries.size()
            );

        g_internalMoveDepth++;

        NotificationAreaIconManager_MoveIcon(
            manager,
            &iconArgumentStorage,
            kOverflowLocation,
            targetIndex
        );

        g_internalMoveDepth--;

        completedSteps++;

        g_moveStepCount.fetch_add(
            1,
            std::memory_order_relaxed
        );

        UIOrderSnapshot afterSnapshot =
            CaptureUIOrderSnapshot();

        const unsigned long long afterPosition =
            afterSnapshot.valid
                ? FindOneBasedPosition(
                      afterSnapshot,
                      candidateIdentity
                  )
                : 0;

        const unsigned long long afterCount =
            afterSnapshot.valid
                ? static_cast<unsigned long long>(
                      afterSnapshot.entries.size()
                  )
                : 0;

        const bool orderChanged =
            currentSnapshot.valid &&
            afterSnapshot.valid &&
            currentSnapshot.entries !=
                afterSnapshot.entries;

        Wh_Log(
            L"DYNAMIC_END_STEP "
            L"step=%u "
            L"targetIndex=%u "
            L"beforePosition=%llu "
            L"beforeCount=%llu "
            L"afterSnapshotValid=%d "
            L"afterStatus=%ld "
            L"afterPosition=%llu "
            L"afterCount=%llu "
            L"orderChanged=%d",
            completedSteps,
            targetIndex,
            beforePosition,
            beforeCount,
            afterSnapshot.valid
                ? 1
                : 0,
            afterSnapshot.status,
            afterPosition,
            afterCount,
            orderChanged
                ? 1
                : 0
        );

        if (!afterSnapshot.valid) {
            break;
        }

        if (
            afterPosition != 0 &&
            afterPosition ==
                afterSnapshot.entries.size()
        ) {
            reachedEnd =
                true;

            currentSnapshot =
                std::move(
                    afterSnapshot
                );

            break;
        }

        if (
            !orderChanged ||
            afterPosition == 0 ||
            afterPosition <= beforePosition
        ) {
            currentSnapshot =
                std::move(
                    afterSnapshot
                );

            break;
        }

        currentSnapshot =
            std::move(
                afterSnapshot
            );
    }

    const unsigned long long finalPosition =
        currentSnapshot.valid
            ? FindOneBasedPosition(
                  currentSnapshot,
                  candidateIdentity
              )
            : 0;

    Wh_Log(
        L"DYNAMIC_END_COMPLETE "
        L"visibleAddCall=%llu "
        L"id=%llu "
        L"completedSteps=%u "
        L"reachedEnd=%d "
        L"finalSnapshotValid=%d "
        L"finalStatus=%ld "
        L"finalPosition=%llu "
        L"finalCount=%llu",
        visibleAddCall,
        static_cast<unsigned long long>(
            candidateIdentity
        ),
        completedSteps,
        reachedEnd
            ? 1
            : 0,
        currentSnapshot.valid
            ? 1
            : 0,
        currentSnapshot.status,
        finalPosition,
        static_cast<unsigned long long>(
            currentSnapshot.entries.size()
        )
    );

    reinterpret_cast<IUnknown*>(
        queriedAbi
    )->Release();
}

void __cdecl
NotificationAreaIconManager_AddVisible_Hook(
    void* pThis,
    void* iconImplementation
) {
    const unsigned long long callNumber =
        g_visibleAddCallCount.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    Wh_Log(
        L"VISIBLE_ADD_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"implementation=%p "
        L"internalMoveDepth=%u",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        iconImplementation,
        g_internalMoveDepth
    );

    NotificationAreaIconManager_AddVisible_Original(
        pThis,
        iconImplementation
    );

    if (g_internalMoveDepth != 0) {
        Wh_Log(
            L"VISIBLE_ADD_INTERNAL_MOVE "
            L"call=%llu "
            L"thread=%lu "
            L"manager=%p "
            L"implementation=%p "
            L"internalMoveDepth=%u",
            callNumber,
            GetCurrentThreadId(),
            pThis,
            iconImplementation,
            g_internalMoveDepth
        );

        return;
    }

    TryDynamicEndMove(
        pThis,
        iconImplementation,
        callNumber
    );

    Wh_Log(
        L"VISIBLE_ADD_END "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"implementation=%p",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        iconImplementation
    );
}

bool HookTaskbarSymbols(
    HMODULE taskbarModule
) {
    WindhawkUtils::SYMBOL_HOOK symbolHooks[] = {
        {
            {
                LR"(private: void __cdecl NotificationAreaIconManager2::AddIconToVisibleCollection(struct winrt::WindowsUdk::UI::Shell::implementation::NotificationAreaIcon2 *))"
            },
            &NotificationAreaIconManager_AddVisible_Original,
            NotificationAreaIconManager_AddVisible_Hook,
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
            L"Failed to hook "
            L"AddIconToVisibleCollection"
        );

        return false;
    }

    Wh_Log(
        L"Dynamic end-move hook installed"
    );

    return true;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Add Path Analyzer "
        L"0.5.0 initializing"
    );

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

    wchar_t modulePath[
        32768
    ]{};

    GetModuleFileNameW(
        taskbarModule,
        modulePath,
        ARRAYSIZE(
            modulePath
        )
    );

    Wh_Log(
        L"TASKBAR_MODULE "
        L"address=%p "
        L"path=\"%s\"",
        taskbarModule,
        modulePath
    );

    if (
        !ResolveRequiredSymbols(
            taskbarModule
        )
    ) {
        return FALSE;
    }

    return
        HookTaskbarSymbols(
            taskbarModule
        )
            ? TRUE
            : FALSE;
}

void Wh_ModUninit() {
    Wh_Log(
        L"Tray Add Path Analyzer stopped; "
        L"visibleAddCalls=%llu "
        L"moveSteps=%llu "
        L"testConsumed=%d",
        g_visibleAddCallCount.load(
            std::memory_order_relaxed
        ),
        g_moveStepCount.load(
            std::memory_order_relaxed
        ),
        g_testConsumed.load(
            std::memory_order_relaxed
        )
            ? 1
            : 0
    );
}
