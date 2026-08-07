// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Tests native saved tray-order reuse across a stable-GUID executable path change.
// @version         0.18.0
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

A temporary two-version diagnostic mod.

Version 0.18.0 tests whether Windows preserves a saved tray position when a
GUID-based icon returns from a different executable version directory while
retaining the same GUID.

The dedicated test executable is:

TrayGuidSavedOrderProbeV180.exe

The test application is run from:

- Version-1.0.0
- Version-2.0.0

Both versions use the same randomly generated GUID for one test run.

First version:

- A fresh tray registry identity is created.
- The analyzer identifies that exact identity.
- The live overflow collection size is read.
- The icon is moved exactly once through the previously validated
  NotificationAreaIconManager2::MoveIcon path.
- The resulting UIOrderList position is recorded.

Second version:

- The old Version-1.0.0 directory has been removed.
- The same GUID is used from Version-2.0.0.
- The analyzer performs no additional MoveIcon call.
- It checks whether Windows reuses the same registry identity.
- It checks whether the registry ExecutablePath changes from Version-1.0.0 to
  Version-2.0.0.
- It observes NotifyIconSettingsDatabase::GetUIOrderForIcon.
- It verifies that the saved UI order remains unchanged across the path update.

The analyzer never moves a non-test icon and performs no registry writes.
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
    L"trayguidsavedorderprobev180.exe";

constexpr wchar_t kVersion1Marker[] =
    L"\\version-1.0.0\\";

constexpr wchar_t kVersion2Marker[] =
    L"\\version-2.0.0\\";

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

using NotifyIconSettingsDatabase_GetUIOrderForIcon_t =
    unsigned int(__cdecl*)(
        void* pThis,
        std::uint64_t identity
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

NotifyIconSettingsDatabase_GetUIOrderForIcon_t
    NotifyIconSettingsDatabase_GetUIOrderForIcon_Original =
        nullptr;

const GUID* g_notificationAreaIconInterfaceId =
    nullptr;

const GUID* g_notificationAreaIconVectorId =
    nullptr;

std::atomic<void*> g_taskbarModel6 =
    nullptr;

std::atomic<unsigned long long> g_addIconCalls =
    0;

std::atomic<unsigned long long> g_visibleAddCalls =
    0;

std::atomic<unsigned long long> g_overflowGetterCalls =
    0;

std::atomic<unsigned long long> g_orderQueries =
    0;

std::atomic<unsigned long long> g_moveAttempts =
    0;

std::atomic<unsigned long long> g_targetResults =
    0;

std::atomic<std::uint64_t> g_firstTargetIdentity =
    0;

std::atomic<unsigned long long> g_savedPositionAfterMove =
    0;

std::atomic<bool> g_moveConsumed =
    false;

std::atomic<bool> g_firstMoveObserved =
    false;

std::atomic<bool> g_crossVersionValidationCompleted =
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

struct OrderQueryObservation {
    std::uint64_t identity =
        0;

    unsigned int returnedOrder =
        0;
};

struct AddIconContext {
    bool active =
        false;

    unsigned long long callNumber =
        0;

    UIOrderSnapshot before;

    std::vector<OrderQueryObservation> orderQueries;

    std::wstring targetPathBefore;
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
        L"GUID_SAVED_ORDER_SUPPORT_READY "
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

bool ContainsIdentity(
    const UIOrderSnapshot& snapshot,
    std::uint64_t identity
) {
    if (!snapshot.valid) {
        return false;
    }

    return
        std::find(
            snapshot.entries.begin(),
            snapshot.entries.end(),
            identity
        ) !=
        snapshot.entries.end();
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

bool IsTargetIdentity(
    std::uint64_t identity
) {
    const std::wstring executablePath =
        QueryExecutablePath(
            identity
        );

    return
        EndsWithOrdinalIgnoreCase(
            executablePath,
            kTargetExecutableName
        );
}

unsigned int CountObservedIdentity(
    const std::vector<OrderQueryObservation>& observations,
    std::uint64_t identity
) {
    unsigned int count =
        0;

    for (
        const OrderQueryObservation& observation :
        observations
    ) {
        if (
            observation.identity ==
            identity
        ) {
            count++;
        }
    }

    return count;
}

unsigned int CountObservedIdentityOrder(
    const std::vector<OrderQueryObservation>& observations,
    std::uint64_t identity,
    unsigned int expectedOrder
) {
    unsigned int count =
        0;

    for (
        const OrderQueryObservation& observation :
        observations
    ) {
        if (
            observation.identity ==
                identity &&
            observation.returnedOrder ==
                expectedOrder
        ) {
            count++;
        }
    }

    return count;
}

bool QueryVectorSize(
    void* collectionAbi,
    unsigned int* size,
    HRESULT* queryResult,
    HRESULT* sizeResult
) {
    if (size) {
        *size =
            0;
    }

    if (queryResult) {
        *queryResult =
            E_FAIL;
    }

    if (sizeResult) {
        *sizeResult =
            E_FAIL;
    }

    if (
        !collectionAbi ||
        !g_notificationAreaIconVectorId
    ) {
        return false;
    }

    void* vectorAbi =
        nullptr;

    const HRESULT queryHr =
        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->QueryInterface(
            *g_notificationAreaIconVectorId,
            &vectorAbi
        );

    if (queryResult) {
        *queryResult =
            queryHr;
    }

    if (
        FAILED(queryHr) ||
        !vectorAbi
    ) {
        return false;
    }

    void** vtable =
        *reinterpret_cast<void***>(
            vectorAbi
        );

    if (!vtable) {
        reinterpret_cast<IUnknown*>(
            vectorAbi
        )->Release();

        return false;
    }

    Vector_GetSize_t getSize =
        reinterpret_cast<Vector_GetSize_t>(
            vtable[7]
        );

    if (!getSize) {
        reinterpret_cast<IUnknown*>(
            vectorAbi
        )->Release();

        return false;
    }

    unsigned int vectorSize =
        0;

    const HRESULT sizeHr =
        getSize(
            vectorAbi,
            &vectorSize
        );

    if (sizeResult) {
        *sizeResult =
            sizeHr;
    }

    if (
        SUCCEEDED(sizeHr) &&
        size
    ) {
        *size =
            vectorSize;
    }

    reinterpret_cast<IUnknown*>(
        vectorAbi
    )->Release();

    return
        SUCCEEDED(sizeHr);
}

bool QueryCurrentOverflowSize(
    unsigned int* size,
    HRESULT* getterResult,
    HRESULT* vectorQueryResult,
    HRESULT* sizeResult
) {
    if (size) {
        *size =
            0;
    }

    if (getterResult) {
        *getterResult =
            E_FAIL;
    }

    if (vectorQueryResult) {
        *vectorQueryResult =
            E_FAIL;
    }

    if (sizeResult) {
        *sizeResult =
            E_FAIL;
    }

    void* taskbarModel6 =
        g_taskbarModel6.load(
            std::memory_order_acquire
        );

    if (
        !taskbarModel6 ||
        !TaskbarModel_GetOverflowIcons_Original
    ) {
        return false;
    }

    void* collectionAbi =
        nullptr;

    const HRESULT getterHr =
        static_cast<HRESULT>(
            TaskbarModel_GetOverflowIcons_Original(
                taskbarModel6,
                &collectionAbi
            )
        );

    if (getterResult) {
        *getterResult =
            getterHr;
    }

    bool success =
        false;

    if (
        SUCCEEDED(getterHr) &&
        collectionAbi
    ) {
        success =
            QueryVectorSize(
                collectionAbi,
                size,
                vectorQueryResult,
                sizeResult
            );
    }

    if (collectionAbi) {
        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->Release();
    }

    return success;
}

void AnalyzeCompletedAddIcon(
    const AddIconContext& context,
    const UIOrderSnapshot& after
) {
    const std::vector<std::uint64_t> addedIdentities =
        FindAddedIdentities(
            context.before,
            after
        );

    std::vector<std::uint64_t> targetAdded;

    for (
        std::uint64_t identity :
        addedIdentities
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

    std::uint64_t firstTargetIdentity =
        g_firstTargetIdentity.load(
            std::memory_order_acquire
        );

    if (
        targetAdded.size() ==
        1
    ) {
        const std::uint64_t targetIdentity =
            targetAdded.front();

        if (
            firstTargetIdentity ==
            0
        ) {
            std::uint64_t expected =
                0;

            g_firstTargetIdentity.compare_exchange_strong(
                expected,
                targetIdentity,
                std::memory_order_acq_rel
            );

            firstTargetIdentity =
                g_firstTargetIdentity.load(
                    std::memory_order_acquire
                );
        }

        const std::wstring pathAfter =
            QueryExecutablePath(
                targetIdentity
            );

        const unsigned long long afterPosition =
            FindOneBasedPosition(
                after,
                targetIdentity
            );

        const bool version1Path =
            ContainsOrdinalIgnoreCase(
                NormalizeSlashes(
                    pathAfter
                ),
                kVersion1Marker
            );

        g_targetResults.fetch_add(
            1,
            std::memory_order_relaxed
        );

        Wh_Log(
            L"GUID_SAVED_ORDER_FIRST_RESULT "
            L"addCall=%llu "
            L"id=%llu "
            L"afterPosition=%llu "
            L"savedPositionAfterMove=%llu "
            L"identityMatchesMove=%d "
            L"firstMoveObserved=%d "
            L"version1Path=%d "
            L"moveAttempts=%llu "
            L"path=\"%s\"",
            context.callNumber,
            static_cast<unsigned long long>(
                targetIdentity
            ),
            afterPosition,
            g_savedPositionAfterMove.load(
                std::memory_order_acquire
            ),
            firstTargetIdentity ==
                    targetIdentity
                ? 1
                : 0,
            g_firstMoveObserved.load(
                std::memory_order_acquire
            )
                ? 1
                : 0,
            version1Path
                ? 1
                : 0,
            g_moveAttempts.load(
                std::memory_order_acquire
            ),
            pathAfter.c_str()
        );

        return;
    }

    if (
        firstTargetIdentity ==
        0
    ) {
        return;
    }

    const bool identityInBefore =
        ContainsIdentity(
            context.before,
            firstTargetIdentity
        );

    const bool identityInAfter =
        ContainsIdentity(
            after,
            firstTargetIdentity
        );

    if (
        !identityInBefore ||
        !identityInAfter
    ) {
        return;
    }

    const unsigned int targetOrderQueries =
        CountObservedIdentity(
            context.orderQueries,
            firstTargetIdentity
        );

    if (
        targetOrderQueries ==
        0
    ) {
        return;
    }

    const unsigned long long beforePosition =
        FindOneBasedPosition(
            context.before,
            firstTargetIdentity
        );

    const unsigned long long afterPosition =
        FindOneBasedPosition(
            after,
            firstTargetIdentity
        );

    const unsigned long long savedPositionAfterMove =
        g_savedPositionAfterMove.load(
            std::memory_order_acquire
        );

    unsigned int expectedZeroBasedOrder =
        0;

    if (
        beforePosition >
        0
    ) {
        expectedZeroBasedOrder =
            static_cast<unsigned int>(
                beforePosition -
                1
            );
    }

    const unsigned int matchingSavedOrderQueries =
        beforePosition >
                0
            ? CountObservedIdentityOrder(
                  context.orderQueries,
                  firstTargetIdentity,
                  expectedZeroBasedOrder
              )
            : 0;

    const std::wstring pathBefore =
        context.targetPathBefore;

    const std::wstring pathAfter =
        QueryExecutablePath(
            firstTargetIdentity
        );

    const std::wstring normalizedPathBefore =
        ToLower(
            NormalizeSlashes(
                pathBefore
            )
        );

    const std::wstring normalizedPathAfter =
        ToLower(
            NormalizeSlashes(
                pathAfter
            )
        );

    const bool pathChanged =
        !normalizedPathBefore.empty() &&
        !normalizedPathAfter.empty() &&
        normalizedPathBefore !=
            normalizedPathAfter;

    const bool beforeVersion1 =
        ContainsOrdinalIgnoreCase(
            normalizedPathBefore,
            kVersion1Marker
        );

    const bool afterVersion2 =
        ContainsOrdinalIgnoreCase(
            normalizedPathAfter,
            kVersion2Marker
        );

    const bool positionMatchesSaved =
        savedPositionAfterMove !=
            0 &&
        beforePosition ==
            savedPositionAfterMove &&
        afterPosition ==
            savedPositionAfterMove;

    const bool positionPreserved =
        beforePosition !=
            0 &&
        beforePosition ==
            afterPosition;

    const bool savedOrderQueried =
        matchingSavedOrderQueries >
        0;

    const bool firstMoveObserved =
        g_firstMoveObserved.load(
            std::memory_order_acquire
        );

    const bool onlyOneAnalyzerMove =
        g_moveAttempts.load(
            std::memory_order_acquire
        ) ==
        1;

    const bool crossVersionSavedOrderReused =
        firstMoveObserved &&
        onlyOneAnalyzerMove &&
        positionMatchesSaved &&
        positionPreserved &&
        savedOrderQueried &&
        pathChanged &&
        beforeVersion1 &&
        afterVersion2 &&
        targetAdded.empty();

    g_crossVersionValidationCompleted.store(
        crossVersionSavedOrderReused,
        std::memory_order_release
    );

    g_targetResults.fetch_add(
        1,
        std::memory_order_relaxed
    );

    Wh_Log(
        L"GUID_SAVED_ORDER_RETURN_RESULT "
        L"addCall=%llu "
        L"id=%llu "
        L"savedPositionAfterMove=%llu "
        L"beforePosition=%llu "
        L"afterPosition=%llu "
        L"beforeCount=%llu "
        L"afterCount=%llu "
        L"expectedZeroBasedOrder=%u "
        L"targetOrderQueries=%u "
        L"matchingSavedOrderQueries=%u "
        L"pathChanged=%d "
        L"beforeVersion1=%d "
        L"afterVersion2=%d "
        L"positionMatchesSaved=%d "
        L"positionPreserved=%d "
        L"savedOrderQueried=%d "
        L"firstMoveObserved=%d "
        L"onlyOneAnalyzerMove=%d "
        L"crossVersionSavedOrderReused=%d "
        L"pathBefore=\"%s\" "
        L"pathAfter=\"%s\"",
        context.callNumber,
        static_cast<unsigned long long>(
            firstTargetIdentity
        ),
        savedPositionAfterMove,
        beforePosition,
        afterPosition,
        static_cast<unsigned long long>(
            context.before.entries.size()
        ),
        static_cast<unsigned long long>(
            after.entries.size()
        ),
        expectedZeroBasedOrder,
        targetOrderQueries,
        matchingSavedOrderQueries,
        pathChanged
            ? 1
            : 0,
        beforeVersion1
            ? 1
            : 0,
        afterVersion2
            ? 1
            : 0,
        positionMatchesSaved
            ? 1
            : 0,
        positionPreserved
            ? 1
            : 0,
        savedOrderQueried
            ? 1
            : 0,
        firstMoveObserved
            ? 1
            : 0,
        onlyOneAnalyzerMove
            ? 1
            : 0,
        crossVersionSavedOrderReused
            ? 1
            : 0,
        pathBefore.c_str(),
        pathAfter.c_str()
    );

    Wh_Log(
        L"GUID_SAVED_ORDER_SUMMARY "
        L"firstIdentity=%llu "
        L"savedPositionAfterMove=%llu "
        L"moveAttempts=%llu "
        L"targetResults=%llu "
        L"crossVersionValidationCompleted=%d",
        static_cast<unsigned long long>(
            firstTargetIdentity
        ),
        savedPositionAfterMove,
        g_moveAttempts.load(
            std::memory_order_acquire
        ),
        g_targetResults.load(
            std::memory_order_acquire
        ),
        g_crossVersionValidationCompleted.load(
            std::memory_order_acquire
        )
            ? 1
            : 0
    );
}

unsigned int __cdecl
NotifyIconSettingsDatabase_GetUIOrderForIcon_Hook(
    void* pThis,
    std::uint64_t identity
) {
    const unsigned int returnedOrder =
        NotifyIconSettingsDatabase_GetUIOrderForIcon_Original(
            pThis,
            identity
        );

    const unsigned long long queryNumber =
        g_orderQueries.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    if (
        g_addIconContext.active
    ) {
        g_addIconContext.orderQueries.push_back(
            {
                identity,
                returnedOrder
            }
        );
    }

    Wh_Log(
        L"UI_ORDER_QUERY "
        L"query=%llu "
        L"identity=%llu "
        L"returnedOrder=%u "
        L"duringAddIcon=%d "
        L"parentAddCall=%llu",
        queryNumber,
        static_cast<unsigned long long>(
            identity
        ),
        returnedOrder,
        g_addIconContext.active
            ? 1
            : 0,
        g_addIconContext.active
            ? g_addIconContext.callNumber
            : 0
    );

    return returnedOrder;
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

    const HRESULT getterHr =
        static_cast<HRESULT>(
            originalResult
        );

    unsigned int size =
        0;

    HRESULT vectorQueryResult =
        E_FAIL;

    HRESULT sizeResult =
        E_FAIL;

    bool sizeValid =
        false;

    if (
        SUCCEEDED(getterHr) &&
        result &&
        *result
    ) {
        g_taskbarModel6.store(
            pThis,
            std::memory_order_release
        );

        sizeValid =
            QueryVectorSize(
                *result,
                &size,
                &vectorQueryResult,
                &sizeResult
            );
    }

    Wh_Log(
        L"OVERFLOW_GETTER "
        L"call=%llu "
        L"pThis=%p "
        L"result=0x%08X "
        L"collection=%p "
        L"sizeValid=%d "
        L"size=%u "
        L"vectorQueryResult=0x%08X "
        L"sizeResult=0x%08X",
        callNumber,
        pThis,
        static_cast<unsigned int>(
            getterHr
        ),
        result
            ? *result
            : nullptr,
        sizeValid
            ? 1
            : 0,
        size,
        static_cast<unsigned int>(
            vectorQueryResult
        ),
        static_cast<unsigned int>(
            sizeResult
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

    const std::uint64_t firstTargetIdentity =
        g_firstTargetIdentity.load(
            std::memory_order_acquire
        );

    if (
        firstTargetIdentity !=
        0
    ) {
        g_addIconContext.targetPathBefore =
            QueryExecutablePath(
                firstTargetIdentity
            );
    }

    Wh_Log(
        L"ADD_ICON_BEGIN "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p "
        L"trayNotifyData=%p "
        L"beforeValid=%d "
        L"beforeStatus=%ld "
        L"beforeCount=%llu "
        L"trackedIdentity=%llu "
        L"trackedPathBefore=\"%s\"",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        trayNotifyData,
        g_addIconContext.before.valid
            ? 1
            : 0,
        g_addIconContext.before.status,
        static_cast<unsigned long long>(
            g_addIconContext.before.entries.size()
        ),
        static_cast<unsigned long long>(
            firstTargetIdentity
        ),
        g_addIconContext.targetPathBefore.c_str()
    );

    NotificationAreaIconManager_AddIcon_Original(
        pThis,
        trayNotifyData
    );

    const UIOrderSnapshot after =
        CaptureUIOrderSnapshot();

    AnalyzeCompletedAddIcon(
        g_addIconContext,
        after
    );

    Wh_Log(
        L"ADD_ICON_END "
        L"call=%llu "
        L"afterValid=%d "
        L"afterStatus=%ld "
        L"afterCount=%llu "
        L"orderQueriesDuringCall=%llu",
        callNumber,
        after.valid
            ? 1
            : 0,
        after.status,
        static_cast<unsigned long long>(
            after.entries.size()
        ),
        static_cast<unsigned long long>(
            g_addIconContext.orderQueries.size()
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

    Wh_Log(
        L"VISIBLE_ADD_BEGIN "
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

    NotificationAreaIconManager_AddVisible_Original(
        pThis,
        iconImplementation
    );

    if (
        g_internalMoveDepth !=
        0
    ) {
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

    if (
        !g_addIconContext.active
    ) {
        return;
    }

    const UIOrderSnapshot beforeMove =
        CaptureUIOrderSnapshot();

    const std::vector<std::uint64_t> addedIdentities =
        FindAddedIdentities(
            g_addIconContext.before,
            beforeMove
        );

    std::vector<std::uint64_t> targetAdded;

    for (
        std::uint64_t identity :
        addedIdentities
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
        L"beforeValid=%d "
        L"currentValid=%d "
        L"beforeCount=%llu "
        L"currentCount=%llu "
        L"addedCount=%llu "
        L"targetAddedCount=%llu",
        callNumber,
        g_addIconContext.callNumber,
        g_addIconContext.before.valid
            ? 1
            : 0,
        beforeMove.valid
            ? 1
            : 0,
        static_cast<unsigned long long>(
            g_addIconContext.before.entries.size()
        ),
        static_cast<unsigned long long>(
            beforeMove.entries.size()
        ),
        static_cast<unsigned long long>(
            addedIdentities.size()
        ),
        static_cast<unsigned long long>(
            targetAdded.size()
        )
    );

    if (
        targetAdded.size() !=
        1
    ) {
        return;
    }

    const std::uint64_t targetIdentity =
        targetAdded.front();

    void* queriedAbi =
        nullptr;

    const HRESULT iconQueryResult =
        static_cast<HRESULT>(
            NotificationAreaIcon_QueryInterface(
                iconImplementation,
                *g_notificationAreaIconInterfaceId,
                &queriedAbi
            )
        );

    Wh_Log(
        L"TARGET_ICON_QUERY "
        L"call=%llu "
        L"id=%llu "
        L"implementation=%p "
        L"result=0x%08X "
        L"queriedAbi=%p",
        callNumber,
        static_cast<unsigned long long>(
            targetIdentity
        ),
        iconImplementation,
        static_cast<unsigned int>(
            iconQueryResult
        ),
        queriedAbi
    );

    if (
        FAILED(iconQueryResult) ||
        !queriedAbi
    ) {
        return;
    }

    unsigned int overflowSize =
        0;

    HRESULT getterResult =
        E_FAIL;

    HRESULT vectorQueryResult =
        E_FAIL;

    HRESULT sizeResult =
        E_FAIL;

    const bool overflowSizeValid =
        QueryCurrentOverflowSize(
            &overflowSize,
            &getterResult,
            &vectorQueryResult,
            &sizeResult
        );

    Wh_Log(
        L"TARGET_OVERFLOW_SIZE "
        L"call=%llu "
        L"id=%llu "
        L"valid=%d "
        L"size=%u "
        L"getterResult=0x%08X "
        L"vectorQueryResult=0x%08X "
        L"sizeResult=0x%08X",
        callNumber,
        static_cast<unsigned long long>(
            targetIdentity
        ),
        overflowSizeValid
            ? 1
            : 0,
        overflowSize,
        static_cast<unsigned int>(
            getterResult
        ),
        static_cast<unsigned int>(
            vectorQueryResult
        ),
        static_cast<unsigned int>(
            sizeResult
        )
    );

    if (
        !overflowSizeValid ||
        overflowSize ==
            0
    ) {
        reinterpret_cast<IUnknown*>(
            queriedAbi
        )->Release();

        return;
    }

    bool expected =
        false;

    if (
        !g_moveConsumed.compare_exchange_strong(
            expected,
            true,
            std::memory_order_acq_rel
        )
    ) {
        reinterpret_cast<IUnknown*>(
            queriedAbi
        )->Release();

        return;
    }

    const unsigned int targetIndex =
        overflowSize -
        1;

    const unsigned long long beforePosition =
        FindOneBasedPosition(
            beforeMove,
            targetIdentity
        );

    std::uint64_t expectedIdentity =
        0;

    g_firstTargetIdentity.compare_exchange_strong(
        expectedIdentity,
        targetIdentity,
        std::memory_order_acq_rel
    );

    const unsigned long long moveNumber =
        g_moveAttempts.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    void* iconArgumentStorage =
        queriedAbi;

    Wh_Log(
        L"GUID_SINGLE_MOVE_BEGIN "
        L"move=%llu "
        L"call=%llu "
        L"parentAddCall=%llu "
        L"id=%llu "
        L"beforePosition=%llu "
        L"overflowSize=%u "
        L"location=%d "
        L"targetIndex=%u",
        moveNumber,
        callNumber,
        g_addIconContext.callNumber,
        static_cast<unsigned long long>(
            targetIdentity
        ),
        beforePosition,
        overflowSize,
        kOverflowLocation,
        targetIndex
    );

    g_internalMoveDepth++;

    NotificationAreaIconManager_MoveIcon(
        pThis,
        &iconArgumentStorage,
        kOverflowLocation,
        targetIndex
    );

    g_internalMoveDepth--;

    const UIOrderSnapshot afterMove =
        CaptureUIOrderSnapshot();

    const unsigned long long afterPosition =
        FindOneBasedPosition(
            afterMove,
            targetIdentity
        );

    const bool orderChanged =
        beforeMove.valid &&
        afterMove.valid &&
        beforeMove.entries !=
            afterMove.entries;

    const bool positionChanged =
        beforePosition !=
            0 &&
        afterPosition !=
            0 &&
        beforePosition !=
            afterPosition;

    const bool moveObserved =
        orderChanged &&
        positionChanged;

    if (
        afterPosition !=
        0
    ) {
        g_savedPositionAfterMove.store(
            afterPosition,
            std::memory_order_release
        );
    }

    g_firstMoveObserved.store(
        moveObserved,
        std::memory_order_release
    );

    Wh_Log(
        L"GUID_SINGLE_MOVE_COMPLETE "
        L"move=%llu "
        L"call=%llu "
        L"id=%llu "
        L"afterSnapshotValid=%d "
        L"afterStatus=%ld "
        L"afterCount=%llu "
        L"beforePosition=%llu "
        L"afterPosition=%llu "
        L"orderChanged=%d "
        L"positionChanged=%d "
        L"moveObserved=%d",
        moveNumber,
        callNumber,
        static_cast<unsigned long long>(
            targetIdentity
        ),
        afterMove.valid
            ? 1
            : 0,
        afterMove.status,
        static_cast<unsigned long long>(
            afterMove.entries.size()
        ),
        beforePosition,
        afterPosition,
        orderChanged
            ? 1
            : 0,
        positionChanged
            ? 1
            : 0,
        moveObserved
            ? 1
            : 0
    );

    reinterpret_cast<IUnknown*>(
        queriedAbi
    )->Release();
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
                LR"(public: unsigned int __cdecl NotifyIconSettingsDatabase::GetUIOrderForIcon(unsigned __int64))"
            },
            &NotifyIconSettingsDatabase_GetUIOrderForIcon_Original,
            NotifyIconSettingsDatabase_GetUIOrderForIcon_Hook,
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
        L"0.18.0 initializing"
    );

    if (
        !IsPrimaryShellProcess()
    ) {
        Wh_Log(
            L"GUID_SAVED_ORDER_TEST_SKIPPED "
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

    if (
        !HookTaskbarSymbols(
            taskbarModule
        )
    ) {
        return FALSE;
    }

    Wh_Log(
        L"GUID_SAVED_ORDER_TEST_READY "
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
        L"orderQueries=%llu "
        L"moveAttempts=%llu "
        L"firstIdentity=%llu "
        L"savedPositionAfterMove=%llu "
        L"firstMoveObserved=%d "
        L"crossVersionValidationCompleted=%d",
        g_addIconCalls.load(
            std::memory_order_acquire
        ),
        g_visibleAddCalls.load(
            std::memory_order_acquire
        ),
        g_overflowGetterCalls.load(
            std::memory_order_acquire
        ),
        g_orderQueries.load(
            std::memory_order_acquire
        ),
        g_moveAttempts.load(
            std::memory_order_acquire
        ),
        static_cast<unsigned long long>(
            g_firstTargetIdentity.load(
                std::memory_order_acquire
            )
        ),
        g_savedPositionAfterMove.load(
            std::memory_order_acquire
        ),
        g_firstMoveObserved.load(
            std::memory_order_acquire
        )
            ? 1
            : 0,
        g_crossVersionValidationCompleted.load(
            std::memory_order_acquire
        )
            ? 1
            : 0
    );
}
