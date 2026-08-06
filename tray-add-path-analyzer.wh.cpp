// ==WindhawkMod==
// @id              tray-add-path-analyzer
// @name            Tray Add Path Analyzer
// @description     Correlates new tray identities with the live overflow collection size.
// @version         0.6.0
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

A temporary read-only diagnostic mod.

Version 0.6.0 performs no tray movement.

It:

- Captures the TaskbarModel6 ABI object through
  `get_NotificationAreaOverflowIcons`.
- Reads the current overflow collection size through
  `IVector<NotificationAreaIcon>`.
- Captures UIOrderList before `AddIcon`.
- During `AddIconToVisibleCollection`, identifies the exact registry identity
  added by the active AddIcon call.
- Correlates the dedicated test icon with the live overflow size.

The result will provide the valid final zero-based index for a later single
MoveIcon call without repeating synchronous moves.
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
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr wchar_t kNotifyIconSettingsPath[] =
    L"Control Panel\\NotifyIconSettings";

constexpr wchar_t kUIOrderListValueName[] =
    L"UIOrderList";

constexpr wchar_t kTargetExecutableName[] =
    L"traycollectioncounttest.exe";

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

using TaskbarModel_GetOverflowIcons_t =
    int(__cdecl*)(
        void* pThis,
        void** result
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

TaskbarModel_GetOverflowIcons_t
    TaskbarModel_GetOverflowIcons_Original =
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

std::atomic<unsigned long long> g_targetObservations =
    0;

std::atomic<bool> g_testConsumed =
    false;

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

thread_local AddIconContext g_addIconContext;

bool IsVectorInterfaceIdSymbol(
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
            !g_notificationAreaIconVectorId &&
            IsVectorInterfaceIdSymbol(
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

    if (!g_notificationAreaIconVectorId) {
        Wh_Log(
            L"IVector<NotificationAreaIcon> "
            L"IID symbol not found"
        );

        return false;
    }

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

    void*** objectPointer =
        reinterpret_cast<void***>(
            vectorAbi
        );

    void** vtable =
        objectPointer
            ? *objectPointer
            : nullptr;

    if (!vtable) {
        reinterpret_cast<IUnknown*>(
            vectorAbi
        )->Release();

        return false;
    }

    // IUnknown: 0-2
    // IInspectable: 3-5
    // IVector::GetAt: 6
    // IVector::get_Size: 7
    Vector_GetSize_t getSize =
        reinterpret_cast<Vector_GetSize_t>(
            vtable[7]
        );

    unsigned int localSize =
        0;

    const HRESULT sizeHr =
        getSize(
            vectorAbi,
            &localSize
        );

    if (sizeResult) {
        *sizeResult =
            sizeHr;
    }

    reinterpret_cast<IUnknown*>(
        vectorAbi
    )->Release();

    if (FAILED(sizeHr)) {
        return false;
    }

    if (size) {
        *size =
            localSize;
    }

    return true;
}

void CacheTaskbarModel6(
    void* taskbarModel6
) {
    if (!taskbarModel6) {
        return;
    }

    reinterpret_cast<IUnknown*>(
        taskbarModel6
    )->AddRef();

    void* previous =
        g_taskbarModel6.exchange(
            taskbarModel6,
            std::memory_order_acq_rel
        );

    if (previous) {
        reinterpret_cast<IUnknown*>(
            previous
        )->Release();
    }
}

bool ReadCurrentOverflowSize(
    unsigned int* size,
    HRESULT* getterResult,
    HRESULT* queryResult,
    HRESULT* sizeResult
) {
    if (size) {
        *size =
            0;
    }

    if (getterResult) {
        *getterResult =
            HRESULT_FROM_WIN32(
                ERROR_NOT_READY
            );
    }

    if (queryResult) {
        *queryResult =
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

    if (!taskbarModel6) {
        return false;
    }

    reinterpret_cast<IUnknown*>(
        taskbarModel6
    )->AddRef();

    void* collectionAbi =
        nullptr;

    const HRESULT getterHr =
        TaskbarModel_GetOverflowIcons_Original(
            taskbarModel6,
            &collectionAbi
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
                queryResult,
                sizeResult
            );

        reinterpret_cast<IUnknown*>(
            collectionAbi
        )->Release();
    }

    reinterpret_cast<IUnknown*>(
        taskbarModel6
    )->Release();

    return success;
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

    const HRESULT getterResult =
        TaskbarModel_GetOverflowIcons_Original(
            pThis,
            result
        );

    if (
        SUCCEEDED(getterResult) &&
        result &&
        *result
    ) {
        CacheTaskbarModel6(
            pThis
        );
    }

    unsigned int size =
        0;

    HRESULT queryResult =
        E_FAIL;

    HRESULT sizeResult =
        E_FAIL;

    const bool sizeValid =
        SUCCEEDED(getterResult) &&
        result &&
        *result &&
        QueryVectorSize(
            *result,
            &size,
            &queryResult,
            &sizeResult
        );

    Wh_Log(
        L"OVERFLOW_GETTER "
        L"call=%llu "
        L"thread=%lu "
        L"taskbarModel6=%p "
        L"result=0x%08X "
        L"collection=%p "
        L"vectorQueryResult=0x%08X "
        L"sizeResult=0x%08X "
        L"sizeValid=%d "
        L"size=%u",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        static_cast<unsigned int>(
            getterResult
        ),
        result
            ? *result
            : nullptr,
        static_cast<unsigned int>(
            queryResult
        ),
        static_cast<unsigned int>(
            sizeResult
        ),
        sizeValid
            ? 1
            : 0,
        size
    );

    return getterResult;
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
        L"trayNotifyData=%p "
        L"beforeValid=%d "
        L"beforeStatus=%ld "
        L"beforeCount=%llu",
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
        )
    );

    NotificationAreaIconManager_AddIcon_Original(
        pThis,
        trayNotifyData
    );

    Wh_Log(
        L"ADD_ICON_END "
        L"call=%llu "
        L"thread=%lu "
        L"manager=%p",
        callNumber,
        GetCurrentThreadId(),
        pThis
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
        L"parentAddCall=%llu",
        callNumber,
        GetCurrentThreadId(),
        pThis,
        iconImplementation,
        g_addIconContext.active
            ? 1
            : 0,
        g_addIconContext.active
            ? g_addIconContext.callNumber
            : 0
    );

    NotificationAreaIconManager_AddVisible_Original(
        pThis,
        iconImplementation
    );

    if (!g_addIconContext.active) {
        Wh_Log(
            L"VISIBLE_ADD_WITHOUT_ADD_CONTEXT "
            L"call=%llu",
            callNumber
        );

        return;
    }

    const UIOrderSnapshot after =
        CaptureUIOrderSnapshot();

    const std::vector<std::uint64_t> addedIdentities =
        FindAddedIdentities(
            g_addIconContext.before,
            after
        );

    Wh_Log(
        L"VISIBLE_ADD_ORDER_DELTA "
        L"call=%llu "
        L"parentAddCall=%llu "
        L"beforeValid=%d "
        L"afterValid=%d "
        L"beforeCount=%llu "
        L"afterCount=%llu "
        L"addedCount=%llu",
        callNumber,
        g_addIconContext.callNumber,
        g_addIconContext.before.valid
            ? 1
            : 0,
        after.valid
            ? 1
            : 0,
        static_cast<unsigned long long>(
            g_addIconContext.before.entries.size()
        ),
        static_cast<unsigned long long>(
            after.entries.size()
        ),
        static_cast<unsigned long long>(
            addedIdentities.size()
        )
    );

    std::uint64_t targetIdentity =
        0;

    unsigned int targetMatches =
        0;

    for (
        std::uint64_t identity :
        addedIdentities
    ) {
        const std::wstring executablePath =
            QueryStringValue(
                MakeTrayEntrySubkey(
                    identity
                ),
                L"ExecutablePath"
            );

        Wh_Log(
            L"ADDED_IDENTITY "
            L"call=%llu "
            L"id=%llu "
            L"path=\"%s\"",
            callNumber,
            static_cast<unsigned long long>(
                identity
            ),
            executablePath.c_str()
        );

        if (
            EndsWithOrdinalIgnoreCase(
                executablePath,
                kTargetExecutableName
            )
        ) {
            targetIdentity =
                identity;

            targetMatches++;
        }
    }

    if (targetMatches != 1) {
        Wh_Log(
            L"TARGET_NOT_OBSERVED "
            L"call=%llu "
            L"targetMatches=%u",
            callNumber,
            targetMatches
        );

        return;
    }

    unsigned int overflowSize =
        0;

    HRESULT getterResult =
        E_FAIL;

    HRESULT queryResult =
        E_FAIL;

    HRESULT sizeResult =
        E_FAIL;

    const bool overflowSizeValid =
        ReadCurrentOverflowSize(
            &overflowSize,
            &getterResult,
            &queryResult,
            &sizeResult
        );

    if (!overflowSizeValid) {
        Wh_Log(
            L"TARGET_OVERFLOW_SIZE_UNAVAILABLE "
            L"call=%llu "
            L"id=%llu "
            L"getterResult=0x%08X "
            L"vectorQueryResult=0x%08X "
            L"sizeResult=0x%08X "
            L"cachedTaskbarModel6=%p",
            callNumber,
            static_cast<unsigned long long>(
                targetIdentity
            ),
            static_cast<unsigned int>(
                getterResult
            ),
            static_cast<unsigned int>(
                queryResult
            ),
            static_cast<unsigned int>(
                sizeResult
            ),
            g_taskbarModel6.load(
                std::memory_order_acquire
            )
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
            L"TARGET_ALREADY_CONSUMED "
            L"call=%llu "
            L"id=%llu",
            callNumber,
            static_cast<unsigned long long>(
                targetIdentity
            )
        );

        return;
    }

    const unsigned long long observationNumber =
        g_targetObservations.fetch_add(
            1,
            std::memory_order_relaxed
        ) +
        1;

    Wh_Log(
        L"TARGET_OVERFLOW_OBSERVATION "
        L"observation=%llu "
        L"call=%llu "
        L"parentAddCall=%llu "
        L"id=%llu "
        L"implementation=%p "
        L"overflowSize=%u "
        L"finalZeroBasedIndex=%u",
        observationNumber,
        callNumber,
        g_addIconContext.callNumber,
        static_cast<unsigned long long>(
            targetIdentity
        ),
        iconImplementation,
        overflowSize,
        overflowSize == 0
            ? 0
            : overflowSize - 1
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

    Wh_Log(
        L"Tray identity and overflow-size "
        L"hooks installed"
    );

    return true;
}

}  // namespace

BOOL Wh_ModInit() {
    Wh_Log(
        L"Tray Add Path Analyzer "
        L"0.6.0 initializing"
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
    void* taskbarModel6 =
        g_taskbarModel6.exchange(
            nullptr,
            std::memory_order_acq_rel
        );

    if (taskbarModel6) {
        reinterpret_cast<IUnknown*>(
            taskbarModel6
        )->Release();
    }

    Wh_Log(
        L"Tray Add Path Analyzer stopped; "
        L"addIconCalls=%llu "
        L"visibleAddCalls=%llu "
        L"overflowGetterCalls=%llu "
        L"targetObservations=%llu "
        L"testConsumed=%d",
        g_addIconCalls.load(
            std::memory_order_relaxed
        ),
        g_visibleAddCalls.load(
            std::memory_order_relaxed
        ),
        g_overflowGetterCalls.load(
            std::memory_order_relaxed
        ),
        g_targetObservations.load(
            std::memory_order_relaxed
        ),
        g_testConsumed.load(
            std::memory_order_relaxed
        )
            ? 1
            : 0
    );
}
