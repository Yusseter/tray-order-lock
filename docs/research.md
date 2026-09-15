# Tray ordering research

## Tested environment

- Windows 11 25H2, build 26200.8973
- 64-bit Explorer
- `SystemTray.dll` 2606.29002.0.0
- `Taskbar.View.dll` 2606.25000.0.0

The findings below describe the tested build. Internal Windows symbols and
implementation details can change in later builds.

## Notification icon identities

The notification-icon analyzer showed that applications use several different
identity models:

- Some icons already provide stable GUIDs.
- Some icons use an executable path and UID.
- Packaged application paths can contain a version and therefore change after an
  update.
- Tooltips are unsuitable as identifiers because they can contain versions,
  temperatures or other changing state.
- Some applications use UIDs that behave like changing window or instance
  values.
- One logical icon can be hosted by more than one executable, as seen with the
  NVIDIA Settings icon.

These findings mean that automatically assigning a GUID from only the full path,
tooltip or UID is not safe for every application.

The fixed-GUID experiments were therefore kept separate from the general
tray-order lock.

## `NotifyIconSettings` and `UIOrderList`

Notification-area registry data is stored under:

```text
HKEY_CURRENT_USER\Control Panel\NotifyIconSettings
```

The `UIOrderList` value is a binary sequence of little-endian 64-bit registry
subkey identifiers.

Each identifier corresponds to a child key below `NotifyIconSettings`.

A controlled test swapped two identifiers in `UIOrderList`:

- The visible tray order did not change while Explorer remained running.
- Restarting Explorer made the changed order visible.
- Restoring the original bytes and restarting Explorer restored the original
  order.
- Temporarily touching values in the child keys did not make Explorer refresh
  the order live.

This shows that Explorer keeps an in-memory ordering model instead of
continuously rendering directly from `UIOrderList`.

`UIOrderList` stores persistent order, but writing or suppressing that value
alone does not directly control the already visible in-memory order.

## `StackViewModel::UpdateIconIndexes`

On the tested build, the following function is called when tray icon indexes are
updated:

```text
winrt::SystemTray::implementation::StackViewModel::UpdateIconIndexes()
```

Observed behavior included:

- A successful manual drag generated two calls.
- Dragging the icon back generated two calls.
- Removing an application tray icon generated a call.
- Adding the icon again generated a call.

Immediate snapshots before and after the function showed no registry change.

Delayed snapshots at the following offsets also showed no later change:

```text
10 ms
50 ms
250 ms
1000 ms
1500 ms
2000 ms
2500 ms
3000 ms
5000 ms
10000 ms
```

The function is an update and observation point, but it is not the function that
writes `UIOrderList`.

## Registry change timing

A read-only `RegNotifyChangeKeyValue` watcher was added for:

```text
HKEY_CURRENT_USER\Control Panel\NotifyIconSettings
```

During a successful manual drag, the observed order was:

```text
UIOrderList changes
→ registry watcher notification
→ first StackViewModel::UpdateIconIndexes call
→ second StackViewModel::UpdateIconIndexes call
```

The watcher snapshot confirmed that the `UIOrderList` hash had already changed
before either index-update call began.

This explains why snapshots around `UpdateIconIndexes()` always showed the same
new value: the persistent write had completed earlier in the operation.

## Native `UIOrderList` write trace

The analyzer hooked `ntdll!NtSetValueKey` and filtered calls by:

- Value name equal to `UIOrderList`, case-insensitively.
- Registry path ending in
  `\REGISTRY\USER\...\Control Panel\NotifyIconSettings`.
- Successful writes to the exact value.

A manual drag produced one matching write.

The captured call stack resolved through public symbols to the following path:

```text
SystemTray!NotifyIconView::OnPointerReleased
→ SystemTray!DragDropManager::DoDrop
→ NotifyIconDragDropOperation delegate and event
→ SystemTray!SystemTrayController::HandleNotifyIconDragDrop
→ SystemTray!ITaskbarModel5::MoveNotificationAreaIcon
→ taskbar!TaskbarModel::MoveNotificationAreaIcon
→ taskbar!NotificationAreaIconManager2::MoveIcon
→ taskbar!NotifyIconSettingsDatabase::MoveIcon
→ taskbar!NotifyIconRegistryHelpers::WriteUInt64Vector
→ ntdll!NtSetValueKey
→ UIOrderList
```

The write completed before either observed
`StackViewModel::UpdateIconIndexes()` call.

## Candidate control points

### `NotifyIconRegistryHelpers::WriteUInt64Vector`

This is the direct helper that serializes and writes the 64-bit identifier
vector.

Hooking it would control persistence, but it would not necessarily prevent the
live in-memory move.

### `NotificationAreaIconManager2::MoveIcon`

This is a common move layer below the taskbar model.

The function receives a WinRT object by value. Its normal function body performs
cleanup for that argument, so returning early from a direct hook could bypass
required destruction or reference cleanup.

It was therefore not selected as the production hook boundary.

### `SystemTrayController::HandleNotifyIconDragDrop`

This is an upper mouse-drag-specific layer.

It is useful for understanding the pointer interaction, but it is less general
than the taskbar model interface.

### `ITaskbarModel5::MoveNotificationAreaIcon`

The verified ABI-facing symbol is:

```text
winrt::impl::produce<
    winrt::WindowsUdk::UI::Shell::implementation::TaskbarModel,
    winrt::WindowsUdk::UI::Shell::ITaskbarModel5
>::MoveNotificationAreaIcon(void *,int,unsigned int)
```

The tested hook signature is equivalent to:

```cpp
int __cdecl MoveNotificationAreaIcon(
    void* taskbarModel,
    void* notificationAreaIconAbi,
    int location,
    unsigned int index
);
```

This boundary returns an HRESULT-compatible integer and allows a move request to
be rejected safely by returning `S_OK` without calling the original function.

## Registry-write suppression experiment

System Tray Index Analyzer 0.5.0 suppressed the first exact
`NtSetValueKey` write to `UIOrderList`.

Result:

- The icon visibly moved.
- The new position remained visible in the running Explorer session.
- The persistent `UIOrderList` value did not change.
- Later non-suppressed moves wrote the value normally.

This proved that suppressing the registry write blocks persistence but does not
block the live in-memory reorder.

A registry-write hook was therefore not sufficient for a complete order lock.

## One-shot move-request suppression

System Tray Index Analyzer 0.6.0 suppressed the first
`ITaskbarModel5::MoveNotificationAreaIcon` request and allowed later requests to
continue normally.

For the suppressed request:

- The icon did not remain in the attempted position.
- No `UIOrderList` write occurred.
- No registry watcher notification occurred.
- No new `StackViewModel::UpdateIconIndexes()` call occurred.
- The before and after registry snapshots were identical.

A later allowed request performed the normal visible move, registry write,
watcher notification and two index-update calls.

This demonstrated that the ABI-facing move request is upstream of both the live
move and its persistent registry update.

## Continuous move-request suppression

System Tray Index Analyzer 0.7.0 suppressed every
`ITaskbarModel5::MoveNotificationAreaIcon` request.

The test included repeated attempts with several tray icons.

Observed results:

- Six move requests were generated.
- All six requests were suppressed.
- No icon could be reordered.
- No `UIOrderList` write was attempted.
- No registry watcher notification occurred.
- No new index-update call was caused by the blocked drags.
- The `UIOrderList` value and hash remained unchanged.

A separate application-lifecycle test completely closed and reopened Discord:

- The Discord tray icon disappeared normally.
- The icon returned normally after Discord restarted.
- Discord and Explorer remained functional.
- The lifecycle operations generated expected index-update calls.
- They did not generate move requests.

The analyzer watcher and hooks also shut down cleanly when the mod was disabled.

## Production implementation: 0.1.0

The successful 0.7.0 experiment was reduced to the production
`tray-order-lock.wh.cpp` source.

Tray Order Lock 0.1.0 contains only the components needed for the lock:

- A hook for the verified
  `ITaskbarModel5::MoveNotificationAreaIcon` symbol in `taskbar.dll`.
- A minimal module-load fallback for installations where `taskbar.dll` is not
  loaded when the mod initializes.
- A counter for blocked move requests.
- Basic initialization and shutdown logging.

The production mod does not include:

- `NtSetValueKey` hooks.
- Registry watchers.
- Registry snapshots.
- `UIOrderList` parsing.
- `StackViewModel::UpdateIconIndexes()` hooks.
- Delayed snapshot workers.
- Registry modifications.

Runtime validation of version 0.1.0 confirmed:

- Manual tray reordering was blocked while the mod was enabled.
- Applications could still remove and recreate their tray icons.
- Explorer remained stable.
- Disabling the mod restored normal dragging immediately.
- No Explorer restart was required.

## 0.1.0 scope and limitations

- Testing was performed on the environment listed at the top of this document.
- Internal Windows symbols and class layouts can change in later Windows builds.
- Windhawk must be able to resolve the required public symbol in `taskbar.dll`.
- The verified runtime test covered dragging within the visible notification
  area.
- Moving icons directly between the visible area and the overflow area was not
  separately validated.
- The hook suppresses every request made through
  `ITaskbarModel5::MoveNotificationAreaIcon`, not only requests originating from
  mouse dragging.
- The mod prevents move requests while enabled; it does not reconstruct an old
  order or repair order changes made while the mod was disabled.
- Newly created icons remain subject to Windows' normal icon creation and
  placement behavior.

## Version 0.2.0 research and implementation

Version 0.2.0 extends the original move-request lock with a second ordering
behavior: **Preserve order, allow manual changes**.

The goal is to let the user intentionally change tray order while preventing
later icon recreation, application updates or Explorer restarts from losing the
learned logical relation.

### Canonical logical order

Manual moves are converted into a logical canonical order and persisted in
Windhawk local storage.

Logical identity uses:

- `IconGuid` when available.
- Otherwise, version-normalized executable path plus UID.

Version directories in executable paths are normalized so that an application
update can still resolve to the same logical icon when the remaining identity is
safe and unambiguous.

Historical 64-bit `NotifyIconSettings` identities are not treated as stable
logical identities across Explorer restarts.

### Live Windows identity mapping

Research with `NotificationAreaIcon2` established a direct runtime bridge
between the implementation object and the 64-bit Windows
`NotifyIconSettings`/`UIOrderList` identity.

The constructor receives a settings pair whose first 64-bit value is the Windows
notification-area identity.

The implementation is converted to the same `INotificationAreaIcon` ABI used by
the taskbar move path through `QueryInterface`. Production code therefore does
not depend on a fixed implementation-object offset.

Manual move learning prefers this live ABI-to-Windows-identity mapping. A
read-only `UIOrderList` before/after comparison remains only as a conservative
fallback.

### Automatic restoration

Known icons are restored through Windows'
`NotificationAreaIconManager2::MoveIcon` path.

The production mod does not directly write `UIOrderList`.

Restore decisions are based on canonical logical neighbors rather than requiring
an exact saved numeric index. Unrelated or newly introduced icons may therefore
exist between canonical neighbors without violating the learned relation.

A relation is satisfied when:

- With only a predecessor, the predecessor remains before the target.
- With only a follower, the target remains before the follower.
- With both, the target remains between them.

Automatic moves are verified after the Windows move call and are not retried
aggressively when the result is ambiguous.

### Reentrancy and manual moves

Runtime testing found that a user-initiated taskbar move can synchronously cause
the visible-icon path to run while the outer move is still active.

Automatic restoration is therefore suppressed while a user taskbar move is in
progress. Internal automatic moves use a separate reentrancy depth and are not
learned back into the canonical order as manual user changes.

This eliminated the reentrant restore crash observed during development.

### New icons

Version 0.2.0 supports two policies for genuinely new logical icons.

#### Use Windows default position

The icon remains where Windows placed it.

The mod attempts to adopt that position into canonical order using safe known
neighbors from the live overflow snapshot. If no usable live canonical neighbor
is available, a read-only `UIOrderList` snapshot can be used as a fallback to
derive the relation.

No direct `UIOrderList` write is performed.

#### Place new icons at the end

The icon is moved through `NotificationAreaIconManager2::MoveIcon` to the end of
the overflow ordering.

The new logical key is persisted only after the resulting position is verified.

### Explorer restart validation

Runtime validation confirmed that:

- Canonical logical order loads from Windhawk local storage after a complete
  Explorer process restart.
- Live Windows identities can change while the same logical icon is still
  recognized.
- Known icons can satisfy or restore their canonical relation after restart.
- New icons adopted in an earlier Explorer process are treated as known icons
  after restart.

### Final 0.2.0 validation

The final implementation validated:

- Persistent manual ordering.
- Live identity mapping before and after Explorer restart.
- Automatic restoration of known logical icons.
- Safe suppression of reentrant restore operations during manual moves.
- Windows-default adoption for new icons.
- Place-at-end handling for new icons.
- Read-only `UIOrderList` fallback when live neighbors are unavailable.
- Continued Lock all reordering behavior from version 0.1.0.
- Stable Explorer operation during the final test sequence.

## Post-release order-drift investigation

During longer-term real-world use of version 0.2.0 in **Preserve order, allow
manual changes** mode, some tray icons were observed to move from previously
chosen positions.

The trigger and responsible code path are not yet known. No deliberate Explorer
restart was part of the observed period, so the issue is not currently classified
as an Explorer-restart persistence failure.

The investigation/order-drift branch adds persistent file-backed diagnostic
logging so future occurrences can be correlated with manual-move learning,
canonical-state loading, new-icon handling and automatic restoration before the
ordering logic is changed.

## Current scope and limitations

- The implementation targets the tested Windows 11 notification-area
  architecture and depends on internal taskbar symbols and interfaces.
- Future Windows builds can change those symbols or interfaces.
- Logical identities that cannot be resolved uniquely are left untouched.
- `UIOrderList` is used only for observation and fallback identity/order
  correlation; the mod does not directly write or reconstruct it.
- Automatic restoration is deliberately conservative and avoids speculative
  moves when canonical identity or neighbor relations are ambiguous.
