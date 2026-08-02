# Tray ordering research

## Tested environment

- Windows 11 25H2, build 26200.8973
- `SystemTray.dll` 2606.29002.0.0
- `Taskbar.View.dll` 2606.25000.0.0

## Notification icon identities

The analyzer showed that applications use several different identity models:

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

## `NotifyIconSettings` and `UIOrderList`

The notification-area registry data is stored under:

```text
HKEY_CURRENT_USER\Control Panel\NotifyIconSettings
```

The `UIOrderList` value is a binary sequence of little-endian 64-bit registry
subkey identifiers.

A controlled test swapped two identifiers in `UIOrderList`:

- The visible tray order did not change while Explorer remained running.
- Restarting Explorer made the changed order visible.
- Restoring the original bytes and restarting Explorer restored the original
  order.
- Temporarily touching values in the child keys did not make Explorer refresh the
  order live.

This indicates that Explorer keeps an in-memory ordering model instead of
continuously rendering directly from `UIOrderList`.

## SystemTray update function

On the tested build, the following function is called when icon indexes are
updated:

```text
winrt::SystemTray::implementation::StackViewModel::UpdateIconIndexes()
```

Observed behavior:

- A manual drag generated two calls.
- Dragging the icon back generated two calls.
- Deleting a ChatGPT or NVIDIA icon generated a call.
- Adding the icon again generated a call.

The function is therefore a useful observation point for future work, but the
current analyzer does not alter its behavior.
