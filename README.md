# Windhawk Tray Order Lock

Windhawk project for studying and preserving Windows 11 notification-area icon
identity and ordering.

The repository contains a usable tray-order lock together with the analyzers and
experiments used to identify a safe control point.

## Tray Order Lock

`tray-order-lock.wh.cpp` prevents notification-area icons from being manually
reordered while the mod is enabled.

Arrange the icons in the desired order, then enable the mod. Dragging an icon to
another position is rejected without changing either the live order or the
persistent `UIOrderList` registry data.

Disabling the mod immediately restores normal icon dragging.

### Version 0.1.0 behavior

- Blocks tray icon move requests through
  `ITaskbarModel5::MoveNotificationAreaIcon`.
- Returns `S_OK` without forwarding blocked requests.
- Does not modify, replace or reconstruct the saved tray order.
- Does not write to `UIOrderList`.
- Allows applications to add and remove their tray icons normally.
- Requires no Explorer restart when enabling or disabling the lock.
- Targets 64-bit Windows 11 Explorer.

The tested behavior covers manual dragging within the visible notification area.
Because the mod suppresses the interface itself, any other caller using the same
move interface is also blocked while the mod is enabled.

## Research mods

### Stable Tray Icons

`stable-tray-icons.wh.cpp` assigns fixed GUIDs to the verified ChatGPT and NVIDIA
Settings tray icons.

This experiment addresses icon identity rather than general tray ordering.

### Tray Order Lock Analyzer

`tray-order-lock-analyzer.wh.cpp` hooks `Shell_NotifyIconW/A` and records the
identity information supplied by tray applications, including process path,
package family, company, product, window, UID, GUID, flags and tooltip.

The analyzer observes calls without changing icon data. Version 0.2.0 keeps the
live Windhawk output and also writes UTF-16 process logs under:

```text
%LOCALAPPDATA%\TrayOrderLockAnalyzer
```

### System Tray Index Analyzer

`system-tray-index-analyzer.wh.cpp` was developed through versions 0.1.0 to
0.7.0 to trace the tray-order update path.

The analyzer was used to:

- Observe `StackViewModel::UpdateIconIndexes()`.
- Monitor `UIOrderList` registry changes.
- Trace native `NtSetValueKey` writes.
- Resolve the complete tray drag-to-registry call chain.
- Compare registry-write suppression with move-request suppression.
- Validate continuous move-request suppression before creating the production
  mod.

Analyzer milestones are preserved in annotated tags named
`analyzer-vX.Y.Z`.

## Repository layout

```text
tray-order-lock.wh.cpp
stable-tray-icons.wh.cpp
tray-order-lock-analyzer.wh.cpp
system-tray-index-analyzer.wh.cpp
docs/
└── research.md
scripts/
└── copy-mod-to-clipboard.ps1
experiments/
├── chatgpt-stable-tray-id-test.wh.cpp
└── nvidia-stable-tray-id-test.wh.cpp
```

## VS Code workflow

The files in this repository are the source of truth. Use normal VS Code for
editing, Git and review, then copy a `.wh.cpp` file into Windhawk for compilation
and runtime testing.

The included VS Code task **Copy active Windhawk mod to clipboard** runs the
PowerShell helper in `scripts/`.

Press `Ctrl+Shift+B` while the desired Windhawk source file is active to copy its
complete contents to the clipboard.

Windhawk remains responsible for `Compile Mod`, mod enablement and live log
output.

## Research notes

See [`docs/research.md`](docs/research.md) for the tested identity,
`UIOrderList`, call-chain and move-suppression findings.

## Versioning

Analyzer versions use annotated tags in this form:

```text
analyzer-vX.Y.Z
```

Usable Tray Order Lock releases use annotated tags and GitHub Releases in this
form:

```text
tray-order-lock-vX.Y.Z
```

## Status

The repository contains the tested Tray Order Lock 0.1.0 implementation together
with the research code that led to it.

## License

Licensed under the MIT License.
