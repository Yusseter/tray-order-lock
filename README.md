# Windhawk Tray Order Lock

Research project for preserving Windows 11 notification-area icon identity and
ordering across application updates.

## Included mods

### Stable Tray Icons

Assigns fixed GUIDs to the verified ChatGPT and NVIDIA Settings tray icons.

### Tray Order Lock Analyzer

Hooks `Shell_NotifyIconW/A` and logs the identity information supplied by tray
applications, including process path, package family, company, product, window,
UID, GUID, flags and tooltip.

The analyzer only observes calls and does not change icon data. Version 0.2.0
keeps the live Windhawk output and also writes UTF-16 process logs under
`%LOCALAPPDATA%\TrayOrderLockAnalyzer`.

### System Tray Index Analyzer

Hooks `StackViewModel::UpdateIconIndexes()` in `SystemTray.dll` (with a
`Taskbar.View.dll` fallback) and logs each call without changing tray state.

## Repository layout

```text
stable-tray-icons.wh.cpp
tray-order-lock-analyzer.wh.cpp
system-tray-index-analyzer.wh.cpp
experiments/
├── chatgpt-stable-tray-id-test.wh.cpp
└── nvidia-stable-tray-id-test.wh.cpp
```

## VS Code workflow

The files in this repository are the source of truth. Use normal VS Code for
editing, Git and review, then copy a `.wh.cpp` file into Windhawk for compilation
and runtime testing.

The included VS Code task **Copy active Windhawk mod to clipboard** runs the
PowerShell helper in `scripts/`. Windhawk remains responsible for `Compile Mod`,
mod enablement and live log output.

## Research notes

See [`docs/research.md`](docs/research.md) for the tested identity and
`UIOrderList` findings.

## Status

Experimental research project. A complete general order-lock implementation has
not been added yet.

## License

Licensed under the MIT License.
