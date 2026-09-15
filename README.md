# Tray Order Lock

A Windhawk mod for preserving Windows 11 notification-area icon order while
still allowing user-controlled reordering.

## Status

Tray Order Lock 0.2.0 is the current standalone release.

Long-term real-world use has exposed an order-drift issue in
**Preserve order, allow manual changes** mode. The trigger and responsible code
path are still under investigation.

The mod is not yet published in Windhawk's official mod catalog. Official
submission is paused until the order-drift issue is understood and the resulting
fix is validated.

## Features

Tray Order Lock provides two ordering modes:

### Lock all reordering

Preserves the original 0.1.0 behavior.

- Blocks notification-area icon move requests.
- Prevents manual tray reordering while the mode is active.
- Does not directly modify `UIOrderList`.

### Preserve order, allow manual changes

Allows the user to rearrange tray icons while protecting the resulting order
from later application, Windows or Explorer-driven recreation.

- Learns successful manual tray moves.
- Stores a canonical logical order in Windhawk local storage.
- Restores known icons to their canonical relative position when necessary.
- Preserves the canonical order across complete Explorer process restarts.
- Uses Windows' own notification-area move path for restoration.
- Does not directly write or reconstruct `UIOrderList`.

Logical icon identity uses:

- `IconGuid` when available.
- Otherwise, a version-normalized executable path plus UID.

Ambiguous or unsupported identities are deliberately left untouched.

## New icon handling

In **Preserve order, allow manual changes** mode, genuinely new icons can use
one of two policies:

- **Use Windows default position**
- **Place new icons at the end**

Windows-default placement is adopted into the canonical order without moving the
icon when a safe relation can be determined.

## Requirements

- Windows 11
- 64-bit Explorer
- Windhawk

Development and runtime validation for version 0.2.0 was performed on Windows 11
25H2, build 26200.8973.

The mod relies on internal Windows taskbar symbols and interfaces, which can
change in later Windows builds.

## Installation

Until the mod is submitted to the official Windhawk catalog:

1. Open the repository's latest GitHub Release.
2. Download `tray-order-lock.wh.cpp`.
3. Open Windhawk.
4. Create a new local mod.
5. Replace the local mod source with `tray-order-lock.wh.cpp`.
6. Select **Compile Mod**.
7. Enable the mod.
8. Choose the desired ordering behavior in Settings.

## Settings

### Ordering behavior

- **Lock all reordering**
- **Preserve order, allow manual changes**

### New icon placement

Used with Preserve order mode:

- **Use Windows default position**
- **Place new icons at the end**

## Validation

Version 0.2.0 runtime testing confirmed:

- Manual moves can be learned and persisted.
- Known logical icons can be restored after recreation.
- Canonical ordering survives Explorer restarts.
- Automatic restore moves are not learned back as manual changes.
- Restore operations are suppressed safely during user-initiated moves.
- Both new-icon placement policies work.
- The final Lock all reordering regression still blocks move requests.
- Explorer remained stable during the final validated tests.

See [`docs/research.md`](docs/research.md) for the investigation and technical
validation history.

## Repository layout

```text
tray-order-lock.wh.cpp
README.md
LICENSE
docs/
└── research.md
research/
├── analyzers/
│   ├── system-tray-index-analyzer.wh.cpp
│   ├── taskbar-symbol-enumerator.wh.cpp
│   ├── tray-add-path-analyzer.wh.cpp
│   └── tray-order-lock-analyzer.wh.cpp
└── experiments/
    ├── chatgpt-stable-tray-id-test.wh.cpp
    ├── nvidia-stable-tray-id-test.wh.cpp
    └── stable-tray-icons.wh.cpp
scripts/
└── copy-mod-to-clipboard.ps1
```

The repository root intentionally contains only the actual Tray Order Lock
Windhawk source. Analyzer and experimental mods are retained under `research/`
for development history and reproducibility.

## VS Code workflow

The repository files are the source of truth.

Press `Ctrl+Shift+B` while a `.wh.cpp` file is active to run the included
**Copy active Windhawk mod to clipboard** task.

The task copies the complete active source file to the clipboard. Windhawk
remains responsible for **Compile Mod**, mod enablement and runtime logging.

## Versioning

Production Tray Order Lock releases use normal semantic-version tags:

```text
vX.Y.Z
```

Research checkpoints keep tool-specific annotated tag names so that multiple
analyzers can coexist in the same repository without ambiguity.

## License

Licensed under the MIT License.
