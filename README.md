# Windhawk Tray Order Lock

Research project for preserving Windows 11 notification-area icon identity and
ordering across application updates.

## Stable Tray Icons

`stable-tray-icons.wh.cpp` combines the verified app-specific experiments:

- ChatGPT: UID `3`
- NVIDIA Settings: UID `1051`

Both icons receive fixed GUIDs before their `Shell_NotifyIconW/A` calls reach the
Windows shell. The standalone test mods remain under `experiments/` for reference.

This fixes identity changes for those selected applications, but it is not a
general solution because many tray applications do not provide stable GUIDs or
stable UIDs.

## Repository layout

```text
stable-tray-icons.wh.cpp
experiments/
├── chatgpt-stable-tray-id-test.wh.cpp
└── nvidia-stable-tray-id-test.wh.cpp
```

## Status

Experimental research project.

## License

Licensed under the MIT License.
