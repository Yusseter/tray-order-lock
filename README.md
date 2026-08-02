# Windhawk Tray Order Lock

Research project for keeping Windows 11 notification-area icons associated with
their intended identities and positions across application updates.

## Current stage

The repository starts with two focused Windhawk experiments:

- `ChatGPT Stable Tray ID Test`
- `NVIDIA Stable Tray ID Test`

Each experiment assigns a fixed GUID to one verified tray icon. This tests
whether a stable icon identity prevents application updates or changing host
executables from creating a new tray record.

## Repository layout

```text
experiments/
├── chatgpt-stable-tray-id-test.wh.cpp
└── nvidia-stable-tray-id-test.wh.cpp
```

## Status

Experimental. The repository does not yet provide a general tray-order lock.

## License

Licensed under the MIT License.
