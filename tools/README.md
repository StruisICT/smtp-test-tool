# tools/

Developer utilities, **not** shipped to end users.

## `screenshot.ps1` — regenerate the GUI screenshots

Captures `docs/screenshots/gui-{dark,light}.png` from the running release
GUI.  Windows only (uses the Win32 `PrintWindow` API).

**Why this exists.**  Per `AGENTS.md` §3, any user-facing change must
ship with dark + light screenshots.  This script is the deterministic
way to produce them so reviewers see the same image you do.

### Prerequisites

* Windows 10 or newer (PowerShell 5+).
* The release binary built:
  ```sh
  cargo build --release --bin smtp-test-tool-gui
  ```

### Run

```powershell
# from the repo root
powershell -NoProfile -ExecutionPolicy Bypass `
    -File tools/screenshot.ps1 `
    -Theme dark  -OutPng docs/screenshots/gui-dark.png

powershell -NoProfile -ExecutionPolicy Bypass `
    -File tools/screenshot.ps1 `
    -Theme light -OutPng docs/screenshots/gui-light.png
```

### How it works

1. Backs up any pre-existing `target/release/smtp_test_tool.toml`.
2. Writes a deterministic test config there with the requested theme.
3. Launches `target/release/smtp-test-tool-gui.exe`.
4. After a warmup period, locates the window via `Get-Process` (more
   reliable than `FindWindow` under RDP / multi-session).
5. Calls `PrintWindow(hWnd, dc, PW_RENDERFULLCONTENT)` to read pixels
   straight from the window's backing store - works even when other
   windows overlap, and *never* captures anything from the rest of
   your desktop.
6. Saves the PNG, kills the process, restores the backup config.

### Wanted: a non-Windows equivalent

A macOS (`screencapture -l`) and Linux (Xvfb + grim/import) variant
would let CI regenerate the screenshots on every PR.  Open issue
welcome.
