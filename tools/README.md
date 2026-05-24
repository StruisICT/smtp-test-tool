# tools/

Developer utilities, **not** shipped to end users.

## `screenshot.ps1` / `screenshot.sh` / `screenshot-macos.sh`

Captures `docs/screenshots/gui-{dark,light}.png` from the running
release GUI on Windows, Linux (X11), or macOS respectively.  All three
scripts share the same recipe: stage a deterministic config that pins
the requested theme next to the exe, launch the GUI, locate the
window, capture pixels straight from the window's backing store, kill
the process, restore the previous config.

**Why this exists.**  Per `AGENTS.md` §3, any user-facing change must
ship with dark + light screenshots.  This script is the deterministic
way to produce them so reviewers see the same image you do.

### Prerequisites

* Windows 10 or newer (PowerShell 5+).
* The release binary built:
  ```sh
  cargo build --release --bin smtp-test-tool-gui
  ```

### Prerequisites (all platforms)

```sh
cargo build --release --bin smtp-test-tool-gui
```

### Windows

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
    -File tools/screenshot.ps1 `
    -Theme dark  -OutPng docs/screenshots/gui-dark.png
powershell -NoProfile -ExecutionPolicy Bypass `
    -File tools/screenshot.ps1 `
    -Theme light -OutPng docs/screenshots/gui-light.png
```

Uses the Win32 `PrintWindow` API with `PW_RENDERFULLCONTENT`, which
reads pixels from the window's own GL surface.  Works under
overlapping windows; never captures any other desktop area.

**Requires an interactive desktop session.**  PowerShell sessions
started over WinRM, SSH (without a logged-in console session), or any
"session 0" service context cannot capture GL surfaces - both
`PrintWindow` and the `CopyFromScreen` fallback will return an empty
bitmap.  Run the script from a logged-in RDP or physical console
session.  The script samples the captured bitmap for pixel diversity
and warns when the surface looks empty so you don't accidentally
commit blank PNGs.

### Linux (X11)

```sh
sudo apt install xdotool imagemagick     # one-off
tools/screenshot.sh dark  docs/screenshots/gui-dark.png
tools/screenshot.sh light docs/screenshots/gui-light.png
```

`xdotool search --name 'SMTP Test Tool'` resolves the X11 window id;
`import -window <id>` is the actual capture.  **Wayland** sessions are
best-effort: xdotool reaches Xwayland clients via XWayland's X11
bridge, but native-Wayland egui builds will need a manual `grim`
capture - the script prints a warning when `$WAYLAND_DISPLAY` is set.

### macOS

```sh
tools/screenshot-macos.sh dark  docs/screenshots/gui-dark.png
tools/screenshot-macos.sh light docs/screenshots/gui-light.png
```

A short AppleScript helper iterates `CGWindowListCopyWindowInfo` to
find the window id; `screencapture -x -o -l <id>` then writes the
PNG.  First run will trigger a 'Screen Recording' permission prompt
for your terminal under *System Settings > Privacy & Security*.

### Future work

CI does NOT yet regenerate these screenshots automatically; doing so
would require a virtual display server (Xvfb) plus xdotool on the
ubuntu-latest runner.  Open a PR if you want this - the matrix would
run the Linux variant of the script and diff the output against the
committed PNGs.

### Verifying after capture

After regenerating, open the PNGs and confirm they show the current
GUI (with whatever new tabs / buttons the change adds).  An
`identify`-style sanity check from a shell:

```sh
# A real screenshot is > ~30 KB; a blank GL surface compresses to
# under 10 KB.  Reject anything below that and re-run from an
# interactive desktop.
for f in docs/screenshots/gui-*.png; do
  size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")
  [ "$size" -lt 15000 ] && echo "$f looks empty ($size bytes)" && exit 1
done
```
