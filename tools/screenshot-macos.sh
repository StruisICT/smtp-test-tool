#!/usr/bin/env bash
# Capture the smtp-test-tool-gui window into a PNG in a deterministic
# theme.  macOS only.  Uses the built-in `screencapture -l <window-id>`
# which reads pixels straight from the WindowServer's surface for the
# given window - works under overlapping windows, never captures
# anything else on the desktop.
#
# Usage:
#   tools/screenshot-macos.sh dark  docs/screenshots/gui-dark.png
#   tools/screenshot-macos.sh light docs/screenshots/gui-light.png
#
# Prerequisites:
#   * cargo build --release --bin smtp-test-tool-gui  (Apple Silicon or
#     Intel - this script does not care which).
#   * The user must approve 'Screen Recording' for the terminal running
#     the script the first time (System Settings > Privacy & Security >
#     Screen Recording).  Otherwise screencapture returns an empty PNG
#     and prints a warning.
#
# Design mirrors tools/screenshot.ps1 (Windows) and tools/screenshot.sh
# (Linux X11): stage a deterministic config, launch, locate, capture,
# clean up.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 {dark|light} OUTPUT.png" >&2
    exit 64
fi
theme="$1"
out_png="$2"

if [[ "$theme" != "dark" && "$theme" != "light" ]]; then
    echo "error: theme must be 'dark' or 'light' (got '$theme')" >&2
    exit 64
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exe="$repo_root/target/release/smtp-test-tool-gui"
if [[ ! -x "$exe" ]]; then
    echo "error: release binary not found at $exe" >&2
    echo "       run: cargo build --release --bin smtp-test-tool-gui" >&2
    exit 65
fi

# AppleScript helper to find a window's CGWindowID by title.  Returns
# the integer ID on stdout, or empty on no match.
find_window_id() {
    osascript <<'AS' 2>/dev/null
        use framework "AppKit"
        use scripting additions
        set kCGWindowListOptionOnScreenOnly to 1
        set kCGNullWindowID to 0
        set wins to (current application's CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID) as list)
        repeat with w in wins
            try
                set wTitle to ((w as record)'s kCGWindowName as text)
                if wTitle contains "SMTP Test Tool" then
                    return ((w as record)'s kCGWindowNumber as text)
                end if
            end try
        end repeat
        return ""
AS
}

cfg_path="$repo_root/target/release/smtp_test_tool.toml"
backup=""
if [[ -f "$cfg_path" ]]; then
    backup="${cfg_path}.shotbak"
    mv -- "$cfg_path" "$backup"
fi

cleanup() {
    set +e
    if [[ -n "${gui_pid:-}" ]]; then
        kill "$gui_pid" 2>/dev/null
        wait "$gui_pid" 2>/dev/null
    fi
    rm -f -- "$cfg_path"
    if [[ -n "$backup" && -f "$backup" ]]; then
        mv -- "$backup" "$cfg_path"
    fi
}
trap cleanup EXIT

cat > "$cfg_path" <<EOF
active = "default"

[profiles.default]
user = "ops@contoso.com"
smtp_host = "smtp-mail.outlook.com"
smtp_port = 587
smtp_security = "starttls"
imap_host = "outlook.office365.com"
imap_port = 993
imap_security = "ssl"
pop_host = "outlook.office365.com"
pop_port = 995
pop_security = "ssl"
pop_enabled = false
theme = "$theme"
EOF

"$exe" >/dev/null 2>&1 &
gui_pid=$!

window_id=""
for _ in $(seq 1 24); do
    window_id="$(find_window_id | tr -d '[:space:]')"
    if [[ -n "$window_id" ]]; then
        break
    fi
    sleep 0.5
done
if [[ -z "$window_id" ]]; then
    echo "error: GUI window 'SMTP Test Tool' not found via CGWindowList within 12s" >&2
    exit 70
fi

# Bring the window to front so the rendering thread paints the latest
# frame, then capture.  -o omits the window's drop-shadow border.
osascript -e 'tell application "smtp-test-tool-gui" to activate' 2>/dev/null || true
sleep 0.5

mkdir -p -- "$(dirname -- "$out_png")"
screencapture -x -o -l "$window_id" -t png -- "$out_png"
echo "captured $out_png  (theme=$theme, window_id=$window_id)"
