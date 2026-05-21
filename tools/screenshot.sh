#!/usr/bin/env bash
# Capture the smtp-test-tool-gui window into a PNG in a deterministic
# theme.  Linux X11 only (Wayland is best-effort; see notes below).
#
# Usage:
#   tools/screenshot.sh dark  docs/screenshots/gui-dark.png
#   tools/screenshot.sh light docs/screenshots/gui-light.png
#
# Prerequisites:
#   * The release binary built:
#       cargo build --release --bin smtp-test-tool-gui
#   * X11 utilities:
#       xdotool      - to locate the window by name
#       ImageMagick  - 'import' is invoked to capture
#       grim+slurp   - (Wayland-only fallback) NOT supported here
#                       because slurp requires interactive selection;
#                       see tools/README.md for the manual recipe.
#
# Design mirrors tools/screenshot.ps1:
#   1. Back up an existing target/release/smtp_test_tool.toml.
#   2. Stage a deterministic config that pins the requested theme.
#   3. Launch the GUI; wait for the window to appear.
#   4. Capture the window's pixels into the requested PNG path.
#   5. Restore the backed-up config (or remove the staged one).
#   6. Kill the GUI.
#
# Lives outside the GUI binary so the binary stays purely the tool, not
# the screenshot harness.

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
for cmd in xdotool import; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "error: required command '$cmd' is not installed" >&2
        echo "       sudo apt install xdotool imagemagick" >&2
        exit 67
    fi
done
if [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
    cat >&2 <<EOF
warning: Wayland session detected (\$WAYLAND_DISPLAY=$WAYLAND_DISPLAY).
         xdotool + ImageMagick's import work reliably on X11 only.  On
         Wayland the capture may be empty or fail; consider running
         under Xwayland or capturing manually with grim/slurp.  See
         tools/README.md.
EOF
fi

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

# Poll up to 12 s for the window so slow CPUs / cold caches still work.
window_id=""
for _ in $(seq 1 24); do
    if window_id="$(xdotool search --name 'SMTP Test Tool' 2>/dev/null | head -n1)"; then
        if [[ -n "$window_id" ]]; then
            break
        fi
    fi
    sleep 0.5
done
if [[ -z "$window_id" ]]; then
    echo "error: GUI window 'SMTP Test Tool' did not appear within 12s" >&2
    exit 70
fi

# Activate (X11) and let it repaint before capturing.
xdotool windowactivate --sync "$window_id" 2>/dev/null || true
sleep 0.5

mkdir -p -- "$(dirname -- "$out_png")"
import -window "$window_id" -- "$out_png"
echo "captured $out_png  (theme=$theme, window_id=$window_id)"
