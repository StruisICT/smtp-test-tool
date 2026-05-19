# Capture the smtp-test-tool-gui window into a PNG, in the requested
# theme.  Uses the PrintWindow API with PW_RENDERFULLCONTENT so we read
# pixels straight from the window's own backing store - works even when
# other windows are overlapping ours, and never captures anything from
# the rest of the user's desktop.
#
# Lives in .local-screenshot/ (gitignored) so users running this from a
# checkout get a clean tree; we publish only the resulting PNGs under
# docs/screenshots/.

param(
    [Parameter(Mandatory = $true)] [ValidateSet('dark', 'light')] [string] $Theme,
    [Parameter(Mandatory = $true)] [string] $OutPng,
    [int] $WarmupSeconds = 6
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class W32 {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr h, out RECT r);

    // PrintWindow with PW_RENDERFULLCONTENT (0x02) reads the window's
    // own backing store - what the *window* drew, not whatever is on
    // top of it at this moment.
    [DllImport("user32.dll")]
    public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
}
"@

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$exe      = Join-Path $repoRoot 'target\release\smtp-test-tool-gui.exe'
if (-not (Test-Path $exe)) {
    throw "exe not found: $exe (run cargo build --release --bin smtp-test-tool-gui)"
}

# Stage the config next to the exe.  Drop the file in target/release/
# (the FIRST place discover_config_path() looks - exactly what an end
# user does when they ship the binary).  Restore the original after.
$cfgPath = Join-Path (Split-Path -Parent $exe) 'smtp_test_tool.toml'
$cfgBackup = $null
if (Test-Path $cfgPath) {
    $cfgBackup = $cfgPath + '.shotbak'
    Move-Item $cfgPath $cfgBackup -Force
}
@"
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
theme = "$Theme"
"@ | Set-Content -Path $cfgPath -Encoding utf8

# ---- launch + wait ----
$proc = Start-Process -FilePath $exe -PassThru
Start-Sleep -Seconds $WarmupSeconds

try {
    # Get-Process's MainWindowHandle is more reliable than FindWindow
    # under RDP / multi-session conditions.
    $p = Get-Process -Id $proc.Id -ErrorAction Stop
    if ($p.MainWindowHandle -eq [IntPtr]::Zero) {
        throw "process $($proc.Id) has no visible main window yet (raise -WarmupSeconds?)"
    }
    $hwnd = $p.MainWindowHandle

    $r = New-Object W32+RECT
    [void][W32]::GetWindowRect($hwnd, [ref] $r)
    $w  = $r.Right  - $r.Left
    $ht = $r.Bottom - $r.Top
    if ($w -le 0 -or $ht -le 0) { throw "window has zero size" }

    $bmp = New-Object System.Drawing.Bitmap $w, $ht
    $g   = [System.Drawing.Graphics]::FromImage($bmp)
    $dc  = $g.GetHdc()
    try {
        # 0x02 = PW_RENDERFULLCONTENT (Win 8.1+).  Tells PrintWindow to
        # render even DirectComposition / GL-backed surfaces - egui
        # uses glow which paints via OpenGL.
        $ok = [W32]::PrintWindow($hwnd, $dc, 2)
        if (-not $ok) { throw "PrintWindow returned false" }
    } finally {
        $g.ReleaseHdc($dc)
        $g.Dispose()
    }

    $outDir = Split-Path -Parent $OutPng
    if ($outDir -and -not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir | Out-Null
    }
    $bmp.Save($OutPng, [System.Drawing.Imaging.ImageFormat]::Png)
    Write-Host "captured $OutPng  ($w x $ht, theme=$Theme)"
} finally {
    try { Stop-Process -Id $proc.Id -Force } catch {}
    Remove-Item -Force $cfgPath -ErrorAction SilentlyContinue
    if ($cfgBackup -and (Test-Path $cfgBackup)) {
        Move-Item $cfgBackup $cfgPath -Force
    }
}
