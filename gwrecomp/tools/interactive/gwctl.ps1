# Real-input driver for the native GeneWars window: OS-level mouse/keyboard events + window screenshots.
# Usage (dot-source):  . .\gwctl.ps1 ; $w = Find-GwWindow 'gw_demo' ; Shot $w out.png ; Click $w 320 200 ; Key 'ESC'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class W {
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h, ref POINT p);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, int dx, int dy, uint d, UIntPtr e);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte sc, uint f, UIntPtr e);
  [DllImport("user32.dll")] public static extern uint MapVirtualKey(uint c, uint t);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint f);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
}
'@
[void][W]::SetProcessDPIAware()
function Find-GwWindow([string]$proc = 'gw_demo') {
    $p = Get-Process | Where-Object { $_.ProcessName -like "$proc*" -and $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    if ($p) { return $p.MainWindowHandle } else { return [IntPtr]::Zero }
}
# Bring the game window to the front for real (a plain SetForegroundWindow is refused when another app is active, and then
# every click lands on whatever window is on top). Verified through GetForegroundWindow.
function Focus-Window($h) {
    if (-not [W]::IsWindow($h)) { $h = Find-GwWindow }   # the game recreates its window between intro and title: never trust an old handle
    for ($i = 0; $i -lt 5; $i++) {
        if ([W]::GetForegroundWindow() -eq $h) { return $true }
        [W]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero); [W]::keybd_event(0x12, 0, 2, [UIntPtr]::Zero)   # ALT tap lifts the foreground lock
        [void][W]::ShowWindow($h, 9); [void][W]::BringWindowToTop($h); [void][W]::SetForegroundWindow($h); Start-Sleep -Milliseconds 200
    }
    return ([W]::GetForegroundWindow() -eq $h)
}
function Get-Client($h) {
    if (-not [W]::IsWindow($h)) { $h = Find-GwWindow }
    $r = New-Object W+RECT; [void][W]::GetClientRect($h, [ref]$r)
    $pt = New-Object W+POINT; [void][W]::ClientToScreen($h, [ref]$pt)
    return @{ X = $pt.X; Y = $pt.Y; W = $r.R; H = $r.B }
}
function Shot($h, [string]$path) {
    $c = Get-Client $h
    $bmp = New-Object System.Drawing.Bitmap $c.W, $c.H
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($c.X, $c.Y, 0, 0, $bmp.Size)   # screen capture: the window must be visible and not covered
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $bmp.Dispose()
}
# fx,fy are fractions (0..1) of the client area so the call is independent of the window size
function Move-Mouse($h, [double]$fx, [double]$fy) {
    $c = Get-Client $h; [void][W]::SetCursorPos([int]($c.X + $fx * $c.W), [int]($c.Y + $fy * $c.H))
}
function Click($h, [double]$fx, [double]$fy, [string]$button = 'L', [int]$holdMs = 80) {
    if (-not (Focus-Window $h)) { Write-Host '  [warn] could not bring the game window to the front' }; Move-Mouse $h $fx $fy; Start-Sleep -Milliseconds 120
    $dn, $up = if ($button -eq 'R') { 0x0008, 0x0010 } else { 0x0002, 0x0004 }
    [W]::mouse_event($dn, 0, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds $holdMs
    [W]::mouse_event($up, 0, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 150
}
$script:VK = @{ ESC = 0x1B; ENTER = 0x0D; SPACE = 0x20; F1 = 0x70; F2 = 0x71; F3 = 0x72; F4 = 0x73; F5 = 0x74; LEFT = 0x25; UP = 0x26; RIGHT = 0x27; DOWN = 0x28 }
function Key($name, [int]$holdMs = 60) {
    $vk = if ($script:VK.ContainsKey($name)) { $script:VK[$name] } else { [byte][char]$name.ToUpper() }
    $sc = [byte][W]::MapVirtualKey([uint32]$vk, 0)
    [W]::keybd_event([byte]$vk, $sc, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds $holdMs
    [W]::keybd_event([byte]$vk, $sc, 2, [UIntPtr]::Zero); Start-Sleep -Milliseconds 120
}
function ShotPW($h, [string]$path) {
    $c = Get-Client $h
    $bmp = New-Object System.Drawing.Bitmap $c.W, $c.H
    $g = [System.Drawing.Graphics]::FromImage($bmp); $dc = $g.GetHdc()
    [void][W]::PrintWindow($h, $dc, 3)   # PW_CLIENTONLY | PW_RENDERFULLCONTENT
    $g.ReleaseHdc($dc); $g.Dispose()
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
}
function Mean-Brightness([string]$path) {
    $b = [System.Drawing.Bitmap]::FromFile($path); $s = 0; $n = 0
    for ($y = 0; $y -lt $b.Height; $y += 30) { for ($x = 0; $x -lt $b.Width; $x += 30) { $c = $b.GetPixel($x, $y); $s += $c.R + $c.G + $c.B; $n++ } }
    $b.Dispose(); return [math]::Round($s / $n / 3, 1)
}
# Ask the game to dump the frame it presents (needs GW_FRAME_DUMP_DIR); returns the PNG path. Compositor-independent.
function Snap([string]$dir, [string]$stem, [int]$timeoutMs = 5000) {
    $bmp = Join-Path $dir "$stem.bmp"; Remove-Item $bmp -ErrorAction SilentlyContinue
    [IO.File]::WriteAllText((Join-Path $dir 'snap.req'), $stem)
    $t = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path $bmp) -and $t.ElapsedMilliseconds -lt $timeoutMs) { Start-Sleep -Milliseconds 100 }
    if (-not (Test-Path $bmp)) { return $null }
    Start-Sleep -Milliseconds 150
    $png = Join-Path $dir "$stem.png"
    $b = [System.Drawing.Bitmap]::FromFile($bmp); $b.Save($png, [System.Drawing.Imaging.ImageFormat]::Png); $b.Dispose()
    Remove-Item $bmp; return $png
}
