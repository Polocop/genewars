<#
 Interactive scenario for the first mission, driven with REAL mouse/keyboard events on the real game window.
   powershell -NoProfile -ExecutionPolicy Bypass -File tools\interactive\playtest.ps1 [-OutDir <dir>] [-Build <rebuild dir>]

 Needs a completed Level B build and your own game files (GENEWARS_INSTALL_DIR; GENEWARS_CUE for music). It starts the game with
 scripts\play.ps1 -Detach, waits for the title (skipping the intro videos with ESC), clicks UN JUGADOR and plays the first minutes of
 mission 1: select a specialist, move it, open the ESC menu, save, move again, load and check the state came back.
 Frames are read from the game itself (GW_FRAME_DUMP_DIR); they contain game art and stay in -OutDir: never publish them.
 Result: <OutDir>\playtest-report.md with PASS/FAIL per step. Layout assumptions (screen positions, ~28 s landing) are those of the
 Europe 1.1 Spanish build at 640x480; a FAIL on a step after the title can also mean a different language/layout.
#>
param([string]$OutDir = (Join-Path (Get-Location) 'playtest-out'), [string]$Build)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
. (Join-Path $PSScriptRoot 'gwctl.ps1')
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
Get-ChildItem $OutDir -Filter *.png -ErrorAction SilentlyContinue | Remove-Item
$rows = New-Object System.Collections.Generic.List[string]
function Step($name, [bool]$ok, $detail) { $rows.Add("| $name | $(if ($ok) { 'PASS' } else { 'FAIL' }) | $detail |"); Write-Host ("{0,-44} {1}  {2}" -f $name, $(if ($ok) { 'PASS' } else { 'FAIL' }), $detail) }
function Frame($stem) { $p = Snap $OutDir $stem 8000; if (-not $p) { throw "no frame dump for $stem (is GW_FRAME_DUMP_DIR active?)" }; return $p }
# fraction of pixels (0..1) that differ between two 640x480 frames inside a rectangle given in game pixels
function Diff($a, $b, $x, $y, $w, $h) {
    $A = [System.Drawing.Bitmap]::FromFile($a); $B = [System.Drawing.Bitmap]::FromFile($b); $n = 0; $d = 0
    for ($j = $y; $j -lt $y + $h; $j += 2) { for ($i = $x; $i -lt $x + $w; $i += 2) { $n++; $p = $A.GetPixel($i, $j); $q = $B.GetPixel($i, $j)
        if ([math]::Abs($p.R - $q.R) + [math]::Abs($p.G - $q.G) + [math]::Abs($p.B - $q.B) -gt 24) { $d++ } } }
    $A.Dispose(); $B.Dispose(); return $d / $n
}
function Wait-Log($pattern, [int]$sec) { $t = [Diagnostics.Stopwatch]::StartNew(); while ($t.Elapsed.TotalSeconds -lt $sec) { if (Select-String -Path $script:err -Pattern $pattern -Quiet) { return $true }; Start-Sleep -Milliseconds 500 }; return $false }
function Click-G($w, $gx, $gy, $btn = 'L', $hold = 150) { Click $w ($gx / 640.0) ($gy / 480.0) $btn $hold }

# --- start the game
$env:GW_FRAME_DUMP_DIR = $OutDir; $env:GW_VSB16_CAPTURE = Join-Path $OutDir 'sound.pcm'
$playArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $root 'scripts\play.ps1'), '-Detach'); if ($Build) { $playArgs += @('-Build', $Build) }
$gamePid = [int](& powershell @playArgs | Select-Object -Last 1)
$proc = Get-Process -Id $gamePid
$buildDir = if ($Build) { $Build } else { (Get-ChildItem (Join-Path $root 'build') -Directory -Filter 'rebuild-*' | Sort-Object Name | Select-Object -Last 1).FullName }
$script:err = Join-Path $buildDir 'play.stderr.log'
$t0 = Get-Date
$w = [IntPtr]::Zero; $sw = [Diagnostics.Stopwatch]::StartNew()
while ($w -eq [IntPtr]::Zero -and $sw.Elapsed.TotalSeconds -lt 240) { $w = Find-GwWindow 'gw_demo'; Start-Sleep 1 }
Step 'window opens' ($w -ne [IntPtr]::Zero) "$([int]$sw.Elapsed.TotalSeconds) s"
if ($w -eq [IntPtr]::Zero) { $proc.Kill(); throw 'no window' }
# skip the intro videos (ESC skips the video that is playing) until the title menu is ready
$sw.Restart(); $title = $false
while (-not $title -and $sw.Elapsed.TotalSeconds -lt 300) {
    $title = Select-String -Path $script:err -Pattern 'interactive_title_menu_ready' -Quiet
    if (-not $title) { [void][W]::SetForegroundWindow($w); Key 'ESC'; Start-Sleep 3 }
}
Step 'intro videos skippable, title menu ready' $title "$([int]$sw.Elapsed.TotalSeconds) s"
Start-Sleep 3
$f_title = Frame 'title'
$bm = [System.Drawing.Bitmap]::FromFile($f_title); $s = 0; $n = 0; for ($j = 0; $j -lt 480; $j += 8) { for ($i = 0; $i -lt 640; $i += 8) { $c = $bm.GetPixel($i, $j); $s += $c.R + $c.G + $c.B; $n++ } }; $bm.Dispose()
Step 'title frame is rendered (not black)' (($s / $n / 3) -gt 15) ('mean brightness {0:N0}' -f ($s / $n / 3))

# --- new game -> mission
Click-G $w 320 122
$m = Wait-Log 'current_ifc=0035fe9a' 90
Step 'UN JUGADOR -> mission 1 (IFCLevel active)' $m ''
Start-Sleep 30    # landing animation
$f_a = Frame 'mission_a'
# --- select first specialist
Click-G $w 283 276; Start-Sleep 2
$f_sel = Frame 'selected'
$d = Diff $f_a $f_sel 78 378 92 70
Step 'select specialist (portrait/name panel changes)' ($d -gt 0.05) ("changed fraction {0:N2}" -f $d)
# --- move
$f_m0 = Frame 'move_before'
Click-G $w 430 330; Start-Sleep 10
$f_m1 = Frame 'move_after'
$d = Diff $f_m0 $f_m1 255 250 80 50
Step 'move specialist (unit leaves its place)' ($d -gt 0.02) ("changed fraction at origin {0:N2}" -f $d)
# --- menu
[void][W]::SetForegroundWindow($w); Key 'ESC'; Start-Sleep 3
$f_menu = Frame 'esc_menu'
$d = Diff $f_m1 $f_menu 0 0 640 480
Step 'ESC opens the options menu' ($d -gt 0.5) ("whole-frame change {0:N2}" -f $d)
# --- save: pick the slot, type a name, Enter, Guardar
Click-G $w 300 204 'L' 200; Start-Sleep 1
foreach ($k in 'T', 'E', 'S', 'T') { Key $k }; Key 'ENTER'; Start-Sleep 1
Click-G $w 452 225 'L' 250; Start-Sleep 3
$sav = Get-ChildItem $buildDir -Recurse -Filter 'save0.sav' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $t0 } | Select-Object -First 1
Step 'save writes a 343958-byte save file' ($sav -and $sav.Length -eq 343958) $(if ($sav) { "$($sav.Length) bytes" } else { 'not found' })
Click-G $w 312 418 'L' 250; Start-Sleep 3
$f_back = Frame 'back_in_game'
$d = Diff $f_menu $f_back 0 0 640 480
Step 'OK returns to the mission' ($d -gt 0.5) ("whole-frame change {0:N2}" -f $d)
# --- move far, then load
Click-G $w 283 276; Start-Sleep 1; Click-G $w 250 160; Start-Sleep 12
$f_far = Frame 'moved_far'
[void][W]::SetForegroundWindow($w); Key 'ESC'; Start-Sleep 3
Click-G $w 300 204 'L' 200; Start-Sleep 1
Click-G $w 160 225 'L' 250; Start-Sleep 6
$f_loaded = Frame 'after_load'
$dBack = Diff $f_loaded $f_far 200 130 120 100     # where the unit stood after the far move
$dKeep = Diff $f_loaded $f_back 255 280 220 80      # around its position when saved
Step 'load restores the saved state (unit back, selection cleared)' (($dKeep -lt 0.15) -and ($dBack -gt 0.0)) ("vs saved frame {0:N2}, vs far frame {1:N2}" -f $dKeep, $dBack)
# --- stability and sound
$p = Get-Process -Id $gamePid -ErrorAction SilentlyContinue
Step 'process alive and responding after the scenario' ($p -and $p.Responding) $(if ($p) { "ws $([int]($p.WorkingSet64/1MB)) MB, handles $($p.HandleCount)" } else { 'exited' })
$pcm = Join-Path $OutDir 'sound.pcm'
$snd = if (Test-Path $pcm) { (Get-Item $pcm).Length } else { 0 }
Step 'sound reached the virtual SB16 sink (PCM captured)' ($snd -gt 100000) "$snd bytes of PCM"
if ($p) { $p.CloseMainWindow() | Out-Null; Start-Sleep 2; if (-not $p.HasExited) { $p.Kill() } }
$out = New-Object System.Collections.Generic.List[string]
$out.Add('## GWRecomp interactive playtest (mission 1)'); $out.Add('')
$out.Add("- start: $($t0.ToString('yyyy-MM-dd HH:mm:ss')), duration $([int]((Get-Date) - $t0).TotalSeconds) s"); $out.Add('')
$out.Add('| Step | Result | Detail |'); $out.Add('|---|---|---|'); $rows | ForEach-Object { $out.Add($_) }
$out.Add(''); $out.Add('Frames in this folder contain game art and must not be published.')
$out | Set-Content (Join-Path $OutDir 'playtest-report.md') -Encoding utf8
$bad = @($rows | Where-Object { $_ -match '\| FAIL \|' }).Count
Write-Host "`n$($rows.Count - $bad) of $($rows.Count) steps passed. Report: $OutDir\playtest-report.md"
exit ([int]($bad -gt 0))
