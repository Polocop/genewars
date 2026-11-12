<#
 Mission-2 creature scenario (select a creature, give it a ground order, use the genetic engineer on it), with REAL mouse input.
   powershell -NoProfile -ExecutionPolicy Bypass -File tools\interactive\creatures.ps1 -DumpDir <dir> -TraceFile <file> [-Rounds 4]

 Preconditions (not automated here, see docs/ALPHA.md): the game was started with GW_FRAME_DUMP_DIR=<DumpDir> and GW_ORDER_TRACE=<TraceFile>,
 and mission 2 is running with the extractor, the distributor and the genetic pod BUILT and the pod's first creature type available
 (load a save made at that point, or build them by hand). The 640x480 screen positions are those of the Europe 1.1 Spanish build.
 What it does and reports (PASS/FAIL, from the game's own state in the trace, not only from the picture):
   1. selects the pod, presses its breed button, finds the new mule on the frame difference;
   2. hovers the mule until the original picker commits it (MapDisplay+0x18), clicks it -> selectedPlSpec must equal the mule;
   3. clicks the ground -> the 11-byte action packet must change (a move order) and the mule must leave its place;
   4. selects Jon (genetic engineer) by his portrait, clicks a mule -> an action packet with Jon selected must appear.
 Frames contain game art and stay in <DumpDir>: never publish them. The trace holds only addresses and small integers.
#>
param([Parameter(Mandatory)][string]$DumpDir, [Parameter(Mandatory)][string]$TraceFile, [int]$Rounds = 4)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
. (Join-Path $PSScriptRoot 'gwctl.ps1')
$rows = New-Object System.Collections.Generic.List[string]
function Step($n, [bool]$ok, $d) { $rows.Add("| $n | $(if ($ok) { 'PASS' } else { 'FAIL' }) | $d |"); Write-Host ("{0,-52} {1}  {2}" -f $n, $(if ($ok) { 'PASS' } else { 'FAIL' }), $d) }
function GW { Find-GwWindow 'gw_demo' }
function T { $l = Get-Content $TraceFile -Tail 1; $d = @{}; foreach ($t in $l -split ' ') { if ($t -match '=') { $k, $v = $t -split '=', 2; $d[$k] = $v } }; $d }
function Cl($x, $y, $b = 'L') { Click (GW) ($x / 640.0) ($y / 480.0) $b 150 }
function Down-Up([string]$b = 'L') { $dn, $up = if ($b -eq 'R') { 8, 16 } else { 2, 4 }; [W]::mouse_event($dn, 0, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 90; [W]::mouse_event($up, 0, 0, 0, [UIntPtr]::Zero) }
function Sn($stem) { Snap $DumpDir $stem 15000 }
# mule-coloured pixels that were not in the 'before' frame: centroid
function Find-New($png, $before) {
    $a = [System.Drawing.Bitmap]::FromFile($png); $b = [System.Drawing.Bitmap]::FromFile($before); $sx = 0; $sy = 0; $n = 0
    for ($y = 4; $y -lt 440; $y++) { for ($x = 140; $x -lt 630; $x++) { $c = $a.GetPixel($x, $y)
        if ($c.R -gt 90 -and $c.G -lt 66 -and $c.B -lt 62 -and $c.R -gt $c.G * 1.7) { $d = $b.GetPixel($x, $y); if (-not ($d.R -gt 90 -and $d.G -lt 66 -and $d.B -lt 62 -and $d.R -gt $d.G * 1.7)) { $sx += $x; $sy += $y; $n++ } } } }
    $a.Dispose(); $b.Dispose(); if ($n -lt 6) { return $null }; return @{ X = [int]($sx / $n); Y = [int]($sy / $n) } }
function Probe($cx, $cy, $skip) {
    foreach ($r in 0, 5, 10, 16, 24, 32, 44) { foreach ($dy in -$r, 0, $r) { foreach ($dx in -$r, 0, $r) {
        Move-Mouse (GW) (($cx + $dx) / 640.0) (($cy + $dy) / 480.0)
        for ($k = 0; $k -lt 5; $k++) { Start-Sleep -Milliseconds 55; $c = (T)['map18']; if ($c -ne '00000000' -and ($skip -notcontains $c)) { return $c } } } } }
    return $null }
if (-not (Test-Path $TraceFile)) { throw 'trace file missing: start the game with GW_ORDER_TRACE' }
[void](Focus-Window (GW))
$static = @((T)['selectedPlSpec'], '0033d2fc') # the pod/building candidates already seen: ignore as 'the mule'
$ok1 = $false; $ok2 = $false; $ok3 = $false; $ok4 = $false; $detail3 = ''; $detail4 = ''
for ($round = 1; $round -le $Rounds -and -not ($ok2 -and $ok3 -and $ok4); $round++) {
    Write-Host "--- round $round"
    Cl 484 55; Start-Sleep 2; $bf = Sn "c${round}_0pod"
    if (-not $bf) { throw 'no frame dump' }
    Cl 40 356; Start-Sleep 3; $af = Sn "c${round}_1bred"
    $m = Find-New $af $bf; if (-not $m) { Write-Host 'no new creature seen this round'; continue }
    $ok1 = $true
    $cand = Probe $m.X $m.Y $static; if (-not $cand) { Write-Host 'picker never reported the creature'; continue }
    Down-Up; Start-Sleep 1.2
    $ok2 = ((T)['selectedPlSpec'] -eq $cand)
    if (-not $ok2) { continue }
    $before = (T)['packet']; $n0 = (Get-Content $TraceFile).Count
    $gx = 330 + 20 * $round; Move-Mouse (GW) ($gx / 640.0) (300 / 480.0); Start-Sleep -Milliseconds 300; Down-Up
    Start-Sleep 12; $arr = Sn "c${round}_2moved"
    $pk = @(Get-Content $TraceFile | Select-Object -Skip $n0 | ForEach-Object { ($_ -split 'packet=')[1] } | Where-Object { $_ -ne '0000000000000000000000' } | Select-Object -Unique)
    $ok3 = ($pk.Count -ge 1); $detail3 = "$($pk.Count) action packet(s), first $($pk[0])"
    # Jon (genetic engineer) is the third portrait in the mission-2 start: use him on a creature
    Cl 36 275; Start-Sleep 1.2; $jon = (T)['selectedPlSpec']
    if ($jon -ne $cand -and $jon -ne '00000000') {
        $n1 = (Get-Content $TraceFile).Count
        $c2 = Probe $m.X $m.Y ($static + $jon)
        if ($c2) { Down-Up; Start-Sleep 8
            $pj = @(Get-Content $TraceFile | Select-Object -Skip $n1 | Where-Object { $_ -match "selectedPlSpec=$jon" } | ForEach-Object { ($_ -split 'packet=')[1] } | Where-Object { $_ -ne '0000000000000000000000' } | Select-Object -Unique)
            $ok4 = ($pj.Count -ge 1); $detail4 = "$($pj.Count) packet(s) with Jon selected, first $($pj[0])" }
    }
}
Step 'breed a creature (new sprite appears next to the pod)' $ok1 ''
Step 'picker commits the creature, click selects it' $ok2 'selectedPlSpec equals the picker candidate'
Step 'ground click on the selected creature emits an action packet' $ok3 $detail3
Step 'genetic engineer targeting a creature emits an action packet' $ok4 $detail4
$out = @('## GWRecomp creature scenario (mission 2)', '', '| Step | Result | Detail |', '|---|---|---|') + $rows + @('', 'Frames contain game art: do not publish.')
$out | Set-Content (Join-Path $DumpDir 'creatures-report.md') -Encoding utf8
exit ([int](@($rows | Where-Object { $_ -match '\| FAIL \|' }).Count -gt 0))
