param(
    [string]$GameRoot = '<GENEWARS_INSTALL_DIR>',
    [string]$OutputDir = 'E:\GWRecomp\evidence\terrain_renderer',
    [int]$CameraXQ8 = 20967,
    [int]$CameraYQ8 = 13288,
    [int]$ScaleX = 16,
    [int]$ScaleY = 8,
    [int]$HeightScale = 1,
    [string]$Snapshot = 'E:\GWRecomp\snapshots\turn_435_post_landing.snap'
)
$ErrorActionPreference = 'Stop'
$level = Join-Path $GameRoot 'LEVELS\CONQ001.DAT'
$palette = Join-Path $GameRoot 'DATA\MAIN.PAL'
if (!(Test-Path -LiteralPath $level) -or !(Test-Path -LiteralPath $palette)) { throw 'CONQ001.DAT or MAIN.PAL missing from GameRoot.' }
$levelBytes = [IO.File]::ReadAllBytes($level)
if ($levelBytes.Length -ne 343958 -or [BitConverter]::ToUInt32($levelBytes,0) -ne 0x55336) { throw 'CONQ001 file contract mismatch.' }
if ($levelBytes.Length -le 0x1C5B) { throw 'scenario planet-class byte missing.' }
$planetClass = [int]$levelBytes[0x1C5B]
if ($planetClass -gt 3) { throw "unsupported scenario planet class $planetClass" }
$bankLetter = [char]([int][char]'A' + $planetClass)
$bank = Join-Path $GameRoot ("DATA\B32{0}.DAT" -f $bankLetter)
if (!(Test-Path -LiteralPath $bank)) { throw "scenario requires B32$bankLetter.DAT, not found." }
$work = 'E:\GWRecomp\work\terrain_renderer\input'
New-Item -ItemType Directory -Force -Path $work,$OutputDir | Out-Null
$snapshotScenario = Join-Path $work 'CONQ001.snapshot435.DAT'
& 'E:\GWRecomp\.venv\Scripts\python.exe' 'E:\GWRecomp\tools\terrain_renderer\prepare_snapshot_scenario.py' --scenario $level --snapshot $Snapshot --output $snapshotScenario
if ($LASTEXITCODE -ne 0) { throw "snapshot terrain extraction failed: $LASTEXITCODE" }
$bankCopy = Join-Path $work ("B32{0}.DAT" -f $bankLetter)
$raw = Join-Path $work ("B32{0}.raw" -f $bankLetter)
Copy-Item -LiteralPath $bank -Destination $bankCopy -Force
$decoder = 'E:\GeneWarsFX\builds\phase-2ab-options-transition\decode-rnc.exe'
if (!(Test-Path -LiteralPath $decoder)) { throw 'Validated local RNC1 decoder is unavailable.' }
& $decoder $bankCopy $raw
if ($LASTEXITCODE -ne 0) { throw "RNC1 decode failed: $LASTEXITCODE" }
if ((Get-Item -LiteralPath $raw).Length -ne 163840) { throw 'decoded B32 bank has the wrong size.' }
& 'E:\GWRecomp\tools\terrain_renderer\build_renderer.ps1'
$renderer = 'E:\GWRecomp\work\terrain_renderer\gw_terrain_data_renderer.exe'
foreach ($size in @(@(640,480),@(854,480),@(1280,720),@(2560,1440))) {
    $w=[int]$size[0]; $h=[int]$size[1]
    $prefix=Join-Path $OutputDir ("conq001_{0}x{1}" -f $w,$h)
    & $renderer $snapshotScenario $raw $palette $prefix $w $h $CameraXQ8 $CameraYQ8 $ScaleX $ScaleY $HeightScale
    if ($LASTEXITCODE -ne 0) { throw ('renderer failed for ' + $w + 'x' + $h + ': ' + $LASTEXITCODE) }
}
& 'E:\GWRecomp\.venv\Scripts\python.exe' 'E:\GWRecomp\tools\terrain_renderer\validate_terrain_renderer.py' --game-root $GameRoot --output-dir $OutputDir --snapshot $Snapshot --render-scenario $snapshotScenario --camera-x-q8 $CameraXQ8 --camera-y-q8 $CameraYQ8 --scale-x $ScaleX --scale-y $ScaleY --height-scale $HeightScale --planet-class $planetClass
if ($LASTEXITCODE -ne 0) { throw "validation failed: $LASTEXITCODE" }

