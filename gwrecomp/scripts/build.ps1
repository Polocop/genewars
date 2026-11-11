<#
 GWRecomp build, in three levels. A level only reports success for what it actually did.

   -Level A  (default) no game files needed. Verifies the toolchain and pcrecomp, compiles every runtime C unit
                       (host layer) to build\levelA\*.o and checks the independent C components.
   -Level B            needs your game inputs (see tools\rebuild\README_BUILD.md). Runs tools\rebuild\rebuild.ps1 from a
                       clean clone of the COMMITTED repository state: lifts the original executable to C, compiles and links
                       the demo executable. Output: build\rebuild-<timestamp>\ with rebuild_manifest.json.
   -Level C            needs a Level B build. Starts the native executable for a bounded number of frames
                       (scripts\play.ps1 -SmokeFrames) and reports whether it exited cleanly.

   powershell -NoProfile -File scripts\build.ps1 [-Level A|B|C] [-Strict] [-Work <dir>] [-Build <rebuild dir>] [-SmokeFrames 120]
 Level B uses only committed files: commit or stash your edits first if you want them built.
#>
param([ValidateSet('A','B','C')][string]$Level = 'A', [switch]$Strict, [string]$Work, [string]$Build, [int]$SmokeFrames = 120)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'gwconfig.ps1')
$root = Get-GwRoot
$cfg = Get-GwConfig
Set-GwEnvironment $cfg
function Fail($m) { Write-Host "BLOCKED: $m" -ForegroundColor Red; exit 2 }
function Need($v, $name, $hint) { if (-not $v) { Fail "$name is not available. $hint" } }

Need $cfg.Python 'Python' 'Run scripts\setup.ps1.'
Need $cfg.Msys2 'MSYS2 (mingw32)' 'Install MSYS2 and run scripts\setup.ps1 -InstallMsys2Packages, or set MSYS2_ROOT.'
$gcc = Join-Path $cfg.Mingw32Bin 'gcc.exe'
if (-not (Test-Path $gcc)) { Fail "gcc.exe not found at $gcc. Run scripts\setup.ps1 -InstallMsys2Packages." }

if ($Level -eq 'A') {
    $pc = Join-Path $root 'third_party\pcrecomp\runtime\recomp32\recomp_types.h'
    if (-not (Test-Path $pc)) { Fail 'pcrecomp is not set up (third_party\pcrecomp). Run scripts\setup.ps1.' }
    $out = Join-Path $root 'build\levelA'; New-Item -ItemType Directory -Force $out | Out-Null
    $sdl = Join-Path $cfg.Msys2 'mingw32\include\SDL2'
    $ok = @(); $bad = @()
    foreach ($f in Get-ChildItem (Join-Path $root 'runtime') -Filter *.c) {
        $obj = Join-Path $out ($f.BaseName + '.o')
        $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'   # gcc warnings on stderr must not abort (Windows PowerShell 5.1)
        $o = & $gcc -std=gnu11 -m32 -O1 -Wall -c -I (Join-Path $root 'runtime') -I (Join-Path $root 'tests') -I $sdl -o $obj $f.FullName 2>&1
        $rc = $LASTEXITCODE; $ErrorActionPreference = $prevEap
        if ($rc) { $bad += "$($f.Name): $(@($o | Select-String 'error' | Select-Object -First 1))" } else { $ok += $f.Name }
    }
    Write-Host "Level A: compiled $($ok.Count) runtime unit(s): $($ok -join ', ')"
    if ($bad.Count) { Write-Host "Level A: $($bad.Count) unit(s) FAILED:" -ForegroundColor Red; $bad | ForEach-Object { Write-Host "  $_" }; exit 1 }
    Write-Host "Level A OK. Objects in $out. Next: scripts\test.ps1" -ForegroundColor Green
    exit 0
}

# levels B and C need game inputs
foreach ($pair in @(@('Install','GENEWARS_INSTALL_DIR'),@('Cue','GENEWARS_CUE'))) { if (-not $cfg[$pair[0]]) { Fail "$($pair[1]) is not set. Levels B and C need your own game files: see tools\rebuild\README_BUILD.md 'Inputs you must supply'." } }
& $cfg.Python (Join-Path $root 'tools\rebuild\check_inputs.py') --install $cfg.Install --cue $cfg.Cue @(if ($cfg.Map) { '--map'; $cfg.Map })
if ($LASTEXITCODE) { Fail 'required game inputs are missing or differ from the supported build (see list above).' }

if ($Level -eq 'B') {
    if (-not $Work) { $Work = Join-Path $cfg.WorkRoot ('rebuild-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
    $extra = @(); if ($Strict) { $extra += '-Strict' }
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'tools\rebuild\rebuild.ps1') -Work $Work @extra
    if ($LASTEXITCODE) { Write-Host "Level B FAILED (exit $LASTEXITCODE). See $Work\rebuild_manifest.json and build.log." -ForegroundColor Red; exit $LASTEXITCODE }
    Write-Host "Level B OK: $Work" -ForegroundColor Green
    exit 0
}

# Level C
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'play.ps1') -SmokeFrames $SmokeFrames @(if ($Build) { '-Build'; $Build })
if ($LASTEXITCODE) { Write-Host "Level C FAILED (exit $LASTEXITCODE)." -ForegroundColor Red; exit $LASTEXITCODE }
Write-Host "Level C: executable ran $SmokeFrames frames and exited cleanly (this is a smoke run, not a gameplay test)." -ForegroundColor Green
