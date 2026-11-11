<#
 Start the native interactive demo built by scripts\build.ps1 -Level B.
   powershell -NoProfile -File scripts\play.ps1 [-Build <rebuild dir>] [-SmokeFrames N] [-Backend default|terrain_modern]
 -Backend terrain_modern selects the EXPERIMENTAL modern terrain renderer (needs B32 data prepared by tools\terrain_renderer; map clicks disabled).
 -Build defaults to the newest build\rebuild-* directory. -SmokeFrames N makes the program exit after N frames (smoke test).
 Requires GENEWARS_INSTALL_DIR (your own game files). Logs go to <build>\play.stdout.log / play.stderr.log.
#>
param([string]$Build, [ValidateRange(0,1000000)][int]$SmokeFrames = 0, [ValidateSet('default','terrain_modern')][string]$Backend = 'default')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'gwconfig.ps1')
$root = Get-GwRoot
$cfg = Get-GwConfig
Set-GwEnvironment $cfg
function Fail($m) { Write-Host "BLOCKED: $m" -ForegroundColor Red; exit 2 }
if (-not $cfg.Install) { Fail 'GENEWARS_INSTALL_DIR is not set (your own Gene Wars 1.1 GENEWARS folder).' }
if (-not $Build) {
    $latest = Get-ChildItem -LiteralPath $cfg.WorkRoot -Directory -Filter 'rebuild-*' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    if (-not $latest) { Fail "no build found under $($cfg.WorkRoot). Run scripts\build.ps1 -Level B first." }
    $Build = $latest.FullName
}
$manifest = Join-Path $Build 'rebuild_manifest.json'
if (-not (Test-Path $manifest)) { Fail "$Build has no rebuild_manifest.json (not a completed Level B build)." }
$m = Get-Content $manifest -Raw | ConvertFrom-Json
$br = $m.build_root
$exe = Join-Path $br 'bin\gw_demo_sdl2.exe'
$guest = Join-Path $br 'work\ifctitle_creature_probe_guest.bin'
$tsv = Join-Path $br 'work\genewars_1_1_install_manifest_creature_probe.tsv'
foreach ($req in @($exe, (Join-Path $cfg.Mingw32Bin 'SDL2.dll'), $guest, $tsv)) { if (-not (Test-Path -LiteralPath $req)) { Fail "required file missing: $req" } }
$env:PATH = "$(Split-Path $exe);$env:PATH"
$env:SDL_VIDEODRIVER = 'windows'; $env:SDL_RENDER_SCALE_QUALITY = '0'; $env:SDL_AUDIODRIVER = 'directsound'
$env:GW_INTERACTIVE_DEMO = '1'; $env:GW_INTERACTIVE_RESILIENT = '1'; $env:GW_INTERACTIVE_QUIET_CONSOLE = '1'
$env:GWRECOMP_IFCLEVEL_CONTINUE = '1'; $env:GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP = '1'; $env:GWRECOMP_IFCLEVEL_HOST_BOUND_TURN = '420'
$env:GW_DEMO_VSYNC = '0'; $env:GW_DEMO_CAP_60 = '0'; $env:GW_TARGET_FPS = '240'; $env:GW_DEMO_PACING = '20'
if ($Backend -eq 'terrain_modern') {
    $env:GW_RENDER_BACKEND = 'terrain_modern'; $env:GW_DEMO_CAP_60 = '1'; $env:GW_DEMO_PACING = 'native'
    if (-not $env:GW_TERRAIN_WIDTH) { $env:GW_TERRAIN_WIDTH = '2560' }; if (-not $env:GW_TERRAIN_HEIGHT) { $env:GW_TERRAIN_HEIGHT = '1440' }
    if (-not $env:GW_TERRAIN_B32_RAW) { $env:GW_TERRAIN_B32_RAW = Join-Path $br 'work\terrain_renderer\input\B32A.raw' }
}
if ($SmokeFrames -gt 0) { $env:GW_DEMO_MAX_INTERACTIVE_FRAMES = [string]$SmokeFrames } else { Remove-Item Env:GW_DEMO_MAX_INTERACTIVE_FRAMES -ErrorAction SilentlyContinue }
$out = Join-Path $Build 'play.stdout.log'; $err = Join-Path $Build 'play.stderr.log'
Push-Location $br
# Start-Process writes the game's stdout/stderr (TRACE lines) as plain bytes; a plain '2>' redirect in Windows PowerShell 5.1
# would wrap stderr lines in error records and write UTF-16
try {
    $argLine = ('"{0}" "{1}" "{2}"' -f $guest, $cfg.Install, $tsv)
    $p = Start-Process -FilePath $exe -ArgumentList $argLine -WorkingDirectory $br -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    $code = $p.ExitCode
} finally { Pop-Location }
if ($code -ne 0) { Write-Host "GeneWars exited with code $code. Last stderr lines:" -ForegroundColor Red; if (Test-Path $err) { Get-Content $err -Tail 20 } }
exit $code
