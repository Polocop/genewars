<#
 Start the native interactive build made by scripts\build.ps1 -Level B.
   powershell -NoProfile -File scripts\play.ps1 [-Build <rebuild dir>] [-SmokeFrames N] [-Backend default|terrain_modern] [-Detach] [-SkipIntro] [-LoadSave <file.sav>] [-Level <2..24>]
 Without -SmokeFrames this is the ALPHA play mode: real-time window, mouse/keyboard, digital sound (virtual SB16) and, when
 GENEWARS_CUE is set, CD music from your disc image. The intro videos play first (ESC / click skips each one), then the original
 title menu appears. The start still uses the locally generated title snapshot, so it is provisional: see docs/ALPHA.md.
 -Backend terrain_modern selects the EXPERIMENTAL modern terrain renderer (needs B32 data prepared by tools\terrain_renderer; map clicks disabled).
 -SkipIntro cuts the start-up videos at once. -LoadSave <file.sav> goes through the real title flow into mission 1 and then loads that
 save through the original Options > Cargar gadgets (developer aid; your save is copied to slot 1 of the host overlay, the install is untouched).
 -Level N (new game only): on the original mission screen the launcher types the game's own SALMONAXE code and presses S
 N-1 times, so IFCLevel::Update loads the level-N header; you then choose the planet, team and landing yourself. The code
 also enables the game's in-mission cheat keys until the window closes: save at the start, quit, and continue with -LoadSave.
 -OrderLog writes one line per change of the order-related fields (selection, map candidate, action packet) while you click.
 The lines of these three options go to <build root>\gw_flags.log (the console is muted once the game window opens).
 -Build defaults to the newest build\rebuild-* directory. -SmokeFrames N makes the program exit after N frames (smoke test).
 Requires GENEWARS_INSTALL_DIR (your own game files). Logs go to <build>\play.stdout.log / play.stderr.log.
#>
param([string]$Build, [ValidateRange(0,1000000)][int]$SmokeFrames = 0, [ValidateSet('default','terrain_modern')][string]$Backend = 'default', [switch]$Detach, [switch]$SkipIntro, [string]$LoadSave, [switch]$OrderLog, [ValidateRange(0,24)][int]$Level = 0)
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
$env:GWRECOMP_IFCLEVEL_CONTINUE = '1'; $env:GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP = '1'
$alpha = ($SmokeFrames -eq 0)
if ($alpha) {
    # Alpha play mode: no harness bound, the original title menu is driven by the user, 60 fps native pacing
    Remove-Item Env:GWRECOMP_IFCLEVEL_HOST_BOUND_TURN -ErrorAction SilentlyContinue
    $env:GW_INTERACTIVE_START_AT_TITLE = '1'; $env:GW_VSB16 = '1'
    $env:GW_DEMO_VSYNC = '0'; $env:GW_DEMO_CAP_60 = '1'; $env:GW_TARGET_FPS = '60'; $env:GW_DEMO_PACING = 'native'
    if ($cfg.Cue) { $env:GW_CD_AUDIO_CUE = $cfg.Cue } else { Write-Host 'Note: GENEWARS_CUE is not set, so there is no CD music (sound effects only).' -ForegroundColor Yellow }
    # the sound trace is opened for appending: start each session with a fresh file
    $env:GW_VSB16_LOG = Join-Path $Build 'play.sound.log'; Remove-Item -LiteralPath $env:GW_VSB16_LOG -ErrorAction SilentlyContinue
} else {
    $env:GWRECOMP_IFCLEVEL_HOST_BOUND_TURN = '420'
    $env:GW_DEMO_VSYNC = '0'; $env:GW_DEMO_CAP_60 = '0'; $env:GW_TARGET_FPS = '240'; $env:GW_DEMO_PACING = '20'
}
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
    if ($alpha) { $argLine += ' --play' }
    if ($SkipIntro) { $argLine += ' --skip-intro' }
    if ($OrderLog) { $argLine += ' --order-log' }
    if ($Level -gt 1) { if ($LoadSave) { throw '-Level starts a new game; it cannot be combined with -LoadSave' }; $argLine += (' --level {0}' -f $Level) }
    if ($LoadSave) { $argLine += (' --load-save "{0}"' -f (Resolve-Path -LiteralPath $LoadSave).Path) }
    if ($Detach) {   # for automated interactive tests: start the game and return its process id
        $p = Start-Process -FilePath $exe -ArgumentList $argLine -WorkingDirectory $br -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
        Set-Content -LiteralPath (Join-Path $Build 'play.pid') -Value $p.Id -Encoding ascii
        Write-Host "started, pid $($p.Id)"; Pop-Location; exit 0
    }
    $p = Start-Process -FilePath $exe -ArgumentList $argLine -WorkingDirectory $br -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    $code = $p.ExitCode
} finally { Pop-Location }
if ($code -ne 0) { Write-Host "GeneWars exited with code $code. Last stderr lines:" -ForegroundColor Red; if (Test-Path $err) { Get-Content $err -Tail 20 } }
exit $code
