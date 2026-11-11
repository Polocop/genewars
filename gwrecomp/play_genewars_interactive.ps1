[CmdletBinding()]
param(
    [ValidateRange(0,1000000)][int]$SmokeFrames = 0,
    [string]$InstallRoot = '<GENEWARS_INSTALL_DIR>'
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Exe = Join-Path $Root 'bin\gw_demo_sdl2.exe'
$Guest = Join-Path $Root 'work\ifctitle_creature_probe_guest.bin'
$Manifest = Join-Path $Root 'work\genewars_1_1_install_manifest_creature_probe.tsv'
$Evidence = Join-Path $Root 'evidence'
$Stdout = Join-Path $Evidence 'play_genewars_interactive.stdout.log'
$Stderr = Join-Path $Evidence 'play_genewars_interactive.stderr.log'
foreach ($Required in @($Exe, (Join-Path $Root 'bin\SDL2.dll'), $Guest, $Manifest, $InstallRoot)) {
    if (-not (Test-Path -LiteralPath $Required)) { throw "Required launcher input missing: $Required" }
}
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null
Set-Location -LiteralPath $Root
$env:PATH = "$Root\bin;E:\msys64\mingw32\bin;E:\msys64\usr\bin;$env:PATH"
$env:SDL_VIDEODRIVER = 'windows'
$env:SDL_RENDER_SCALE_QUALITY = '0'
$env:SDL_AUDIODRIVER = 'directsound'
$env:GW_INTERACTIVE_DEMO = '1'
$env:GW_INTERACTIVE_RESILIENT = '1'
$env:GW_INTERACTIVE_QUIET_CONSOLE = '1'
$env:GWRECOMP_IFCLEVEL_CONTINUE = '1'
$env:GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP = '1'
$env:GWRECOMP_IFCLEVEL_HOST_BOUND_TURN = '420'
$env:GW_DEMO_VSYNC = '0'
$env:GW_DEMO_CAP_60 = '0'
$env:GW_TARGET_FPS = '240'
$env:GW_DEMO_PACING = '20'
if ($SmokeFrames -gt 0) { $env:GW_DEMO_MAX_INTERACTIVE_FRAMES = [string]$SmokeFrames }
else { Remove-Item Env:GW_DEMO_MAX_INTERACTIVE_FRAMES -ErrorAction SilentlyContinue }
& $Exe $Guest $InstallRoot $Manifest 1> $Stdout 2> $Stderr
$ExitCode = $LASTEXITCODE
if ($ExitCode -ne 0) {
    Write-Error "GeneWars exited with code $ExitCode. See $Stderr"
    if (Test-Path $Stderr) { Get-Content $Stderr -Tail 24 }
}
else { Write-Host "GeneWars exited with code 0. Logs: $Stdout and $Stderr" }
exit $ExitCode
