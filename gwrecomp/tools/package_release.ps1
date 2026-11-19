<#
 Portable release folder from a completed build (scripts\build.ps1 -Level B / tools\rebuild\rebuild.ps1).
   powershell -NoProfile -ExecutionPolicy Bypass -File tools\package_release.ps1 [-Build <rebuild dir>] [-Name GWRecomp-v1.0-win32] [-Test]
 Writes dist\<Name>\ (dist\ is git-ignored):
   gwrecomp.exe             the build's bin\gw_demo_sdl2.exe, renamed (the build keeps its own copy)
   *.dll                    every non-Windows DLL the program needs, found by walking the PE imports with objdump
                            through the MSYS2 mingw32 bin folder; the script fails if any import stays unresolved
   work\                    only the install SHA-256 manifest; gwrecomp.exe makes the guest image (from the player's
                            GW.EXE) and the DOS low-memory image on its first start
   gwrecomp.ini             default settings (zoomout, auto, 120 fps, launcher on); gwrecomp.ini.example; README_INSTALL.txt
   licenses\                SDL2's license and the project's third-party notices
   package_manifest.txt     build id, commit, SHA-256 of every file
 Double-click gwrecomp.exe: the launcher opens (with the folder picker for the player's Gene Wars 1.1 folder).
 -Test starts dist\<Name>\gwrecomp.exe with no arguments and a PATH that holds only Windows folders, checks that the
 launcher window opens and stays up for a few seconds, and closes it.
 The folder holds no game data files and no image of the game executable; gwrecomp.exe itself is the recompiled
 (translated) game program. After a run, work\ also holds files made from the player's copy: package from a fresh
 folder (this script always recreates it), never from one that has been played.
#>
param([string]$Build, [ValidatePattern('^[A-Za-z0-9._-]+$')][string]$Name = 'GWRecomp-v1.0-win32', [switch]$Test)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'scripts\gwconfig.ps1')
$cfg = Get-GwConfig
function Fail($m) { Write-Host "PACKAGE FAILED: $m" -ForegroundColor Red; exit 1 }
if (-not $Build) {
    $latest = Get-ChildItem -LiteralPath $cfg.WorkRoot -Directory -Filter 'rebuild-*' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    if (-not $latest) { Fail "no build under $($cfg.WorkRoot)" }
    $Build = $latest.FullName
}
$manifestPath = Join-Path $Build 'rebuild_manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath)) { Fail "$Build is not a completed build (no rebuild_manifest.json)" }
$bm = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$br = $bm.build_root
$exe = Join-Path $br 'bin\gw_demo_sdl2.exe'
if (-not (Test-Path -LiteralPath $exe)) { Fail "missing $exe" }
$mingwBin = $cfg.Mingw32Bin
if (-not $mingwBin) { Fail 'MSYS2 not found: set MSYS2_ROOT (or Msys2 in gwrecomp.local.json) to the MSYS2 folder (it has mingw32\bin)' }
$objdump = Join-Path $mingwBin 'objdump.exe'
if (-not (Test-Path -LiteralPath $objdump)) { Fail "objdump not found in $mingwBin (MSYS2 mingw32 binutils)" }

# ---- output folder (only ever below <repo>\dist) ----
$distRoot = Join-Path $repo 'dist'
$out = Join-Path $distRoot $Name
New-Item -ItemType Directory -Force $distRoot | Out-Null
if (Test-Path -LiteralPath $out) {
    $full = (Resolve-Path -LiteralPath $out).Path
    if (-not $full.StartsWith((Resolve-Path -LiteralPath $distRoot).Path + '\')) { Fail "refusing to clear $full" }
    Remove-Item -LiteralPath $full -Recurse -Force
}
New-Item -ItemType Directory -Force $out, (Join-Path $out 'work'), (Join-Path $out 'licenses') | Out-Null

# ---- 1. executable ----
Copy-Item -LiteralPath $exe -Destination (Join-Path $out 'gwrecomp.exe')

# ---- 2. DLLs: walk the PE import tables; Windows DLLs stay, the others come from the MSYS2 mingw32 bin folder ----
$sysDirs = @((Join-Path $env:SystemRoot 'SysWOW64'), (Join-Path $env:SystemRoot 'System32'))
function Get-Imports([string]$pe) {
    $o = & $objdump -p $pe 2>$null
    if ($LASTEXITCODE -ne 0) { Fail "objdump could not read $pe" }
    $fmt = ($o | Select-String 'file format (\S+)' | Select-Object -First 1).Matches.Groups[1].Value
    if ($fmt -and $fmt -ne 'pei-i386') { Fail "$pe is $fmt; the game is 32-bit (pei-i386) and needs 32-bit DLLs" }
    return @($o | Select-String 'DLL Name:\s*(\S+)' | % { $_.Matches.Groups[1].Value })
}
function Test-SystemDll([string]$n) {
    if ($n -match '^(api|ext)-ms-') { return $true }
    foreach ($d in $sysDirs) { if (Test-Path -LiteralPath (Join-Path $d $n)) { return $true } }
    return $false
}
$queue = New-Object System.Collections.Queue; $queue.Enqueue((Join-Path $out 'gwrecomp.exe'))
$seen = @{}; $copied = @(); $system = @{}
while ($queue.Count) {
    $pe = $queue.Dequeue()
    foreach ($dll in (Get-Imports $pe)) {
        $k = $dll.ToLowerInvariant(); if ($seen[$k]) { continue }; $seen[$k] = 1
        $local = Join-Path $mingwBin $dll
        if (Test-Path -LiteralPath $local) {     # a MinGW / SDL runtime DLL: ship it (even if Windows has one by that name)
            Copy-Item -LiteralPath $local -Destination (Join-Path $out $dll); $copied += $dll
            $queue.Enqueue((Join-Path $out $dll)); continue
        }
        if (Test-SystemDll $dll) { $system[$k] = $dll; continue }
        Fail "unresolved import $dll (needed by $(Split-Path -Leaf $pe)); not in Windows nor in $mingwBin"
    }
}
# every import of every shipped PE must now be either next to gwrecomp.exe or a Windows DLL
foreach ($pe in Get-ChildItem -LiteralPath $out -File | ? { $_.Extension -in '.exe', '.dll' }) {
    foreach ($dll in (Get-Imports $pe.FullName)) {
        if (-not (Test-Path -LiteralPath (Join-Path $out $dll)) -and -not (Test-SystemDll $dll)) { Fail "$($pe.Name) imports $dll, which is not in the folder" }
    }
}

# ---- runtime inputs of the build (read by the program at start) ----
# Only the install SHA-256 manifest (hashes and file names, no game bytes). gwrecomp.exe makes the two other inputs
# on its first start: work\ifctitle_creature_probe_guest.bin from the player's own GW.EXE and
# work\ifctitle_startup_lowmem.bin (DOS structures only). The program also writes work\*.bin evidence files of its own
# while it runs; none of them is shipped.
$inputs = @('genewars_1_1_install_manifest_creature_probe.tsv')
foreach ($f in $inputs) {
    $src = Join-Path $br "work\$f"
    if (-not (Test-Path -LiteralPath $src)) { Fail "missing build input $src" }
    Copy-Item -LiteralPath $src -Destination (Join-Path $out "work\$f")
}
$extra = @(Get-ChildItem -LiteralPath (Join-Path $out 'work') -Recurse -File | ? { $_.Name -notin $inputs })
if ($extra) { Fail "unexpected files in work\: $($extra.Name -join ', ')" }

# ---- 3. settings, documentation, licenses ----
Copy-Item -LiteralPath (Join-Path $repo 'gwrecomp.ini.example') -Destination $out
@'
; GWRecomp settings. The launcher (double-click gwrecomp.exe) writes every change here; see gwrecomp.ini.example.
mode = zoomout
resolution = auto
fullscreen = 0
fps = 120
filter = sharp
clean_horizon = 1
water_effects = 1
enhanced_audio = 1
launcher = 1
; launcher language: es, en or auto (Windows display language); also the ES / EN buttons in the launcher
language = auto
skip_intro = 0
; your Gene Wars 1.1 folder (the launcher's CHANGE / CAMBIAR button fills this in)
; data_dir = C:\Juegos\GENEWARS
'@ -replace "`r?`n", "`r`n" | Set-Content -LiteralPath (Join-Path $out 'gwrecomp.ini') -Encoding ascii   # ends with a line break
$sdlLicense = Join-Path (Split-Path -Parent $mingwBin) 'share\licenses\SDL2\LICENSE.txt'
if (Test-Path -LiteralPath $sdlLicense) { Copy-Item -LiteralPath $sdlLicense -Destination (Join-Path $out 'licenses\SDL2-LICENSE.txt') }
else { Fail "SDL2 license not found at $sdlLicense" }
Copy-Item -LiteralPath (Join-Path $repo 'THIRD_PARTY_NOTICES.md') -Destination (Join-Path $out 'licenses')
$readme = @'
GWRecomp - Gene Wars recompilado de forma nativa para Windows
=============================================================

QUÉ NECESITAS
  Tu propia copia de Gene Wars 1.1 (Bullfrog / Electronic Arts, 1996) INSTALADA: la carpeta GENEWARS que crea el
  instalador original del juego. GWRecomp no incluye los gráficos, sonidos, vídeos ni niveles del juego
  (lee los de tu carpeta; mira también el AVISO del final sobre la carpeta work\).
  Al arrancar, el programa comprueba con SHA-256 los archivos de esa carpeta (versión 1.1, edición europea) y solo
  la lee: nunca la modifica.

QUÉ CARPETAS HACEN FALTA
  La carpeta GENEWARS completa, tal como queda tras instalar el juego desde el CD:
    DATA, LEVELS, SOUND, INTRO      (las que comprueba el lanzador)
    ANIMS, LDATA, S, SPEECH, SAVE   (también se leen y se verifican)
    y los archivos sueltos de esa carpeta (GENEWARS.EXE, GW.EXE, CONFIG.INI, SOUND.INI, ...)
  Si solo tienes el CD sin instalar, instala el juego con su INSTALL.BAT (por ejemplo en DOSBox) y usa la carpeta
  GENEWARS resultante, o copia la de una instalación existente.

CÓMO EMPEZAR
  1. Descomprime esta carpeta donde quieras (que puedas escribir en ella: aquí se guardan tus partidas y registros).
  2. Haz doble clic en gwrecomp.exe. Se abre el lanzador.
  3. Pulsa CAMBIAR (abajo a la derecha) y elige tu carpeta GENEWARS. Las cuatro marcas DATA / LEVELS / SOUND / INTRO
     deben ponerse en verde.
  4. INICIAR JUEGO (menú original), CONTINUAR ÚLTIMA PARTIDA, o en la pestaña MISIONES elige una y JUGAR MISIÓN.
     La imagen (modo de vista, resolución, filtro...) se ajusta en la pestaña GRÁFICOS.
  Todo lo que cambies en el lanzador se guarda en gwrecomp.ini, junto a gwrecomp.exe.

TECLAS EN PARTIDA
  F7 filtro (nítido / EPX / CRT)   F8 turbo 1x/2x/4x   TAB (mantener) turbo 4x   Rueda zoom   Inicio zoom 1x
  F10 soltar el ratón   WASD / flechas / botón central desplazan el mapa   ESC opciones del juego

MÚSICA DEL CD
  Opcional: pon en gwrecomp.ini la línea  cd_cue = C:\ruta\a\tu\imagen\genewars.cue  (tu propia imagen del CD).

DÓNDE QUEDA CADA COSA
  work\dos_vfs_overlay\save\   tus partidas guardadas
  play.stdout.log, play.stderr.log, gw_flags.log   registros de la última sesión
  gwrecomp.ini                 configuración (gwrecomp.ini.example explica cada clave)

PRIMER ARRANQUE
  La primera vez que entras en el juego, gwrecomp.exe prepara en work\ dos archivos que necesita: los genera a partir
  de TU GW.EXE (el de la carpeta GENEWARS, comprobado por SHA-256) y de estructuras de DOS propias. Tarda un momento y
  solo ocurre una vez. Esos archivos salen de tu copia del juego: no los compartas.

AVISO
  gwrecomp.exe es una traducción a código nativo del programa original de Gene Wars; no contiene los archivos de datos
  del juego (gráficos, sonidos, vídeos, niveles), que se leen siempre de tu propia carpeta GENEWARS.
  Licencias de terceros en licenses\ (SDL2: zlib).


GWRecomp - Gene Wars natively recompiled for Windows (English)
==============================================================

WHAT YOU NEED
  Your own INSTALLED copy of Gene Wars 1.1 (Bullfrog / Electronic Arts, 1996): the GENEWARS folder made by the
  game's original installer (European edition). GWRecomp includes none of the game's graphics, sounds, videos or
  levels; it reads them from your folder, checks them with SHA-256 and never modifies them.
  The whole folder is needed: DATA, LEVELS, SOUND, INTRO (checked by the launcher), ANIMS, LDATA, S, SPEECH, SAVE and
  the loose files (GENEWARS.EXE, GW.EXE, CONFIG.INI, SOUND.INI, ...). With only the CD, install the game with its
  INSTALL.BAT (for example in DOSBox) and use the resulting GENEWARS folder.

HOW TO START
  1. Unzip this folder anywhere you can write (your saves and logs go here).
  2. Double-click gwrecomp.exe. The launcher opens; ES / EN at the top switches its language.
  3. Press CHANGE (bottom right) and choose your GENEWARS folder. DATA / LEVELS / SOUND / INTRO must turn green.
  4. START GAME (original menu), CONTINUE LAST GAME, or pick one in the MISSIONS tab and PLAY MISSION.
     The picture (view mode, resolution, filter...) is set in the GRAPHICS tab.
  Everything you change in the launcher is saved in gwrecomp.ini, next to gwrecomp.exe.

IN-GAME KEYS
  F7 filter (sharp / EPX / CRT)   F8 turbo 1x/2x/4x   TAB (hold) turbo 4x   Wheel zoom   Home zoom 1x
  F10 release the mouse   WASD / arrows / middle button scroll the map   ESC game options

CD MUSIC
  Optional: add  cd_cue = C:\path\to\your\genewars.cue  (your own CD image) to gwrecomp.ini.

FIRST START
  The first time you enter the game, gwrecomp.exe makes two files in work\ from YOUR GW.EXE (checked by SHA-256).
  It takes a moment and happens once. Those files come from your copy of the game: do not share them.

NOTICE
  gwrecomp.exe is a native-code translation of the original Gene Wars program; it contains none of the game's data
  files (graphics, sounds, videos, levels), which are always read from your own GENEWARS folder. Gene Wars is
  (c) Bullfrog Productions / Electronic Arts; GWRecomp is unaffiliated with them. Third-party licenses in licenses\
  (SDL2: zlib).
'@
[IO.File]::WriteAllText((Join-Path $out 'README_INSTALL.txt'), ($readme -replace "`r?`n", "`r`n"), (New-Object Text.UTF8Encoding $true))

# ---- package manifest ----
$commit = try { (& git -C $repo rev-parse HEAD 2>$null) } catch { '' }
$lines = @("GWRecomp package $Name", "build $($bm.build_id) commit-requested $($bm.requested_commit) repo-head $commit", "packaged $(Get-Date -Format s)",
           "bundled DLLs: $(($copied | Sort-Object) -join ', ')", "Windows DLLs used: $(($system.Values | Sort-Object) -join ', ')", '')
Get-ChildItem -LiteralPath $out -Recurse -File | Sort-Object FullName | % {
    $lines += "{0}  {1}  {2}" -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Length, $_.FullName.Substring($out.Length + 1) }
$lines | Set-Content -LiteralPath (Join-Path $out 'package_manifest.txt') -Encoding ascii
Write-Host "package: $out"
Write-Host "bundled DLLs: $(($copied | Sort-Object) -join ', ')"
Write-Host "Windows DLLs: $(($system.Values | Sort-Object) -join ', ')"

# ---- 4. clean-PATH start test ----
if ($Test) {
    Get-Process gwrecomp -ErrorAction SilentlyContinue | Stop-Process -Force
    $before = @{}; Get-ChildItem -LiteralPath $out -Recurse -Force | % { $before[$_.FullName] = 1 }
    $iniBytes = [IO.File]::ReadAllBytes((Join-Path $out 'gwrecomp.ini'))
    $psi = New-Object Diagnostics.ProcessStartInfo (Join-Path $out 'gwrecomp.exe')
    $psi.UseShellExecute = $false; $psi.WorkingDirectory = $env:SystemRoot   # started from somewhere else, as from a shortcut
    $keep = 'SystemRoot', 'windir', 'SystemDrive', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'HOMEDRIVE', 'HOMEPATH',
            'COMPUTERNAME', 'USERNAME', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'OS', 'ComSpec', 'PATHEXT', 'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)'
    $psi.EnvironmentVariables.Clear()
    foreach ($k in $keep) { $v = [Environment]::GetEnvironmentVariable($k); if ($v) { $psi.EnvironmentVariables[$k] = $v } }
    $psi.EnvironmentVariables['PATH'] = "$env:SystemRoot\System32;$env:SystemRoot;$env:SystemRoot\System32\Wbem"
    $p = [Diagnostics.Process]::Start($psi)
    $sw = [Diagnostics.Stopwatch]::StartNew(); $title = ''
    while ($sw.Elapsed.TotalSeconds -lt 20 -and -not $p.HasExited) { Start-Sleep -Milliseconds 500; $p.Refresh(); if ($p.MainWindowHandle -ne 0) { $title = $p.MainWindowTitle; break } }
    if ($title) { Start-Sleep 3; $p.Refresh() }
    $alive = -not $p.HasExited
    if ($alive) { [void]$p.CloseMainWindow(); if (-not $p.WaitForExit(15000)) { $p.Kill(); [void]$p.WaitForExit(5000) } }
    # leave the folder as packaged: drop what the test run created (logs, evidence\) and restore gwrecomp.ini
    Get-ChildItem -LiteralPath $out -Recurse -Force | Sort-Object { $_.FullName.Length } -Descending |
        ? { -not $before[$_.FullName] -and $_.FullName.StartsWith($out + '\') } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    [IO.File]::WriteAllBytes((Join-Path $out 'gwrecomp.ini'), $iniBytes)
    if (-not $title -or -not $alive) { Fail "clean-PATH start: no launcher window (exited=$($p.HasExited) code=$(if($p.HasExited){$p.ExitCode}))" }
    Write-Host "clean-PATH start: window '$title' opened and stayed up; closed with exit code $($p.ExitCode)" -ForegroundColor Green
}
