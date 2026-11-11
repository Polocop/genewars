@echo off
setlocal
cd /d "%~dp0"
set "PATH=%~dp0bin;E:\msys64\mingw32\bin;E:\msys64\usr\bin;%PATH%"
set "SDL_VIDEODRIVER=windows"
set "SDL_RENDER_SCALE_QUALITY=0"
set "SDL_AUDIODRIVER=directsound"
set "GW_INTERACTIVE_DEMO=1"
set "GW_INTERACTIVE_RESILIENT=1"
set "GW_INTERACTIVE_QUIET_CONSOLE=1"
set "GWRECOMP_IFCLEVEL_CONTINUE=1"
set "GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP=1"
set "GWRECOMP_IFCLEVEL_HOST_BOUND_TURN=420"
set "GW_DEMO_VSYNC=0"
set "GW_DEMO_CAP_60=0"
set "GW_TARGET_FPS=240"
set "GW_DEMO_PACING=20"
set "GW_DEMO_MAX_INTERACTIVE_FRAMES="
set "GW_DEMO_MAX_SECONDS="
if not exist "evidence" mkdir "evidence"
if not exist "bin\gw_demo_sdl2.exe" (echo Missing bin\gw_demo_sdl2.exe 1>&2 & exit /b 2)
if not exist "bin\SDL2.dll" (echo Missing bin\SDL2.dll 1>&2 & exit /b 3)
if not exist "work\ifctitle_creature_probe_guest.bin" (echo Missing guest image 1>&2 & exit /b 4)
if not exist "work\genewars_1_1_install_manifest_creature_probe.tsv" (echo Missing 1.1 install manifest 1>&2 & exit /b 5)
"bin\gw_demo_sdl2.exe" "work\ifctitle_creature_probe_guest.bin" "<GENEWARS_INSTALL_DIR>" "work\genewars_1_1_install_manifest_creature_probe.tsv" %* 1>"evidence\play_genewars_interactive.stdout.log" 2>"evidence\play_genewars_interactive.stderr.log"
set "rc=%ERRORLEVEL%"
echo GeneWars exit code %rc%. Logs: evidence\play_genewars_interactive.stdout.log and stderr.log
endlocal & exit /b %rc%

