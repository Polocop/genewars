@echo off
setlocal
cd /d "%~dp0"
set "PATH=E:\msys64\mingw32\bin;E:\msys64\usr\bin;%PATH%"
set "GW_INTERACTIVE_DEMO=1"
set "GW_INTERACTIVE_QUIET_CONSOLE=1"
set "GW_INTERACTIVE_RESILIENT=1"
set "GWRECOMP_IFCLEVEL_CONTINUE=1"
set "GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP=1"
set "GWRECOMP_IFCLEVEL_HOST_BOUND_TURN=420"
set "GW_DEMO_VSYNC=0"
set "GW_DEMO_CAP_60=1"
set "GW_DEMO_PACING=native"
set "GW_RENDER_BACKEND=terrain_modern"
if not defined GW_TERRAIN_WIDTH set "GW_TERRAIN_WIDTH=2560"
if not defined GW_TERRAIN_HEIGHT set "GW_TERRAIN_HEIGHT=1440"
if not defined GW_TERRAIN_B32_RAW set "GW_TERRAIN_B32_RAW=%~dp0work\terrain_renderer\input\B32A.raw"
rem Experimental terrain projection; map clicks remain disabled until its inverse
rem projection is verified against GeneWars' original picker.
"bin\gw_demo_sdl2.exe" "work\ifctitle_creature_probe_guest.bin" "<GENEWARS_INSTALL_DIR>" "work\genewars_1_1_install_manifest_creature_probe.tsv"
set "rc=%ERRORLEVEL%"
endlocal & exit /b %rc%
