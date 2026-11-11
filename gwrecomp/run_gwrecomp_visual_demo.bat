@echo off
setlocal
cd /d "%~dp0"
set "GWRECOMP_BUILD_IFCLEVEL_DEMO_ONLY=1"
"%~dp0.venv\Scripts\python.exe" "%~dp0tests\test_ifctitle_creature_probe.py"
if errorlevel 1 exit /b %errorlevel%
set "GWRECOMP_BUILD_IFCLEVEL_DEMO_ONLY="
set "GWRECOMP_IFCLEVEL_CONTINUE=1"
set "GWRECOMP_IFCLEVEL_DEMO=1"
set "GWRECOMP_IFCLEVEL_DEMO_MAX_TICKS="
set "PATH=E:\msys64\mingw32\bin;%PATH%"
"%~dp0build\test_ifctitle_visual_demo.exe" "%~dp0work\ifctitle_creature_probe_guest.bin" "<GENEWARS_INSTALL_DIR>" "%~dp0work\genewars_1_1_install_manifest_creature_probe.tsv" >nul 2>&1
exit /b %errorlevel%
