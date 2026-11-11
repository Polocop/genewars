@echo off
setlocal
cd /d "%~dp0"
set "GWRECOMP_BUILD_SDL2_INTERACTIVE=1"
".venv\Scripts\python.exe" "tests\test_ifctitle_creature_probe.py"
set "rc=%ERRORLEVEL%"
endlocal & exit /b %rc%
