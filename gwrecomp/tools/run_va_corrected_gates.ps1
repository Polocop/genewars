$GwRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Msys2 = if ($env:MSYS2_ROOT) { $env:MSYS2_ROOT } else { 'C:\msys64' }
$GwFx = if ($env:GENEWARSFX_ROOT) { $env:GENEWARSFX_ROOT } else { Join-Path $GwRoot 'third_party\GeneWarsFX' }
$ErrorActionPreference = 'Stop'
$root="$GwRoot"
$env:PATH="$Msys2\mingw32\bin;$Msys2\usr\bin;"+$env:PATH
$env:TEMP="$root\cache"; $env:TMP="$root\cache"; $env:TMPDIR="$root\cache"
$log="$root\reports\coordination\va_corrected_gate.log"
Clear-Content -Path $log -ErrorAction SilentlyContinue

& $Msys2\mingw32\bin\gcc.exe -std=gnu11 -m32 -c -w -include "$root\build\recomp_catalog_100_externs.h" -I "$root\third_party\pcrecomp\runtime\recomp32" -o "$root\build\recomp_catalog_100_corrected.o" "$root\build\recomp_catalog_100.c" *> $log
if ($LASTEXITCODE -ne 0) { Get-Content $log; exit $LASTEXITCODE }

& $Msys2\mingw32\bin\gcc.exe -std=gnu11 -m32 -c -w -I "$root\third_party\pcrecomp\runtime\recomp32" -o "$root\build\recomp_catalog_100_recursive_corrected.o" "$root\build\recomp_catalog_100_recursive.c" *> $log
if ($LASTEXITCODE -ne 0) { Get-Content $log; exit $LASTEXITCODE }

& $Msys2\mingw32\bin\gcc.exe -std=gnu11 -m32 -O0 -w -I "$root\third_party\pcrecomp\runtime\recomp32" -I "$root\build" -o "$root\build\test_recomp_batch_rebased.exe" "$root\tests\test_recomp_batch.c" *> $log
if ($LASTEXITCODE -ne 0) { Get-Content $log; exit $LASTEXITCODE }
& "$root\build\test_recomp_batch_rebased.exe"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& "$GwFx\experiments\dos-re-gw10\.venv\Scripts\python.exe" "$root\tools\validate_oracle_lifts.py"
exit $LASTEXITCODE
