$ErrorActionPreference = 'Stop'
$root='E:\GWRecomp'
$env:PATH='E:\msys64\mingw32\bin;E:\msys64\usr\bin;'+$env:PATH
$env:TEMP="$root\cache"; $env:TMP="$root\cache"; $env:TMPDIR="$root\cache"
$log="$root\reports\coordination\va_corrected_gate.log"
Clear-Content -Path $log -ErrorAction SilentlyContinue

& E:\msys64\mingw32\bin\gcc.exe -std=gnu11 -m32 -c -w -include "$root\build\recomp_catalog_100_externs.h" -I "$root\third_party\pcrecomp\runtime\recomp32" -o "$root\build\recomp_catalog_100_corrected.o" "$root\build\recomp_catalog_100.c" *> $log
if ($LASTEXITCODE -ne 0) { Get-Content $log; exit $LASTEXITCODE }

& E:\msys64\mingw32\bin\gcc.exe -std=gnu11 -m32 -c -w -I "$root\third_party\pcrecomp\runtime\recomp32" -o "$root\build\recomp_catalog_100_recursive_corrected.o" "$root\build\recomp_catalog_100_recursive.c" *> $log
if ($LASTEXITCODE -ne 0) { Get-Content $log; exit $LASTEXITCODE }

& E:\msys64\mingw32\bin\gcc.exe -std=gnu11 -m32 -O0 -w -I "$root\third_party\pcrecomp\runtime\recomp32" -I "$root\build" -o "$root\build\test_recomp_batch_rebased.exe" "$root\tests\test_recomp_batch.c" *> $log
if ($LASTEXITCODE -ne 0) { Get-Content $log; exit $LASTEXITCODE }
& "$root\build\test_recomp_batch_rebased.exe"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& E:\GeneWarsFX\experiments\dos-re-gw10\.venv\Scripts\python.exe "$root\tools\validate_oracle_lifts.py"
exit $LASTEXITCODE
