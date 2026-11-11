$ErrorActionPreference='Stop'
$root='E:\GWRecomp'
$env:PATH='E:\msys64\mingw32\bin;E:\msys64\usr\bin;'+$env:PATH
$env:TEMP="$root\cache"; $env:TMP="$root\cache"; $env:TMPDIR="$root\cache"
& E:\GeneWarsFX\experiments\dos-re-gw10\.venv\Scripts\python.exe "$root\tools\lift_entry_path.py" *> "$root\reports\coordination\entry_path_lift.log"
if ($LASTEXITCODE -ne 0) { Get-Content "$root\reports\coordination\entry_path_lift.log"; exit $LASTEXITCODE }
& E:\msys64\mingw32\bin\gcc.exe -std=gnu11 -m32 -c -w -I "$root\third_party\pcrecomp\runtime\recomp32" -o "$root\build\entry_path.o" "$root\build\entry_path.c" *> "$root\reports\coordination\entry_path_compile.log"
if ($LASTEXITCODE -ne 0) { Get-Content "$root\reports\coordination\entry_path_compile.log"; exit $LASTEXITCODE }
E:\GeneWarsFX\experiments\dos-re-gw10\.venv\Scripts\python.exe -c "import json,pathlib; d=json.loads(pathlib.Path(r'$root\evidence\entry_path_lifts.json').read_text()); assert d['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'; assert len(d['roots'])==5 and len(d['lifted'])+len(d['missing_or_unsupported'])==5; assert pathlib.Path(r'$root\build\entry_path.o').exists(); print('ENTRY PATH COMPILE PASS',len(d['lifted']),'lifted',len(d['missing_or_unsupported']),'missing/unsupported')"
exit $LASTEXITCODE
