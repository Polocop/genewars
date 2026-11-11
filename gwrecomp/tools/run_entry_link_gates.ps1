$ErrorActionPreference='Stop'
$root='E:\GWRecomp'
$env:PATH='E:\msys64\mingw32\bin;E:\msys64\usr\bin;'+$env:PATH
$env:TEMP="$root\cache"; $env:TMP="$root\cache"; $env:TMPDIR="$root\cache"
& E:\GeneWarsFX\experiments\dos-re-gw10\.venv\Scripts\python.exe "$root\tools\link_entry_path.py" *> "$root\reports\coordination\entry_path_link_generate.log"
if ($LASTEXITCODE -ne 0) { Get-Content "$root\reports\coordination\entry_path_link_generate.log"; exit $LASTEXITCODE }
& E:\msys64\mingw32\bin\gcc.exe -std=gnu11 -m32 -c -w -I "$root\third_party\pcrecomp\runtime\recomp32" -o "$root\build\entry_path_combined.o" "$root\build\entry_path_combined.c" *> "$root\reports\coordination\entry_path_link_compile.log"
if ($LASTEXITCODE -ne 0) { Get-Content "$root\reports\coordination\entry_path_link_compile.log"; exit $LASTEXITCODE }
E:\GeneWarsFX\experiments\dos-re-gw10\.venv\Scripts\python.exe -c "import json,pathlib; d=json.loads(pathlib.Path(r'$root\evidence\entry_path_link.json').read_text()); assert d['guest_entry_executed'] is False; assert pathlib.Path(r'$root\build\entry_path_combined.o').exists(); print('COMBINED ENTRY OBJECT PASS',d['combined_function_definitions'],'definitions',d['resolved_direct_targets'],'resolved',d['unresolved_direct_targets'],'unresolved')"
exit $LASTEXITCODE
