$GwRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Msys2 = if ($env:MSYS2_ROOT) { $env:MSYS2_ROOT } else { 'C:\msys64' }
$GwFx = if ($env:GENEWARSFX_ROOT) { $env:GENEWARSFX_ROOT } else { Join-Path $GwRoot 'third_party\GeneWarsFX' }
$ErrorActionPreference='Stop'
$root="$GwRoot"
$env:PATH="$Msys2\mingw32\bin;$Msys2\usr\bin;"+$env:PATH
$env:TEMP="$root\cache"; $env:TMP="$root\cache"; $env:TMPDIR="$root\cache"
& "$GwFx\experiments\dos-re-gw10\.venv\Scripts\python.exe" "$root\tools\lift_entry_closure.py" *> "$root\reports\coordination\entry_path_closure_generate.log"
if ($LASTEXITCODE -ne 0) { Get-Content "$root\reports\coordination\entry_path_closure_generate.log"; exit $LASTEXITCODE }
& $Msys2\mingw32\bin\gcc.exe -std=gnu11 -m32 -c -w -I "$root\third_party\pcrecomp\runtime\recomp32" -o "$root\build\entry_path_closure.o" "$root\build\entry_path_closure.c" *> "$root\reports\coordination\entry_path_closure_compile.log"
if ($LASTEXITCODE -ne 0) { Get-Content "$root\reports\coordination\entry_path_closure_compile.log"; exit $LASTEXITCODE }
& $Msys2\mingw32\bin\nm.exe -u "$root\build\entry_path_closure.o" | Set-Content -Encoding utf8 "$root\evidence\entry_path_closure_undefined_symbols.txt"
& "$GwFx\experiments\dos-re-gw10\.venv\Scripts\python.exe" -c "import json,pathlib; r=pathlib.Path(r'$root'); d=json.loads((r/'evidence/entry_path_closure.json').read_text()); u=(r/'evidence/entry_path_closure_undefined_symbols.txt').read_text(); assert d['guest_entry_executed'] is False; assert d['unresolved_unique_direct_targets']==0; assert '_sub_' not in u; assert (r/'build/entry_path_closure.o').exists(); print('ENTRY CLOSURE PASS',d['newly_lifted_functions'],'new functions',d['combined_function_bodies'],'total function bodies; no unresolved direct call symbols')"
exit $LASTEXITCODE
