$ErrorActionPreference = 'Stop'
$root = 'E:\GWRecomp'
$env:PATH = 'E:\msys64\mingw32\bin;E:\msys64\usr\bin;' + $env:PATH
$env:TEMP = "$root\cache"
$env:TMP = "$root\cache"
$env:TMPDIR = "$root\cache"
$log = "$root\reports\coordination\core_gate_run.log"

function Invoke-Logged([string[]]$Command) {
  if ($Command.Length -gt 1) { $args = $Command[1..($Command.Length-1)]; $out = & $Command[0] @args 2>&1 }
  else { $out = & $Command[0] 2>&1 }
  $code = $LASTEXITCODE
  $out | Out-File -Encoding utf8 -Append $log
  $out | Write-Output
  if ($code -ne 0) { throw "Command failed ($code): $($Command -join ' ')" }
}

Clear-Content -Path $log -ErrorAction SilentlyContinue
Invoke-Logged @('E:\msys64\mingw32\bin\gcc.exe','-std=gnu11','-m32','-c','-w','-include',"$root\build\recomp_catalog_100_recursive_prototypes.h",'-I',"$root\third_party\pcrecomp\runtime\recomp32",'-o',"$root\build\recomp_catalog_100_recursive.o", "$root\build\recomp_catalog_100_recursive.c")
Invoke-Logged @('E:\msys64\mingw32\bin\gcc.exe','-std=gnu11','-m32','-O0','-w','-I',"$root\third_party\pcrecomp\runtime\recomp32",'-I',"$root\build",'-o',"$root\build\test_recomp_batch_rebased.exe", "$root\tests\test_recomp_batch.c")
Invoke-Logged @("$root\build\test_recomp_batch_rebased.exe")
