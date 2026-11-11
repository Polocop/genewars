<#
 Verify GWRecomp on a clean Windows installation and write a report you can paste into an issue.

   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-clean-machine.ps1 [-InstallMsys2Packages]
        [-GenewarsInstall <GENEWARS folder> -GenewarsCue <file.cue>] [-SkipTests] [-FrameCount 120]

 Always runs: setup, Level A, the classified tests.
 Runs Levels B and C only when you supply your own legitimate game files (-GenewarsInstall and -GenewarsCue, or the
 GENEWARS_INSTALL_DIR / GENEWARS_CUE variables). Nothing is uploaded anywhere; the report contains tool versions, exit codes,
 counts and SHA-256 values of build outputs. It contains no file paths, user names or game data.
 Report: build\verify-report.md
#>
param([switch]$InstallMsys2Packages, [string]$GenewarsInstall, [string]$GenewarsCue, [switch]$SkipTests, [int]$FrameCount = 120)
$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'gwconfig.ps1')
$root = Get-GwRoot
$logs = Join-Path $root 'build\verify-logs'; New-Item -ItemType Directory -Force $logs | Out-Null
$ps = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File')
$rows = New-Object System.Collections.Generic.List[string]
function Run-Step($name, [string[]]$scriptArgs, [string]$file) {
    $log = Join-Path $logs (($name -replace '[^A-Za-z0-9]+', '_') + '.log')
    $t = Get-Date
    & powershell @ps (Join-Path $root $file) @scriptArgs *> $log
    $code = $LASTEXITCODE
    $secs = [math]::Round(((Get-Date) - $t).TotalSeconds)
    $rows.Add("| $name | $(if ($code -eq 0) { 'OK' } else { "exit $code" }) | ${secs}s |")
    Write-Host ("{0,-28} {1}  ({2}s)" -f $name, $(if ($code -eq 0) { 'OK' } else { "exit $code" }), $secs)
    return $code
}

# optional game inputs
if ($GenewarsInstall) { $env:GENEWARS_INSTALL_DIR = $GenewarsInstall }
if ($GenewarsCue)     { $env:GENEWARS_CUE = $GenewarsCue }

$setupArgs = @(); if ($InstallMsys2Packages) { $setupArgs += '-InstallMsys2Packages' }
$cSetup = Run-Step 'setup' $setupArgs 'scripts\setup.ps1'
$cfg = Get-GwConfig
Set-GwEnvironment $cfg
$cA = Run-Step 'level A build' @('-Level', 'A') 'scripts\build.ps1'
$testLine = 'not run'; $cT = $null
if (-not $SkipTests) {
    $cT = Run-Step 'tests' @() 'scripts\test.ps1'
    $tl = Select-String -Path (Join-Path $logs 'tests.log') -Pattern '^modules=' -ErrorAction SilentlyContinue | Select-Object -Last 1
    if ($tl) { $testLine = $tl.Line }
}

$haveGame = $cfg.Install -and $cfg.Cue
$cB = $null; $cC = $null; $lvlB = @()
if ($haveGame) {
    $cB = Run-Step 'level B build' @('-Level', 'B') 'scripts\build.ps1'
    if ($cB -eq 0) {
        $latest = Get-ChildItem -LiteralPath $cfg.WorkRoot -Directory -Filter 'rebuild-*' | Sort-Object Name | Select-Object -Last 1
        if ($latest) {
            $m = Get-Content (Join-Path $latest.FullName 'rebuild_manifest.json') -Raw | ConvertFrom-Json
            $lvlB += "- lifted C (`base.c`) SHA-256: $($m.outputs.base_c_sha256)"
            $lvlB += "- `closure.c` SHA-256: $($m.outputs.closure_c_sha256)"
            $lvlB += "- objects: $(@($m.outputs.objects).Count)"
            $lvlB += "- deterministic executable SHA-256: $($m.outputs.exe_deterministic.sha256)"
            $lvlB += "- reference map: $($m.reference_map); toolchain differences from the reference: $(@($m.toolchain_differences).Count)"
            $expFile = Join-Path $root 'tools\rebuild\expected_levelB.json'
            if (Test-Path $expFile) {
                $e = Get-Content $expFile -Raw | ConvertFrom-Json
                $lvlB += "- lifted C equals the maintainers' reference: $($m.outputs.base_c_sha256 -eq $e.base_c_sha256) (independent of the compiler; a difference means the lifter or its inputs differ)"
                $lvlB += "- executable equals the maintainers' reference: $($m.outputs.exe_deterministic.sha256 -eq $e.deterministic_exe_sha256) (expected to differ if your compiler or linker differ from toolchain.lock.json)"
            }
        }
        $cC = Run-Step 'level C smoke run' @('-Level', 'C', '-SmokeFrames', "$FrameCount") 'scripts\build.ps1'
    }
}

$os = Get-CimInstance Win32_OperatingSystem
$py = if ($cfg.Python) { (& $cfg.Python --version 2>&1) -join '' } else { 'not found' }
$gcc = if ($cfg.Mingw32Bin -and (Test-Path (Join-Path $cfg.Mingw32Bin 'gcc.exe'))) { (& (Join-Path $cfg.Mingw32Bin 'gcc.exe') --version 2>&1 | Select-Object -First 1) } else { 'not found' }
$clang = if ($cfg.ClangX64) { (& $cfg.ClangX64 --version 2>&1 | Select-Object -First 1) } else { 'not found' }
$commit = (& git -C $root rev-parse --short HEAD 2>$null)
$out = New-Object System.Collections.Generic.List[string]
$out.Add('## GWRecomp clean-machine verification'); $out.Add('')
$out.Add("- date (UTC): $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm'))"); $out.Add("- commit: $commit")
$out.Add("- Windows: $($os.Caption) build $($os.BuildNumber)"); $out.Add("- $py"); $out.Add("- $gcc"); $out.Add("- $clang")
$out.Add('- reference toolchain: Python 3.13.0, gcc 16.2.0, clang 19.1.5'); $out.Add('')
$out.Add('| Step | Result | Time |'); $out.Add('|---|---|---|'); $rows | ForEach-Object { $out.Add($_) }; $out.Add('')
$out.Add("Tests: $testLine"); $out.Add('')
if ($haveGame) { $out.Add('### Level B output'); $lvlB | ForEach-Object { $out.Add($_) } }
else { $out.Add('Levels B and C were not run: no game inputs were supplied (-GenewarsInstall and -GenewarsCue).') }
$out.Add(''); $out.Add('The scripts, logs under build\verify-logs and this report contain no game data.')
$out | Set-Content -Encoding utf8 (Join-Path $root 'build\verify-report.md')
Write-Host ''; $out | ForEach-Object { Write-Host $_ }
$bad = @($cSetup, $cA, $cT, $cB, $cC) | Where-Object { $_ -ne $null -and $_ -ne 0 }
if ($bad.Count) { Write-Host "`nVerification FAILED in $($bad.Count) step(s); see build\verify-logs." -ForegroundColor Red; exit 1 }
Write-Host "`nVerification completed." -ForegroundColor Green
