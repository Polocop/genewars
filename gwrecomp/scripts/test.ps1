<#
 Run the test suite and classify every module (PASS / BLOCKED by a named missing input / KNOWN_FAIL / FAIL).
   powershell -NoProfile -File scripts\test.ps1 [-Filter <substring>] [-Jobs 4] [-TimeoutSeconds 90] [-Markdown docs\TEST_STATUS.md]
 Exit code 0 unless a module fails unexpectedly. BLOCKED and KNOWN_FAIL are printed but do not fail the run.
 No game files are needed; modules that need them are reported as BLOCKED with the missing input named.
#>
param([string]$Filter = '', [int]$Jobs = 4, [int]$TimeoutSeconds = 90, [string]$Markdown, [string]$Json)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'gwconfig.ps1')
$cfg = Get-GwConfig
if (-not $cfg.Python) { throw 'No Python found. Run scripts\setup.ps1 first.' }
Set-GwEnvironment $cfg
$args2 = @((Join-Path $PSScriptRoot 'run_tests.py'), '--jobs', $Jobs, '--timeout', $TimeoutSeconds)
if ($Filter) { $args2 += @('--filter', $Filter) }
if ($Markdown) { $args2 += @('--markdown', $Markdown) }
if ($Json) { $args2 += @('--json', $Json) }
& $cfg.Python @args2
exit $LASTEXITCODE
