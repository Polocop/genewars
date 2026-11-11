$ErrorActionPreference = 'Stop'
$root = 'E:\GWRecomp'
. (Join-Path $root 'tools\oracle_sandbox_helpers.ps1')
$setup = Get-Content -LiteralPath (Join-Path $root 'tools\setup_oracle_vhdx_admin.ps1') -Raw
$mountScript = Get-Content -LiteralPath (Join-Path $root 'tools\mount_oracle_vhdx_admin.ps1') -Raw
$compatScript = Get-Content -LiteralPath (Join-Path $root 'tools\setup_oracle_vhdx.ps1') -Raw
if ($setup -notmatch 'Assert-OracleSandbox' -or $mountScript -notmatch 'Assert-OracleSandbox' -or
    $setup -match '(?s)&\s*\([^)]*verify_oracle_sandbox[^)]*\).*?\$LASTEXITCODE' -or
    $mountScript -match '(?s)&\s*\([^)]*verify_oracle_sandbox[^)]*\).*?\$LASTEXITCODE' -or
    $compatScript -match '\$LASTEXITCODE') {
    throw 'Setup/mount/compatibility entrypoints must use PowerShell-native verification and must not interpret residual LASTEXITCODE.'
}

# Simulate a stale nonzero native process result before a successful PowerShell
# verifier. Success must be determined by normal completion, not that variable.
$global:LASTEXITCODE = 71
$successVerifier = { param([string]$Path) 'ORACLE_SANDBOX_VERIFIED = YES' }
$success = Assert-OracleSandbox -Verifier $successVerifier -Path 'E:\synthetic\stage'
if (-not $success[-1]) { throw 'Successful verifier did not return PASS.' }
if ($global:LASTEXITCODE -ne 71) { throw 'Test precondition changed unexpectedly; stale LASTEXITCODE did not remain.' }

$failureVerifier = { param([string]$Path) throw 'synthetic verification failure' }
$failed = $false
try { $null = Assert-OracleSandbox -Verifier $failureVerifier -Path 'E:\synthetic\stage' }
catch { $failed = $_.Exception.Message -match 'synthetic verification failure' }
if (-not $failed) { throw 'Verifier exception was not treated as failure.' }

# Synthetic seed fixture: a pending restore copies only missing eligible files;
# a second restore is a no-op and does not rewrite identical staging data.
$buildRoot = Join-Path $root 'build'
$fixture = Join-Path $buildRoot ('oracle_sandbox_setup_test_' + [guid]::NewGuid().ToString('N'))
if (-not ([IO.Path]::GetFullPath($fixture).StartsWith([IO.Path]::GetFullPath($buildRoot), [StringComparison]::OrdinalIgnoreCase))) { throw 'Unsafe fixture path.' }
try {
    $seed = Join-Path $fixture 'seed'; $stage = Join-Path $fixture 'stage'
    New-Item -ItemType Directory -Path (Join-Path $seed 'GENEWARS'),(Join-Path $stage 'GENEWARS') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $seed 'GENEWARS\MAIN.EXE') -Value 'synthetic-main' -NoNewline
    Set-Content -LiteralPath (Join-Path $seed 'GENEWARS\config.ini') -Value 'synthetic-config' -NoNewline
    Set-Content -LiteralPath (Join-Path $seed 'ADDRESS.TXT') -Value 'must not be restored' -NoNewline
    $firstCount = Restore-OracleSeedSafely -Seed $seed -Stage $stage
    $stamp = (Get-Item -LiteralPath (Join-Path $stage 'GENEWARS\MAIN.EXE')).LastWriteTimeUtc
    $secondCount = Restore-OracleSeedSafely -Seed $seed -Stage $stage
    if ($firstCount -ne 2 -or $secondCount -ne 0 -or -not (Test-OracleSeedRestored -Seed $seed -Stage $stage)) { throw 'Synthetic seed restore/idempotence postcondition failed.' }
    if (Test-Path -LiteralPath (Join-Path $stage 'ADDRESS.TXT')) { throw 'Runaway ADDRESS.TXT was restored from seed.' }
    if ((Get-Item -LiteralPath (Join-Path $stage 'GENEWARS\MAIN.EXE')).LastWriteTimeUtc -ne $stamp) { throw 'Second restore rewrote an existing file.' }
} finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'ORACLE SANDBOX SETUP REGRESSION: PASS (stale LASTEXITCODE ignored; verifier throw propagated)'
