[CmdletBinding()]
param()
$GwRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Msys2 = if ($env:MSYS2_ROOT) { $env:MSYS2_ROOT } else { 'C:\msys64' }

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'oracle_sandbox_helpers.ps1')
$verifyScript = Join-Path $PSScriptRoot 'verify_oracle_sandbox.ps1'
$vhdx = "$GwRoot\build\dosboxx_oracle\oracle_c.vhdx"
$stage = "$GwRoot\build\dosboxx_oracle\C"
if ($vhdx -ne "$GwRoot\build\dosboxx_oracle\oracle_c.vhdx" -or $stage -ne "$GwRoot\build\dosboxx_oracle\C") { throw 'Unexpected oracle sandbox path.' }
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from elevated PowerShell.' }
if (-not (Test-Path -LiteralPath $vhdx)) { throw "VHDX missing: $vhdx" }
if (-not (Get-DiskImage -ImagePath $vhdx).Attached) { Mount-DiskImage -ImagePath $vhdx | Out-Null }
$disk = Get-Disk -ErrorAction Stop | Where-Object { $_.Location -ieq $vhdx } | Select-Object -First 1
if (-not $disk) { throw 'Attached VHDX did not resolve to a disk by backing-file path.' }
$part = Get-Partition -DiskNumber $disk.Number | Where-Object Type -ne 'Reserved' | Select-Object -First 1
if (-not $part) { throw 'VHDX has no partition.' }
$vol = Get-Volume -Partition $part
if ($vol.FileSystemLabel -ne 'GWORACLE' -or $vol.FileSystem -ne 'NTFS' -or [long]$vol.Size -gt 16L * 1GB) { throw 'VHDX volume identity/capacity check failed.' }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
$paths = @($part.AccessPaths)
if (-not ($paths | Where-Object { ([string]$_).TrimEnd('\') -ieq $stage.TrimEnd('\') })) {
    Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -AccessPath ($stage.TrimEnd('\') + '\')
}
$verifyBlock = { param($Path) & $verifyScript -Path $Path }.GetNewClosure()
$null = Assert-OracleSandbox -Verifier $verifyBlock -Path $stage
Enable-OracleConfigs -OracleDirectory (Split-Path $stage) -Stage $stage
$null = Assert-OracleSandbox -Verifier $verifyBlock -Path $stage
