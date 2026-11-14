[CmdletBinding()]
param()
$GwRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Msys2 = if ($env:MSYS2_ROOT) { $env:MSYS2_ROOT } else { 'C:\msys64' }

$ErrorActionPreference = 'Stop'
$root = "$GwRoot"
$oracle = Join-Path $root 'build\dosboxx_oracle'
$stage = Join-Path $oracle 'C'
$vhdx = Join-Path $oracle 'oracle_c.vhdx'
$verifyScript = Join-Path $PSScriptRoot 'verify_oracle_sandbox.ps1'
. (Join-Path $PSScriptRoot 'oracle_sandbox_helpers.ps1')
$verifyBlock = { param($Path) & $verifyScript -Path $Path }.GetNewClosure()
$verifyAllowEmptyBlock = { param($Path) & $verifyScript -Path $Path -AllowEmptyGuestStaging }.GetNewClosure()
$size = 16L * 1GB
if ($root -ne "$GwRoot" -or $stage -ne "$GwRoot\build\dosboxx_oracle\C") { throw 'Refusing unexpected project/staging path' }
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($id)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# A mounted VHDX is never moved or recreated. Complete a pending seed restore
# and config enablement in place, or report ALREADY CONFIGURED only after every
# readiness condition is true.
if (Test-Path -LiteralPath $vhdx -PathType Leaf) {
    $probe = Get-DiskImage -ImagePath $vhdx -ErrorAction Stop
    if ($probe.Attached) {
        $probeDisk = Get-Disk | Where-Object { $_.Location -ieq $vhdx } | Select-Object -First 1
        if ($probeDisk) {
            $probePart = Get-Partition -DiskNumber $probeDisk.Number -ErrorAction Stop | Where-Object Type -ne 'Reserved' | Select-Object -First 1
            if ($probePart) {
                $probePart = Get-Partition -DiskNumber $probeDisk.Number -PartitionNumber $probePart.PartitionNumber
                $expectedAccess = @($probePart.AccessPaths) | Where-Object { ([string]$_).TrimEnd('\') -ieq $stage.TrimEnd('\') }
                if ($expectedAccess) {
                    $null = Assert-OracleSandbox -Verifier $verifyAllowEmptyBlock -Path $stage
                    $seed = Get-ChildItem -LiteralPath $oracle -Directory -Filter 'C.seed.*' -ErrorAction SilentlyContinue |
                        Sort-Object Name -Descending | Select-Object -First 1
                    if ($seed) {
                        $seedBytes = (Get-ChildItem -LiteralPath $seed.FullName -Recurse -File -Force -ErrorAction Stop | Measure-Object -Property Length -Sum).Sum
                        if ($seedBytes -gt 14L * 1GB) { throw "Seed exceeds the 14 GiB restore limit ($seedBytes bytes); seed preserved and not copied." }
                    }
                    $seedWasRestored = $seed -and (Test-OracleSeedRestored -Seed $seed.FullName -Stage $stage)
                    $configsWereReady = Test-OracleConfigsReady -OracleDirectory $oracle -Stage $stage
                    if ($seedWasRestored -and $configsWereReady) {
                        $null = Assert-OracleSandbox -Verifier $verifyBlock -Path $stage
                        Write-Host 'ALREADY CONFIGURED'
                        return
                    }
                    if (-not $isAdmin) { throw 'Verified VHDX needs seed/config repair. Re-run as administrator to complete the pending setup.' }
                    if (-not $seed) { throw 'VHDX is mounted but no preserved C.seed.* exists; refusing to claim full setup.' }
                    if (-not $seedWasRestored) {
                        $copied = Restore-OracleSeedSafely -Seed $seed.FullName -Stage $stage
                        Write-Host "SEED RESTORE PASS; files copied=$copied"
                    }
                    $null = Assert-OracleSandbox -Verifier $verifyBlock -Path $stage
                    Enable-OracleConfigs -OracleDirectory $oracle -Stage $stage
                    $null = Assert-OracleSandbox -Verifier $verifyBlock -Path $stage
                    if (-not (Test-OracleSeedRestored -Seed $seed.FullName -Stage $stage)) { throw 'Seed/staging postcondition failed.' }
                    if ($seedWasRestored -and $configsWereReady) { Write-Host 'ALREADY CONFIGURED' }
                    else { Write-Host 'FULLY CONFIGURED' }
                    return
                }
            }
        }
    }
}

if (-not $isAdmin) { throw 'Run this script from an elevated PowerShell window to create or mount the VHDX.' }
New-Item -ItemType Directory -Path $oracle -Force | Out-Null

# Preserve old staging data once. Never move a mountpoint or overwrite an existing seed.
$seed = Get-ChildItem -LiteralPath $oracle -Directory -Filter 'C.seed.*' -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending | Select-Object -First 1
if (Test-Path -LiteralPath $stage) {
    $stageItem = Get-Item -LiteralPath $stage -Force
    if (($stageItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'C staging is a reparse point but not the expected VHDX access path; refusing to move it.' }
    $stageContents = @(Get-ChildItem -LiteralPath $stage -Force -ErrorAction Stop)
    if ($stageContents.Count -gt 0) {
        if ($seed) { throw "Staging contains data and an authoritative seed already exists at $($seed.FullName); refusing to move or overwrite either." }
        $seedBytes = (Get-ChildItem -LiteralPath $stage -Recurse -File -Force -ErrorAction Stop | Measure-Object -Property Length -Sum).Sum
        if ($seedBytes -gt 14L * 1GB) { throw "Existing guest C: seed is over 14 GiB ($seedBytes bytes); preserving it in place and refusing to copy into the bounded VHDX." }
        $seedPath = Join-Path $oracle ('C.seed.' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Move-Item -LiteralPath $stage -Destination $seedPath
        $seed = Get-Item -LiteralPath $seedPath
        Write-Host "Preserved guest C: contents at $seedPath"
    } else { Remove-Item -LiteralPath $stage -Force }
}

if (-not (Test-Path -LiteralPath $vhdx -PathType Leaf)) {
    $dp = Join-Path $env:TEMP 'gw_oracle_vhd_create.txt'
    @("create vdisk file=`"$vhdx`" maximum=16384 type=expandable") | Set-Content -LiteralPath $dp -Encoding ascii
    $out = & diskpart.exe /s $dp 2>&1
    $rc = $LASTEXITCODE
    Remove-Item -LiteralPath $dp -Force
    if ($rc -ne 0 -or -not (Test-Path -LiteralPath $vhdx)) { throw "DiskPart could not create the bounded VHDX: $out" }
}
$image = Get-DiskImage -ImagePath $vhdx -ErrorAction Stop
if ([long]$image.Size -gt $size -or [long]$image.Size -lt 1GB) { throw "VHDX virtual capacity is invalid: $($image.Size)" }
if (-not $image.Attached) { Mount-DiskImage -ImagePath $vhdx -ErrorAction Stop | Out-Null }
$disk = Get-Disk | Where-Object { $_.Location -ieq $vhdx } | Select-Object -First 1
if (-not $disk) { throw 'Attached VHDX did not resolve to a disk by its backing-file path.' }
if ($disk.PartitionStyle -eq 'RAW') { Initialize-Disk -Number $disk.Number -PartitionStyle GPT | Out-Null; $disk = Get-Disk -Number $disk.Number }
$parts = @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop | Where-Object Type -ne 'Reserved')
if ($parts.Count -gt 1) { throw 'VHDX has multiple data partitions; refusing to guess.' }
$newPartition = $false
if ($parts.Count -eq 0) { $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize; $newPartition = $true }
else { $part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $parts[0].PartitionNumber -ErrorAction Stop }

if ($newPartition) {
    $letter = @('R','Q','P','O','N','M','L','K','J','I','H','G','F') | Where-Object { -not (Get-Volume -DriveLetter $_ -ErrorAction SilentlyContinue) } | Select-Object -First 1
    if (-not $letter) { throw 'No temporary drive letter is available for formatting the new oracle partition.' }
    Set-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -NewDriveLetter $letter | Out-Null
    Format-Volume -DriveLetter $letter -FileSystem NTFS -NewFileSystemLabel GWORACLE -Confirm:$false | Out-Null
    $part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
} else {
    $vol = Get-Volume -Partition $part -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace([string]$vol.FileSystem) -and [string]::IsNullOrWhiteSpace([string]$vol.FileSystemLabel)) {
        $letter = @('R','Q','P','O','N','M','L','K','J','I','H','G','F') | Where-Object { -not (Get-Volume -DriveLetter $_ -ErrorAction SilentlyContinue) } | Select-Object -First 1
        if (-not $letter) { throw 'No temporary drive letter is available to format the unformatted oracle partition.' }
        Set-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -NewDriveLetter $letter | Out-Null
        Format-Volume -DriveLetter $letter -FileSystem NTFS -NewFileSystemLabel GWORACLE -Confirm:$false | Out-Null
        $part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
    } elseif ($vol.FileSystem -ne 'NTFS' -or $vol.FileSystemLabel -ne 'GWORACLE') {
        throw "Existing partition is not the expected GWORACLE NTFS volume (filesystem='$($vol.FileSystem)', label='$($vol.FileSystemLabel)'); refusing to format it."
    }
}
$vol = Get-Volume -Partition $part -ErrorAction Stop
if ([long]$vol.Size -gt $size) { throw 'Formatted volume exceeds 16 GiB.' }

# Establish and verify the mountpoint before copying the preserved seed.
$part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
$stageAccess = @($part.AccessPaths) | Where-Object { ([string]$_).TrimEnd('\') -ieq $stage.TrimEnd('\') }
if (-not $stageAccess) {
    if (-not (Test-Path -LiteralPath $stage)) { New-Item -ItemType Directory -Path $stage -Force | Out-Null }
    elseif (@(Get-ChildItem -LiteralPath $stage -Force).Count -gt 0) { throw 'C staging is not empty and is not the VHDX mountpoint; refusing to overlay it.' }
    Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -AccessPath ($stage.TrimEnd('\') + '\')
}
 $null = Assert-OracleSandbox -Verifier $verifyAllowEmptyBlock -Path $stage

# Restore only eligible seed files, copying missing files only. Existing
# identical files are retained and conflicts abort without overwrite.
if ($seed) {
    $seedBytes = (Get-ChildItem -LiteralPath $seed.FullName -Recurse -File -Force -ErrorAction Stop | Measure-Object -Property Length -Sum).Sum
    if ($seedBytes -gt 14L * 1GB) { throw "Seed exceeds the 14 GiB restore limit ($seedBytes bytes); seed preserved and not copied." }
    if (-not (Test-OracleSeedRestored -Seed $seed.FullName -Stage $stage)) {
        $copied = Restore-OracleSeedSafely -Seed $seed.FullName -Stage $stage
        Write-Host "Restored preserved seed from $($seed.FullName); files copied=$copied"
    } else { Write-Host "Seed already restored and SHA-256 matched: $($seed.FullName)" }
}
$null = Assert-OracleSandbox -Verifier $verifyBlock -Path $stage

# The expected path is now attached and verified; remove only a temporary drive-letter path if one was used.
$part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
foreach ($temporaryLetter in @('R','Q','P','O','N','M','L','K','J','I','H','G','F')) {
    if ($part.DriveLetter -eq $temporaryLetter) {
        Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -AccessPath ("${temporaryLetter}:\") -Confirm:$false
        break
    }
}
Enable-OracleConfigs -OracleDirectory $oracle -Stage $stage
$null = Assert-OracleSandbox -Verifier $verifyBlock -Path $stage
if ($seed -and -not (Test-OracleSeedRestored -Seed $seed.FullName -Stage $stage)) { throw 'Final seed/staging verification failed.' }
Write-Host 'FULLY CONFIGURED'
Write-Host 'ORACLE HARD CAP ACTIVE: the original staging path is a mountpoint on the 16 GiB maximum VHDX.'
Write-Host 'After reboot, run tools\mount_oracle_vhdx_admin.ps1 from elevated PowerShell before any oracle.'
