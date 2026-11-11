[CmdletBinding()]
param(
    [string]$Path = 'E:\GWRecomp\build\dosboxx_oracle\C',
    [switch]$Json,
    [switch]$AllowEmptyGuestStaging
)
$ErrorActionPreference = 'Stop'
$expectedPath = 'E:\GWRecomp\build\dosboxx_oracle\C'
$vhdx = 'E:\GWRecomp\build\dosboxx_oracle\oracle_c.vhdx'
$result = [ordered]@{ verified=$false; reason='unverified'; mount_path=$null; label=$null; capacity_bytes=$null; host_free_bytes=$null; host_floor_bytes=(100L * 1GB); vhdx=$vhdx }
try {
    $want = [IO.Path]::GetFullPath($expectedPath).TrimEnd('\')
    $got = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($got -ine $want) { throw "Unexpected staging path: $got" }
    if (-not (Test-Path -LiteralPath $vhdx -PathType Leaf)) { throw "VHDX missing: $vhdx" }
    $image = Get-DiskImage -ImagePath $vhdx -ErrorAction Stop
    if (-not $image.Attached) { throw 'VHDX is not attached' }
    # Get-DiskImage.Number is null on some supported PowerShell/Storage builds;
    # match the attached disk by its VHDX backing-file Location instead.
    $disk = Get-Disk -ErrorAction Stop | Where-Object { $_.Location -ieq $vhdx } | Select-Object -First 1
    if (-not $disk) { throw "Attached VHDX did not resolve to a disk by backing path: $vhdx" }
    $part = Get-Partition -DiskNumber $disk.Number -ErrorAction Stop | Where-Object Type -ne 'Reserved' | Select-Object -First 1
    if (-not $part) { throw 'VHDX has no data partition' }
    $part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -ErrorAction Stop
    $access = @($part.AccessPaths)
    $mount = $access | Where-Object { ([string]$_).TrimEnd('\') -ieq $want } | Select-Object -First 1
    if (-not $mount) { throw 'The expected staging directory is not an access path of the VHDX partition' }
    $vol = Get-Volume -Partition $part -ErrorAction Stop
    if ($vol.FileSystem -ne 'NTFS') { throw "Expected NTFS, got $($vol.FileSystem)" }
    if ($vol.FileSystemLabel -ne 'GWORACLE') { throw "Expected volume label GWORACLE, got $($vol.FileSystemLabel)" }
    $capacity = [long]$vol.Size
    if ($capacity -le 0 -or $capacity -gt 16L * 1GB) { throw "Volume capacity $capacity exceeds 16 GiB hard cap" }
    $hostVolume = Get-Volume -DriveLetter E -ErrorAction Stop
    $hostFree = [long]$hostVolume.SizeRemaining
    $hostFloor = 100L * 1GB
    if ($hostFree -lt $hostFloor) { throw "Host E: free space $hostFree bytes is below the 100 GiB floor ($hostFloor bytes)" }
    if (-not $AllowEmptyGuestStaging) {
        foreach ($relative in @('GENEWARS\MAIN.EXE','GENEWARS\GW.EXE','GENEWARS\DOS4GW.EXE','GENEWARS\config.ini')) {
            $required = Join-Path $want $relative
            if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Required guest staging file missing: $relative" }
        }
    }
    $result.verified = $true; $result.reason = 'verified'; $result.mount_path = $want
    $result.label = $vol.FileSystemLabel; $result.capacity_bytes = $capacity
    $result.host_free_bytes = $hostFree
} catch { $result.reason = $_.Exception.Message }
if ($Json) { $result | ConvertTo-Json -Compress }
else {
    if ($result.verified) { Write-Host "VERIFIED: $($result.mount_path) -> $($result.label), $([math]::Round($result.capacity_bytes/1GB,3)) GiB; E: free $([math]::Round($result.host_free_bytes/1GB,2)) GiB"; Write-Host 'ORACLE_SANDBOX_VERIFIED = YES' }
    else { Write-Error "ORACLE SANDBOX NOT VERIFIED: $($result.reason)" }
}
if (-not $result.verified) { throw "ORACLE SANDBOX VERIFICATION FAILED: $($result.reason)" }
