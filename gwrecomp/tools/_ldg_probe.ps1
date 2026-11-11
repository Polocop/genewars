$GwRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Msys2 = if ($env:MSYS2_ROOT) { $env:MSYS2_ROOT } else { 'C:\msys64' }
$ErrorActionPreference = 'SilentlyContinue'
Write-Output '=== DRIVES ==='
Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
    $freeGB = [math]::Round($_.FreeSpace / 1GB, 2)
    $sizeGB = [math]::Round($_.Size    / 1GB, 2)
    "{0}: free {1} GB / total {2} GB  (label={3})" -f $_.DeviceID, $freeGB, $sizeGB, $_.VolumeName
}
Write-Output '=== FREE LETTERS ==='
$used = @()
Get-CimInstance Win32_LogicalDisk | ForEach-Object { $used += $_.DeviceID }
foreach ($c in [char[]]([char]'A'..[char]'Z')) {
    $l = "$c`:"
    if ($used -notcontains $l) { Write-Output "FREE: $l" }
}
Write-Output '=== DOSBOX-X EXE ==='
$exe = "$GwRoot\tools\dosboxx_oracle\dosbox-x.exe"
if (Test-Path $exe) {
    $f = Get-Item $exe
    "EXISTS: $exe  ({0} bytes)" -f $f.Length
} else {
    $cand = @()
    foreach ($r in @("$GwRoot\tools\dosboxx_oracle","$GwRoot\build\dosboxx_oracle","$GwRoot\tools","$GwRoot\build")) {
        if (Test-Path $r) { $cand += (Get-ChildItem $r -Filter 'dosbox-x*.exe' -Recurse -ErrorAction SilentlyContinue).FullName }
    }
    $cand | Select-Object -First 10
}
Write-Output '=== GUEST C MOUNT (grep conf) ==='
foreach ($c in @("$GwRoot\tools\dosboxx_oracle\*.conf","$GwRoot\build\dosboxx_oracle\*.conf")) {
    Get-ChildItem $c -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output ("--- " + $_.FullName)
        (Get-Content $_.FullName) | Where-Object { $_ -match 'mount|C:|DEBUGBOX|debuggerrun|MEMDUMP|address\.txt|GW\.ERR' } | Select-Object -First 40
    }
}
Write-Output '=== STAGING DIR ==='
foreach ($s in @("$GwRoot\build\dosboxx_oracle\C","$GwRoot\build\dosboxx_oracle\C\GENEWARS")) {
    if (Test-Path $s) {
        $sz = (Get-ChildItem $s -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
        "EXISTS: $s  total={0} bytes ({1} MB)" -f $sz, ([math]::Round($sz/1MB,1))
    } else { "MISSING: $s" }
}
Write-Output '=== PYTHON ==='
$py = "$GwRoot\.venv\Scripts\python.exe"
if (Test-Path $py) { & $py --version 2>&1 | ForEach-Object { "venv py: " + $_ } }
else { "no venv py at $py" }