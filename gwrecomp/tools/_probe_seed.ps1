$ErrorActionPreference = 'SilentlyContinue'
$c = 'E:\GWRecomp\build\dosboxx_oracle\C'
if (Test-Path $c) {
  $all = Get-ChildItem $c -Recurse -File
  $tot = ($all | Measure-Object Length -Sum).Sum
  [PSCustomObject]@{ label='seed C total MB'; mb=[math]::Round($tot/1MB,1); files=$all.Count } | Format-List
  Write-Output '--- largest 12 files ---'
  $all | Sort-Object Length -Descending | Select-Object -First 12 | ForEach-Object { '{0:N0}  {1}' -f $_.Length, $_.FullName }
} else { Write-Output 'seed C missing' }
Write-Output '--- top-level of C ---'
Get-ChildItem $c | Select-Object Name,Length | Format-Table -AutoSize
Write-Output '--- assigned drive letters ---'
Get-Volume | Where-Object { $_.DriveLetter } | Select-Object DriveLetter,@{n='GB';e={[math]::Round($_.Size/1GB,1)}},@{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,1)}} | Format-Table -AutoSize
Write-Output 'DONE'