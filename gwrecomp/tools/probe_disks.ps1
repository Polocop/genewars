$ErrorActionPreference = 'Stop'
Get-Volume -DriveLetter D, E | ForEach-Object {
  [PSCustomObject]@{
    Drive = $_.DriveLetter
    SizeGB   = [math]::Round($_.Size/1GB, 1)
    FreeGB   = [math]::Round($_.SizeRemaining/1GB, 1)
    Fs       = $_.FileSystem
    Label    = $_.Label
  }
} | Format-List
Write-Output '--- VHD/VHDX presence ---'
Get-ChildItem -Path E:\GWRecomp, D:\ -Filter *.vhdx -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length | Format-List
Write-Output '--- temp leftovers (large files >100MB on D:) ---'
Get-ChildItem -Path D:\ -Filter *.vhd* -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, @{n='MB';e={[math]::Round($_.Length/1MB,1)}} | Format-List
Write-Output '--- running DOSBox/oracle procs ---'
Get-Process | Where-Object { $_.ProcessName -match 'dosbox|oracle|debugbox' } | Select-Object Id, ProcessName | Format-Table -AutoSize
Write-Output 'DONE'