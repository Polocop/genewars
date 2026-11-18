# Sample the running game every IntervalSec: memory, handles, CPU seconds, responsiveness, and whether the presented frame still changes.
# Needs the game started with GW_FRAME_DUMP_DIR=<DumpDir>.
param([int]$Minutes = 60, [int]$IntervalSec = 60, [Parameter(Mandatory)][string]$DumpDir, [string]$Out = 'soak.csv')
. (Join-Path $PSScriptRoot 'gwctl.ps1')
"time,ws_mb,priv_mb,handles,responding,cpu_s,frame_md5" | Out-File $Out -Encoding ascii
$end = (Get-Date).AddMinutes($Minutes)
while ((Get-Date) -lt $end) {
    $p = Get-Process gw_demo_sdl2 -ErrorAction SilentlyContinue
    if (-not $p) { "$((Get-Date).ToString('HH:mm:ss')),EXITED" | Add-Content $Out -Encoding ascii; break }
    $png = Snap $DumpDir 'soak'
    $h = if ($png) { (Get-FileHash $png -Algorithm MD5).Hash.Substring(0, 8) } else { 'nosnap' }
    "{0},{1},{2},{3},{4},{5},{6}" -f (Get-Date).ToString('HH:mm:ss'), [int]($p.WorkingSet64 / 1MB), [int]($p.PrivateMemorySize64 / 1MB), $p.HandleCount, $p.Responding, [int]$p.CPU, $h | Add-Content $Out -Encoding ascii
    Start-Sleep -Seconds $IntervalSec
}
