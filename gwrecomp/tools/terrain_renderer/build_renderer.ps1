param()
$ErrorActionPreference = 'Stop'
$source = 'E:\GWRecomp\tools\terrain_renderer\gw_terrain_data_renderer.cpp'
$outDir = 'E:\GWRecomp\work\terrain_renderer'
$vsDev = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat'
if (!(Test-Path -LiteralPath $source) -or !(Test-Path -LiteralPath $vsDev)) { throw 'C++ source or Visual Studio Build Tools not found.' }
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$cmd = 'call "' + $vsDev + '" -arch=x64 -host_arch=x64 && cl /nologo /std:c++17 /EHsc /O2 /Fe:' + $outDir + '\gw_terrain_data_renderer.exe ' + $source
& cmd.exe /d /s /c $cmd
if ($LASTEXITCODE -ne 0) { throw "renderer build failed: $LASTEXITCODE" }
Get-FileHash -LiteralPath "$outDir\gw_terrain_data_renderer.exe" -Algorithm SHA256

