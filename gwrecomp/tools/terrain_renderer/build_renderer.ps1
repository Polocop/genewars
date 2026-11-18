param()
$GwRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Msys2 = if ($env:MSYS2_ROOT) { $env:MSYS2_ROOT } else { 'C:\msys64' }

$ErrorActionPreference = 'Stop'
$source = "$GwRoot\tools\terrain_renderer\gw_terrain_data_renderer.cpp"
$outDir = "$GwRoot\work\terrain_renderer"
$vsDev = if ($env:GWRECOMP_VSDEVCMD) { $env:GWRECOMP_VSDEVCMD } else { Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat' }
if (!(Test-Path -LiteralPath $source) -or !(Test-Path -LiteralPath $vsDev)) { throw 'C++ source or Visual Studio Build Tools not found.' }
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$cmd = 'call "' + $vsDev + '" -arch=x64 -host_arch=x64 && cl /nologo /std:c++17 /EHsc /O2 /Fe:' + $outDir + '\gw_terrain_data_renderer.exe ' + $source
& cmd.exe /d /s /c $cmd
if ($LASTEXITCODE -ne 0) { throw "renderer build failed: $LASTEXITCODE" }
Get-FileHash -LiteralPath "$outDir\gw_terrain_data_renderer.exe" -Algorithm SHA256

