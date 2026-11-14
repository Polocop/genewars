<#
 GWRecomp configuration resolver (dot-source this file; do not run it).

 Every location is resolved in this order:  explicit parameter  >  environment variable  >  gwrecomp.local.json  >  auto-detection.
 gwrecomp.local.json lives in the gwrecomp directory, is ignored by Git and is written by scripts\setup.ps1 when you pass paths.

 Variables / JSON keys (all optional unless marked):
   GWRECOMP_PYTHON        python.exe to use                           (default: <gwrecomp>\.venv, else python on PATH)
   MSYS2_ROOT             MSYS2 install containing mingw32            (default: gcc on PATH, else C:\msys64)
   GWRECOMP_CLANG_X64     clang.exe for the large lifted C unit       (default: clang on PATH, VS 2022 LLVM, C:\Program Files\LLVM)
   GWRECOMP_CLANG_X86     clang.exe used to link                      (default: same as GWRECOMP_CLANG_X64)
   PCRECOMP_ROOT          pcrecomp checkout                           (default: <gwrecomp>\third_party\pcrecomp, created by setup.ps1)
   GWRECOMP_WORK          directory for build outputs                 (default: <gwrecomp>\build)
   GENEWARS_INSTALL_DIR   your Gene Wars 1.1 GENEWARS folder          (REQUIRED for levels B and C; contains GW.EXE and DATA\)
   GENEWARS_CUE           .cue of your Gene Wars CD image             (REQUIRED for levels B and C)
   GENEWARS_MAP           symbol map genewars-1_1.map                 (REQUIRED for levels B and C; see README_BUILD.md)
#>
function Get-GwRoot {
    # <gwrecomp> = parent of the directory holding this script, wherever the repository was cloned
    return (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

function Get-GwConfig {
    param([hashtable]$Override = @{})
    $root = Get-GwRoot
    $localFile = Join-Path $root 'gwrecomp.local.json'
    $local = @{}
    if (Test-Path -LiteralPath $localFile) {
        $obj = Get-Content -LiteralPath $localFile -Raw | ConvertFrom-Json
        foreach ($p in $obj.PSObject.Properties) { $local[$p.Name] = [string]$p.Value }
    }
    $cfg = [ordered]@{ Root = $root; LocalFile = $localFile; Sources = [ordered]@{} }
    function Pick([string]$key, [scriptblock]$auto) {
        if ($Override.ContainsKey($key) -and $Override[$key]) { $cfg.Sources[$key] = 'parameter'; return [string]$Override[$key] }
        $e = [Environment]::GetEnvironmentVariable($key)
        if ($e) { $cfg.Sources[$key] = 'environment'; return $e }
        if ($local.ContainsKey($key) -and $local[$key]) { $cfg.Sources[$key] = 'gwrecomp.local.json'; return $local[$key] }
        $a = & $auto
        if ($a) { $cfg.Sources[$key] = 'auto-detected'; return [string]$a }
        $cfg.Sources[$key] = 'not found'; return $null
    }
    $cfg.Python = Pick 'GWRECOMP_PYTHON' {
        $v = Join-Path $root '.venv\Scripts\python.exe'
        if (Test-Path -LiteralPath $v) { $v } else { $c = Get-Command python.exe -ErrorAction SilentlyContinue; if ($c) { $c.Source } }
    }
    $cfg.Msys2 = Pick 'MSYS2_ROOT' {
        $g = Get-Command gcc.exe -ErrorAction SilentlyContinue
        if ($g -and (Split-Path -Leaf (Split-Path -Parent (Split-Path -Parent $g.Source))) -eq 'mingw32') { Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $g.Source)) }
        elseif (Test-Path 'C:\msys64\mingw32\bin\gcc.exe') { 'C:\msys64' }
        elseif (Test-Path 'C:\msys64\usr\bin\pacman.exe') { 'C:\msys64' }   # MSYS2 without the mingw32 packages yet (setup.ps1 -InstallMsys2Packages adds them)
    }
    $cfg.ClangX64 = Pick 'GWRECOMP_CLANG_X64' {
        $c = Get-Command clang.exe -ErrorAction SilentlyContinue
        if ($c) { $c.Source } else {
            $cands = @()
            foreach ($b in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) { if ($b) {
                foreach ($ed in 'BuildTools','Community','Professional','Enterprise') { $cands += (Join-Path $b "Microsoft Visual Studio\2022\$ed\VC\Tools\Llvm\x64\bin\clang.exe") }
                $cands += (Join-Path $b 'LLVM\bin\clang.exe') } }
            $cands | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        }
    }
    $cfg.ClangX86 = Pick 'GWRECOMP_CLANG_X86' { $cfg.ClangX64 }
    $cfg.Pcrecomp = Pick 'PCRECOMP_ROOT' { $p = Join-Path $root 'third_party\pcrecomp'; if (Test-Path -LiteralPath (Join-Path $p '.git')) { $p } }
    $cfg.WorkRoot = Pick 'GWRECOMP_WORK' { Join-Path $root 'build' }
    $cfg.Install = Pick 'GENEWARS_INSTALL_DIR' { $null }
    $cfg.Cue = Pick 'GENEWARS_CUE' { $null }
    $cfg.Map = Pick 'GENEWARS_MAP' { $null }
    if ($cfg.Msys2) {
        $cfg.Mingw32Bin = Join-Path $cfg.Msys2 'mingw32\bin'
        $cfg.Mingw32Lib = Join-Path $cfg.Msys2 'mingw32\lib'
        $cfg.UsrBin = Join-Path $cfg.Msys2 'usr\bin'
    }
    return $cfg
}

function Set-GwEnvironment {
    # Export the resolved configuration for the Python drivers (they read these variables).
    param($Cfg)
    if ($Cfg.Python)    { $env:GWRECOMP_PYTHON = $Cfg.Python }
    if ($Cfg.Msys2)     { $env:MSYS2_ROOT = $Cfg.Msys2; $env:PATH = "$($Cfg.Mingw32Bin);$($Cfg.UsrBin);$env:PATH" }
    if ($Cfg.ClangX64)  { $env:GWRECOMP_CLANG_X64 = $Cfg.ClangX64 }
    if ($Cfg.ClangX86)  { $env:GWRECOMP_CLANG_X86 = $Cfg.ClangX86 }
    if ($Cfg.Install)   { $env:GENEWARS_INSTALL_DIR = $Cfg.Install }
    if ($Cfg.Cue)       { $env:GENEWARS_CUE = $Cfg.Cue }
    if ($Cfg.Map)       { $env:GENEWARS_MAP = $Cfg.Map }
}

function Write-GwConfigSummary {
    param($Cfg)
    foreach ($k in 'Python','Msys2','ClangX64','ClangX86','Pcrecomp','WorkRoot','Install','Cue','Map') {
        $src = ''
        $name = @{Python='GWRECOMP_PYTHON';Msys2='MSYS2_ROOT';ClangX64='GWRECOMP_CLANG_X64';ClangX86='GWRECOMP_CLANG_X86';Pcrecomp='PCRECOMP_ROOT';WorkRoot='GWRECOMP_WORK';Install='GENEWARS_INSTALL_DIR';Cue='GENEWARS_CUE';Map='GENEWARS_MAP'}[$k]
        $v = if ($Cfg[$k]) { $Cfg[$k] } else { '(not set)' }
        '{0,-22} {1}  [{2}]' -f $name, $v, $Cfg.Sources[$name] | Write-Host
    }
}
