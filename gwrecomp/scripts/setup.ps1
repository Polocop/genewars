<#
 GWRecomp setup: prepares everything that can be obtained from public sources and reports what you must supply yourself.

   powershell -NoProfile -File scripts\setup.ps1 [-InstallMsys2Packages] [-GenewarsInstall <dir>] [-GenewarsCue <file>] [-GenewarsMap <file>]

 What it does (idempotent, safe to re-run):
   1. checks git, Python, MSYS2 (mingw32 gcc + SDL2), clang
   2. creates .venv and installs the pinned Python packages (tools\rebuild\requirements.txt)
   3. clones pcrecomp (MIT) at the pinned commit into third_party\pcrecomp and applies the documented patch (hash verified)
   4. with -InstallMsys2Packages: installs the mingw32 packages with pacman (changes your MSYS2 install; opt-in)
   5. stores game input locations you pass in gwrecomp.local.json (Git-ignored) and verifies them by SHA-256
 It never downloads or copies any Gene Wars file and never touches system settings.
#>
param([switch]$InstallMsys2Packages, [switch]$SkipPcrecomp,
      [string]$GenewarsInstall, [string]$GenewarsCue, [string]$GenewarsMap)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'gwconfig.ps1')
$root = Get-GwRoot
$lock = Get-Content (Join-Path $root 'tools\rebuild\toolchain.lock.json') -Raw | ConvertFrom-Json
$problems = @()
function Step($m) { Write-Host "`n== $m" -ForegroundColor Cyan }
function Ok($m) { Write-Host "  [ok]   $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [todo] $m" -ForegroundColor Yellow; $script:problems += $m }

function ConvertTo-MsysPath([string]$p) { '/' + $p.Substring(0, 1).ToLower() + ($p.Substring(2) -replace '\\', '/') }
function Install-Msys2Pinned($cfg) {
    # MSYS2 retired its i686 (mingw32) environment: the package database no longer lists these packages, so
    # 'pacman -S <name>' fails. The exact package files are still on the mirror; install the pinned list with
    # 'pacman -U' from downloads whose SHA-256 is checked against tools\rebuild\msys2-mingw32-packages.json.
    $man = Get-Content (Join-Path $root 'tools\rebuild\msys2-mingw32-packages.json') -Raw | ConvertFrom-Json
    $dir = Join-Path $root 'build\msys2-cache'; New-Item -ItemType Directory -Force $dir | Out-Null
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'
    $paths = @()
    foreach ($p in $man.packages) {
        $f = Join-Path $dir $p.file
        if (-not (Test-Path $f) -or (Get-FileHash $f -Algorithm SHA256).Hash.ToLower() -ne $p.sha256) {
            Invoke-WebRequest -Uri $p.url -OutFile $f -UseBasicParsing
            Invoke-WebRequest -Uri ($p.url + '.sig') -OutFile ($f + '.sig') -UseBasicParsing
        }
        if ((Get-FileHash $f -Algorithm SHA256).Hash.ToLower() -ne $p.sha256) { throw "SHA-256 mismatch for $($p.file); refusing to install" }
        $paths += (ConvertTo-MsysPath $f)
    }
    & (Join-Path $cfg.UsrBin 'pacman.exe') -U --noconfirm --needed @paths
    return $LASTEXITCODE
}

# persist any game input locations first so that later steps see them
if ($GenewarsInstall -or $GenewarsCue -or $GenewarsMap) {
    $local = @{}
    $lf = Join-Path $root 'gwrecomp.local.json'
    if (Test-Path $lf) { foreach ($p in (Get-Content $lf -Raw | ConvertFrom-Json).PSObject.Properties) { $local[$p.Name] = $p.Value } }
    if ($GenewarsInstall) { $local['GENEWARS_INSTALL_DIR'] = (Resolve-Path -LiteralPath $GenewarsInstall).Path }
    if ($GenewarsCue)     { $local['GENEWARS_CUE'] = (Resolve-Path -LiteralPath $GenewarsCue).Path }
    if ($GenewarsMap)     { $local['GENEWARS_MAP'] = (Resolve-Path -LiteralPath $GenewarsMap).Path }
    $local | ConvertTo-Json | Set-Content -Encoding utf8 $lf
    Write-Host "Saved game input locations to $lf (ignored by Git)."
}

Step '1. Prerequisites'
if (Get-Command git.exe -ErrorAction SilentlyContinue) { Ok ((& git --version)) } else { Warn 'git is required: https://git-scm.com/download/win' }
$cfg = Get-GwConfig
$basePython = $null
foreach ($cand in @('py -3', 'python')) {
    try { $v = & cmd /c "$cand --version 2>&1"; if ($LASTEXITCODE -eq 0 -and $v -match 'Python 3\.(\d+)') { if ([int]$Matches[1] -ge 10) { $basePython = $cand; Ok "$v via '$cand' (reference build used $($lock.tools.python))"; break } } } catch { }
}
if (-not $basePython -and -not (Test-Path (Join-Path $root '.venv\Scripts\python.exe'))) { Warn 'Python 3.10+ is required (reference: 3.13): https://www.python.org/downloads/windows/' }
if ($cfg.Msys2 -and (Test-Path (Join-Path $cfg.Mingw32Bin 'gcc.exe'))) { Ok "MSYS2 at $($cfg.Msys2) ($(& (Join-Path $cfg.Mingw32Bin 'gcc.exe') --version | Select-Object -First 1))" }
elseif ($cfg.Msys2) { Warn "MSYS2 found at $($cfg.Msys2) without the mingw32 toolchain: re-run with -InstallMsys2Packages (installs pinned packages)." }
else { Warn 'MSYS2 not found. Install MSYS2 (https://www.msys2.org/), then re-run with -InstallMsys2Packages, or set MSYS2_ROOT.' }
if ($cfg.ClangX64) { Ok "clang: $($cfg.ClangX64) ($(& $cfg.ClangX64 --version | Select-Object -First 1)); reference: $($lock.tools.clang)" }
else { Warn "clang not found. Install LLVM $($lock.tools.clang -replace 'clang version ','') (for example: winget install --id LLVM.LLVM --version 19.1.5 -e) or set GWRECOMP_CLANG_X64." }

Step '2. Python environment'
$venvPy = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPy) -and $basePython) {
    & cmd /c "$basePython -m venv `"$root\.venv`""
    if ($LASTEXITCODE) { Warn 'could not create .venv' }
}
if (Test-Path $venvPy) {
    & $venvPy -m pip install --disable-pip-version-check -q -r (Join-Path $root 'tools\rebuild\requirements.txt')
    if ($LASTEXITCODE) { Warn 'pip install of pinned packages failed' }
    else { Ok ("packages: " + ((& $venvPy -I -c "import importlib.metadata as m;print(', '.join(sorted(d.metadata['Name'].lower()+'=='+d.version for d in m.distributions() if d.metadata['Name'].lower() in ('capstone','unicorn'))))"))) }
}

Step '3. MSYS2 packages'
if ($cfg.Msys2) {
    $pacman = Join-Path $cfg.UsrBin 'pacman.exe'
    if ($InstallMsys2Packages) { $rc = Install-Msys2Pinned $cfg; if ($rc) { Warn "pacman -U of the pinned packages failed (exit $rc)" } }
    $sdl = Join-Path $cfg.Msys2 'mingw32\include\SDL2\SDL.h'
    if (Test-Path $sdl) { Ok "SDL2 headers present ($(& $pacman -Q mingw-w64-i686-SDL2 2>&1)); reference: $($lock.tools.msys_packages)" }
    else { Warn 'SDL2 for mingw32 missing: re-run with -InstallMsys2Packages (pinned package list in tools\rebuild\msys2-mingw32-packages.json)' }
} else { Warn 'skipped: MSYS2 not found' }

Step '4. pcrecomp (pinned commit + documented patch)'
if (-not $SkipPcrecomp -and (Get-Command git.exe -ErrorAction SilentlyContinue) -and (Test-Path $venvPy)) {
    $pc = Join-Path $root 'third_party\pcrecomp'
    if (-not (Test-Path (Join-Path $pc '.git'))) {
        New-Item -ItemType Directory -Force (Split-Path $pc) | Out-Null
        if (Test-Path -LiteralPath $pc) { Remove-Item -LiteralPath $pc -Recurse -Force }   # leftover of an interrupted clone
        & git clone --no-checkout $lock.pcrecomp.repository $pc
        if ($LASTEXITCODE) { Warn "git clone of $($lock.pcrecomp.repository) failed (network or proxy problem?). Re-run scripts\setup.ps1; nothing else is affected."; if (Test-Path -LiteralPath $pc) { Remove-Item -LiteralPath $pc -Recurse -Force } }
        else {
            & git -C $pc config core.autocrlf true
            & git -C $pc checkout --detach $lock.pcrecomp.commit
            if ($LASTEXITCODE) { Warn "could not check out pcrecomp $($lock.pcrecomp.commit); delete third_party\pcrecomp and re-run scripts\setup.ps1" }
        }
    }
    if (-not (Test-Path (Join-Path $pc '.git'))) { Write-Host '  pcrecomp not available; skipping the patch step' }
    else {
    $head = (& git -C $pc rev-parse HEAD).Trim()
    if ($head -ne $lock.pcrecomp.commit) { Warn "pcrecomp is at $head, expected $($lock.pcrecomp.commit)" }
    else {
        $man = Get-Content (Join-Path $root "tools\rebuild\$($lock.pcrecomp.patch_manifest)") -Raw | ConvertFrom-Json
        $applied = $true
        foreach ($c in $man.changed_tracked_files) { if ((Get-FileHash (Join-Path $pc $c.file) -Algorithm SHA256).Hash.ToLower() -ne $c.post_sha256) { $applied = $false } }
        if ($applied) { Ok "pcrecomp $($head.Substring(0,7)) with patch already applied" }
        else {
            $o = & $venvPy -I (Join-Path $root 'tools\rebuild\apply_pcrecomp_patch.py') $pc (Join-Path $root "tools\rebuild\$($lock.pcrecomp.patch)") (Join-Path $root "tools\rebuild\$($lock.pcrecomp.patch_manifest)") 2>&1
            if ($LASTEXITCODE) { Warn "pcrecomp patch failed: $($o -join ' ')" } else { Ok ($o -join ' ') }
        }
    }
    }
} else { Write-Host '  skipped (needs git and the Python environment)' }

Step '5. Inputs from your own copy of the game (Levels B and C)'
$cfg = Get-GwConfig
Write-GwConfigSummary $cfg
if ($cfg.Install -or $cfg.Cue -or $cfg.Map) {
    if (Test-Path $venvPy) { & $venvPy (Join-Path $root 'tools\rebuild\check_inputs.py') --install $cfg.Install --cue $cfg.Cue @(if ($cfg.Map) { '--map'; $cfg.Map }) }
} else {
    Write-Host '  No game inputs configured. Level A does not need them. For levels B/C re-run with:'
    Write-Host '    scripts\setup.ps1 -GenewarsInstall <GENEWARS folder> -GenewarsCue <cue file> -GenewarsMap <genewars-1_1.map>'
    Write-Host '  (see tools\rebuild\README_BUILD.md, "Inputs you must supply")'
}

Write-Host ''
if ($problems.Count) { Write-Host "Setup finished with $($problems.Count) open item(s) above." -ForegroundColor Yellow; exit 1 }
Write-Host 'Setup complete. Next: scripts\build.ps1 -Level A ; scripts\test.ps1' -ForegroundColor Green
