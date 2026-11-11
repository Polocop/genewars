<#
 GWRecomp - rebuild the demo executable from a CLEAN checkout of this repository plus explicit, hash-verified dependencies.
 Sources come from git; the lifter dependency (pcrecomp) from its pinned commit plus a versioned patch; the two build inputs
 that derive from the game (GW.EXE and the symbol map) from locations YOU configure, verified by SHA-256.
 Nothing is read from the author's machine layout: all locations come from scripts\gwconfig.ps1 (parameters, environment
 variables, gwrecomp.local.json or auto-detection).

 usage: powershell -NoProfile -File tools\rebuild\rebuild.ps1 -Work <new dir> [-Commit <sha|ref>] [-Lift regenerate|reuse] [-Strict]
        [-PcrecompSource <path|url>] [-Audit] [-ReuseObjectCacheId <id>] [-ObjectCacheDiagnostics] [-DryRun]
 Phases: 1 toolchain | 2 clean checkout | 3 eol policy | 4 pcrecomp (pinned commit + patch) | 5 inputs
         6 build (python driver; lift regenerated) | 7 deterministic link | 8 manifest
 Everything is written under -Work (a directory that must not exist yet). See tools\rebuild\README_BUILD.md.
#>
param([Parameter(Mandatory)][string]$Work,
      [string]$Commit = 'HEAD',
      [ValidateSet('regenerate','reuse')][string]$Lift = 'regenerate',
      [switch]$Strict,
      [switch]$Audit,
      [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,23}$')][string]$ReuseObjectCacheId,
      [switch]$UseCurrentObjectCacheSources,
      [switch]$ObjectCacheDiagnostics,
      [switch]$DryRun,
      [string]$PcrecompSource,
      [string]$Python)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path          # <repo>\tools\rebuild
$repoRoot = (Resolve-Path "$here\..\..").Path
. (Join-Path $repoRoot 'scripts\gwconfig.ps1')
$Cfg = Get-GwConfig -Override @{ GWRECOMP_PYTHON = $Python }
$Work = [System.IO.Path]::GetFullPath($Work)
if(Test-Path -LiteralPath $Work){ throw "work dir $Work already exists (each BuildId requires a new directory)" }
$BuildId = Split-Path -Leaf $Work.TrimEnd('\')
$lock = Get-Content "$here\toolchain.lock.json" -Raw | ConvertFrom-Json
$PCRE_COMMIT = $lock.pcrecomp.commit
if(-not $PcrecompSource){ $PcrecompSource = if($Cfg.Pcrecomp){ $Cfg.Pcrecomp } else { $lock.pcrecomp.repository } }
$CacheRoot = $null; $CacheLock = $null; $CacheBase = Join-Path $Cfg.WorkRoot 'reusable-object-cache'
if($ReuseObjectCacheId){
  $CacheRoot = Join-Path $CacheBase $ReuseObjectCacheId
  $WorkFull = $Work; $CacheFull = [System.IO.Path]::GetFullPath($CacheRoot)
  $workPrefix = $WorkFull.TrimEnd('\') + '\'; $cachePrefix = $CacheFull.TrimEnd('\') + '\'
  if($WorkFull.Equals($CacheFull,[System.StringComparison]::OrdinalIgnoreCase) -or
     $WorkFull.StartsWith($cachePrefix,[System.StringComparison]::OrdinalIgnoreCase) -or
     $CacheFull.StartsWith($workPrefix,[System.StringComparison]::OrdinalIgnoreCase)){
    throw 'BuildId Work and reusable object cache must be separate, non-overlapping paths'
  }
}
if($DryRun){
  Write-GwConfigSummary $Cfg
  [pscustomobject]@{ Mode='DRY-RUN'; BuildId=$BuildId; Work=$Work; WorkExists=(Test-Path -LiteralPath $Work)
    ObjectCache=if($CacheRoot){$CacheRoot}else{'disabled (per-build object directory)'}
    PcrecompSource=$PcrecompSource; PcrecompCommit=$PCRE_COMMIT; Strict=[bool]$Strict
    ObjectCacheSourceOverlay=[bool]$UseCurrentObjectCacheSources; ObjectCacheDiagnostics=[bool]$ObjectCacheDiagnostics
    Lock='not acquired in DRY-RUN'; NoBuildOrWrites=$true } | Format-List
  return
}
foreach($need in @(@('Python','GWRECOMP_PYTHON'),@('Msys2','MSYS2_ROOT'),@('ClangX64','GWRECOMP_CLANG_X64'))){
  if(-not $Cfg[$need[0]]){ throw "$($need[1]) is not configured and could not be auto-detected. Run scripts\setup.ps1 (see tools\rebuild\README_BUILD.md)." }
}
foreach($need in @(@('Install','GENEWARS_INSTALL_DIR'),@('Cue','GENEWARS_CUE'),@('Map','GENEWARS_MAP'))){
  if(-not $Cfg[$need[0]]){ throw "$($need[1]) is not set. This input comes from your own copy of the game; see tools\rebuild\README_BUILD.md 'Inputs you must supply'." }
}
$Python = $Cfg.Python
$MINGW = $Cfg.Mingw32Bin; $CLANG_X64 = $Cfg.ClangX64; $CLANG_X86 = $Cfg.ClangX86
if($CacheRoot){
  New-Item -ItemType Directory -Force $CacheRoot | Out-Null
  try { $CacheLock = [System.IO.File]::Open((Join-Path $CacheRoot 'workspace.lock'),[System.IO.FileMode]::OpenOrCreate,[System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::None) }
  catch { throw "object cache '$ReuseObjectCacheId' is already in use; use a distinct cache id or retry later" }
}
$src = "$Work\src"; $tmp = "$Work\tmp"
New-Item -ItemType Directory -Force $Work, $tmp | Out-Null
$objectDir = if($CacheRoot){Join-Path $CacheRoot 'objects'}else{"$src\work\native_ifctitle_plugin_load_at_objs"}
$objectCacheManifest = Join-Path $Work 'object-cache-usage.json'
$M = [ordered]@{ schema='gwrecomp-rebuild/2'; build_id=$BuildId; started=(Get-Date).ToString('o'); work=$Work; object_cache_id=$ReuseObjectCacheId; object_cache_path=$CacheRoot; object_cache_diagnostics=[bool]$ObjectCacheDiagnostics; lift=$Lift; requested_commit=$Commit; pcrecomp_commit=$PCRE_COMMIT; strict=[bool]$Strict; phases=[ordered]@{} }
function Sha($p){ (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() }
function Save { $M | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 "$Work\rebuild_manifest.json" }
function Run($cmdline){ $o = cmd.exe /c "$cmdline 2>&1"; if($LASTEXITCODE){ throw "command failed ($LASTEXITCODE): $cmdline`n$o" }; $o }
$M.rebuild_script_sha256 = Sha $PSCommandPath
function Phase($n, [scriptblock]$b){
  $t = Get-Date; $code = 0
  try { & $b } catch { $code = 1; Write-Host "PHASE $n FAILED: $_" }
  $M.phases[$n] = [ordered]@{ exit=$code; seconds=[math]::Round(((Get-Date)-$t).TotalSeconds,1) }
  Write-Host ("PHASE {0} exit={1} {2}s" -f $n, $code, $M.phases[$n].seconds)
  if($code){ Save; exit $code } }
Get-ChildItem Env: | ? { $_.Name -match '^(GWRECOMP_|GW_)' -and $_.Name -notin @('GWRECOMP_PYTHON','GWRECOMP_CLANG_X64','GWRECOMP_CLANG_X86','GWRECOMP_WORK') } | % { Remove-Item "Env:$($_.Name)" }
$env:TEMP=$tmp; $env:TMP=$tmp; $env:TMPDIR=$tmp; $env:PYTHONDONTWRITEBYTECODE='1'
Set-GwEnvironment $Cfg
$env:GWRECOMP_OBJECT_CACHE_ROOT = $CacheBase
if($CacheRoot){ $env:GWRECOMP_OBJECT_CACHE=$objectDir; $env:GWRECOMP_OBJECT_CACHE_LOCKED='1'; $env:GWRECOMP_OBJECT_CACHE_USAGE=$objectCacheManifest }
if($ObjectCacheDiagnostics){ $env:GWRECOMP_OBJECT_CACHE_DIAGNOSTICS='1' }

# resolve the commit to build (exact sha) and the object store to clone from
$c0 = "git -C `"$repoRoot`" rev-parse --verify $Commit"; $r0 = Run $c0; $COMMIT_SHA = "$r0".Trim()
$c1 = "git -C `"$repoRoot`" rev-parse --path-format=absolute --git-common-dir"; $r1 = Run $c1; $RepoSource = "$r1".Trim()
$c1b = "git -C `"$repoRoot`" rev-parse --show-prefix"; $r1b = Run $c1b; $RepoPrefix = "$r1b".Trim().TrimEnd('/')   # '' when gwrecomp is the repository root, 'gwrecomp' in the fork
$M.commit = $COMMIT_SHA

Phase '1_toolchain' {
  $got = [ordered]@{ python=((& $Python --version) -join ''); gcc=(& "$MINGW\gcc.exe" --version)[0]; ld=(& "$MINGW\ld.exe" --version)[0]
    clang_x64=(& $CLANG_X64 --version)[0]; clang_x86=(& $CLANG_X86 --version)[0] }
  $pk = & $Python -I -c "import importlib.metadata as m;print(';'.join(sorted(d.metadata['Name'].lower()+'=='+d.version for d in m.distributions() if d.metadata['Name'].lower() in ('capstone','unicorn'))))"
  $got.python_packages = $pk
  $pacman = Join-Path $Cfg.UsrBin 'pacman.exe'
  if(Test-Path -LiteralPath $pacman){ $got.msys_packages = ((& $pacman -Q mingw-w64-i686-SDL2 mingw-w64-i686-gcc mingw-w64-i686-crt-git mingw-w64-i686-binutils 2>&1) -join '; ') }
  $issues = @()
  if($got.python -ne $lock.tools.python){ $issues += "python: have '$($got.python)' reference '$($lock.tools.python)'" }
  if($got.gcc -ne $lock.tools.gcc){ $issues += "gcc: have '$($got.gcc)' reference '$($lock.tools.gcc)'" }
  if($got.ld -ne $lock.tools.ld){ $issues += "ld: have '$($got.ld)' reference '$($lock.tools.ld)'" }
  foreach($k in 'clang_x64','clang_x86'){ if(-not $got[$k].StartsWith($lock.tools.clang)){ $issues += "${k}: have '$($got[$k])' reference '$($lock.tools.clang)'" } }
  if($pk -ne ($lock.python_packages -join ';')){ $issues += "python packages: have '$pk' reference '$($lock.python_packages -join ';')'" }
  $M.toolchain = $got; $M.toolchain_differences = @($issues)
  if($issues){
    $msg = "toolchain differs from the reference build:`n" + ($issues -join "`n")
    if($Strict){ throw $msg } else { Write-Host "WARNING: $msg`n(continuing; output may not be byte-identical to the reference. Use -Strict to make this an error.)" }
  }
  if($Strict){
    $rh = $lock.reference_hashes
    $hb = @(); if((Sha $CLANG_X64) -ne $rh.clang_x64_sha){ $hb += 'clang_x64 binary hash' }; if((Sha "$MINGW\SDL2.dll") -ne $rh.sdl2_dll_sha){ $hb += 'SDL2.dll hash' }
    if($hb){ throw "strict: binaries differ from the reference build: $($hb -join ', ')" }
  }
}
Phase '2_clean_checkout' {
  Run "git clone --no-checkout --local `"$RepoSource`" `"$src`"" | Out-Null
  Run "git -C `"$src`" checkout --detach $COMMIT_SHA" | Out-Null
  $c2 = "git -C `"$src`" rev-parse HEAD"; $r2 = Run $c2; if("$r2".Trim() -ne $COMMIT_SHA){ throw "checkout HEAD mismatch" }
  $c3 = "git -C `"$src`" status --porcelain"; $r3 = Run $c3; if("$r3".Trim()){ throw "checkout not clean: $r3" }
  $M.checkout_head = $COMMIT_SHA
  # the build runs inside the gwrecomp directory of the checkout
  $script:buildRoot = if($RepoPrefix){ Join-Path $src $RepoPrefix } else { $src }
  $M.build_root = $script:buildRoot
}
$buildRoot = if($RepoPrefix){ Join-Path $src $RepoPrefix } else { $src }
if(-not $CacheRoot){ $objectDir = "$buildRoot\work\native_ifctitle_plugin_load_at_objs" }   # per-build objects live inside the gwrecomp directory of the checkout
if($UseCurrentObjectCacheSources){
  Phase '2b_object_cache_source_overlay' {
    $overlayRows = @()
    foreach($rel in 'tests\test_ifctitle_creature_probe.py','tools\rebuild\object_cache.py'){
      $sourcePath = Join-Path $repoRoot $rel
      $destination = Join-Path $buildRoot $rel
      if(-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)){ throw "cache source overlay missing: $sourcePath" }
      New-Item -ItemType Directory -Force (Split-Path $destination) | Out-Null
      Copy-Item -LiteralPath $sourcePath -Destination $destination
      $sourceHash = Sha $sourcePath; $copiedHash = Sha $destination
      if($sourceHash -cne $copiedHash){ throw "cache source overlay hash mismatch: $rel" }
      $overlayRows += [ordered]@{ path=$rel.Replace('\','/'); sha256=$sourceHash; size=(Get-Item -LiteralPath $sourcePath).Length }
    }
    $M.source_overlay_mode = 'explicit working-tree cache sources over exact clean commit'
    $M.source_overlay = $overlayRows
  }
}
Phase '3_eol_policy' {
  # .gitattributes pins the end-of-line handling of the patched sources independent of core.autocrlf.
  # Informational: record what this checkout produced; the lifter/driver compare content, not line endings.
  $rows = @()
  foreach($f in 'tests/test_ifctitle_creature_probe.c','tests/test_ifctitle_creature_probe.py','runtime/recomp_context.c','tools/lift_entry_path.py'){
    $p = if($RepoPrefix){ "$RepoPrefix/$f" } else { $f }
    $eolCmd = "git -C `"$src`" ls-files --eol $p"
    $r4 = "$(Run $eolCmd)"; $rows += $r4.Trim()
  }
  $M.eol = $rows
}
Phase '4_pcrecomp' {
  $pc = "$buildRoot\third_party\pcrecomp"
  Run "git clone --no-checkout `"$PcrecompSource`" `"$pc`"" | Out-Null
  Run "git -C `"$pc`" config core.autocrlf true" | Out-Null
  Run "git -C `"$pc`" checkout --detach $PCRE_COMMIT" | Out-Null
  $o = & $Python -I "$here\apply_pcrecomp_patch.py" $pc "$here\patches\P01_pcrecomp_local_mods.patch" "$here\patches\P01_pcrecomp_local_mods.json" 2>&1; $o | Write-Host
  if($LASTEXITCODE){ throw ($o -join "`n") }
}
Phase '5_inputs' {
  $ev = Get-Content "$here\evidence_inputs.json" -Raw | ConvertFrom-Json
  foreach($e in $ev.files){
    $source = if($e.source_env -eq 'GENEWARS_INSTALL_DIR'){ Join-Path $Cfg.Install $e.source_relative } elseif($e.source_env -eq 'GENEWARS_MAP'){ $Cfg.Map } else { throw "unknown input source $($e.source_env)" }
    $dst = Join-Path $buildRoot $e.path
    if(-not (Test-Path -LiteralPath $source)){ throw "input missing for $($e.path): $source ($($e.source_env))" }
    if((Sha $source) -ne $e.sha256){ throw "input $($e.path) from '$source' has SHA-256 $(Sha $source), expected $($e.sha256) (different game build or file?)" }
    New-Item -ItemType Directory -Force (Split-Path $dst) | Out-Null; Copy-Item -LiteralPath $source $dst
  }
  New-Item -ItemType Directory -Force "$buildRoot\work", "$buildRoot\bin" | Out-Null
  $M.inputs_placed = @($ev.files).Count
}
$env:GWRECOMP_BUILD_SDL2_INTERACTIVE = '1'
if($Lift -eq 'reuse'){ $env:GWRECOMP_REUSE_EXISTING_LIFT = '1' }
if($Audit){ $env:PYTHONPATH = "$here\audit"; $env:GW_AUDIT_LOG = "$Work\audit.jsonl" }
Phase '6_build' {
  Push-Location $buildRoot
  try { & cmd.exe /c "`"$Python`" tests\test_ifctitle_creature_probe.py > `"$Work\build.log`" 2>&1" } finally { Pop-Location }
  if($LASTEXITCODE){ throw "driver exit $LASTEXITCODE (see $Work\build.log)" }
  if(-not (Test-Path "$buildRoot\bin\gw_demo_sdl2.exe")){ throw 'no exe produced' }
}
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
Phase '7_deterministic_link' {
  $od = $objectDir
  $names = 'test_ifctitle_creature_probe','ifctitle_creature_probe_closure','lbdataload_callback_init_slice','recomp_context','gw_interrupts','gw_recomp_trace','gw_segments','gw_pit8254','gw_dos_services','gw_vbe_provider','recomp_x87','gw_camera_interpolation','gw_func_coverage','gw_cdda_audio','gw_vsb16','gw_terrain_renderer'
  if($CacheRoot){
    if(-not (Test-Path -LiteralPath $objectCacheManifest -PathType Leaf)){ throw 'cache usage manifest missing after successful build' }
    $usage = Get-Content -LiteralPath $objectCacheManifest -Raw | ConvertFrom-Json
    $objectRecords = @($usage.objects)
    if($usage.schema -ne 'gwrecomp-object-cache-use/1' -or $objectRecords.Count -ne $names.Count){ throw 'cache usage manifest has wrong schema or object count' }
    $recordNames = @($objectRecords | ForEach-Object {$_.name} | Sort-Object -Unique)
    $expectedNames = @($names | ForEach-Object {"$_.obj"} | Sort-Object -Unique)
    if(($recordNames -join '|') -cne ($expectedNames -join '|')){ throw 'cache usage manifest object names differ from deterministic link inputs' }
    $M.object_cache_objects = @($objectRecords)
    $M.object_cache_metrics = [ordered]@{
      hits = @($objectRecords | Where-Object {$_.cache -eq 'hit'}).Count
      misses = @($objectRecords | Where-Object {$_.cache -eq 'miss'}).Count
      bypasses = @($objectRecords | Where-Object {$_.cache -eq 'bypass'}).Count
      newlyStoredObjectBytes = [int64](($objectRecords | Where-Object {$_.cache -eq 'miss'} | Measure-Object -Property size_bytes -Sum).Sum)
    }
    $objs = @()
    foreach($record in $objectRecords){
      $objPath = [System.IO.Path]::GetFullPath($record.path)
      $cachePrefix = ([System.IO.Path]::GetFullPath($od)).TrimEnd('\') + '\'
      $workObjectPrefix = ([System.IO.Path]::GetFullPath("$buildRoot\work\native_ifctitle_plugin_load_at_objs")).TrimEnd('\') + '\'
      $isCacheObject = $objPath.StartsWith($cachePrefix,[System.StringComparison]::OrdinalIgnoreCase)
      $isWorkMiss = $objPath.StartsWith($workObjectPrefix,[System.StringComparison]::OrdinalIgnoreCase)
      if(($record.cache -in @('hit','miss') -and -not $isCacheObject) -or
         ($record.cache -eq 'bypass' -and -not $isWorkMiss) -or
         ($record.cache -notin @('hit','miss','bypass'))){ throw "object path/status escaped its approved storage class: $($record.cache) $objPath" }
      $objFile = Get-Item -LiteralPath $objPath -Force
      if(-not $objFile -or $objFile.PSIsContainer -or ($objFile.Attributes -band [System.IO.FileAttributes]::ReparsePoint)){ throw "cached object is missing, a directory, or a reparse point: $objPath" }
      if((Sha $objPath) -cne $record.sha256 -or $objFile.Length -ne [int64]$record.size_bytes){ throw "cached object changed after compile: $objPath" }
      $objs += $objPath
    }
  } else {
    $objectRecords = @()
    $objs = @($names | % { "$od\$_.obj" })
  }
  $a = @('--target=i686-w64-windows-gnu','-m32','-B',$Cfg.Mingw32Lib,'-o',"$buildRoot\bin\gw_demo_sdl2.det.exe") + $objs + @('-L',$Cfg.Mingw32Lib,'-lSDL2','-lbcrypt','-lwinmm','-lm','-Wl,--no-insert-timestamp')
  $line = "`"$CLANG_X86`" " + (($a | % { '"' + $_ + '"' }) -join ' ')
  Run $line | Out-Null
  $M.link_command = $line
}
Phase '8_manifest' {
  if($CacheRoot){
    $manifestObjects = @($M.object_cache_objects | ForEach-Object {[ordered]@{ name=$_.name; sha256=$_.sha256 }})
  } else {
    $manifestObjects = @(Get-ChildItem $objectDir -Filter *.obj | % { [ordered]@{ name=$_.Name; sha256=(Sha $_.FullName) } })
  }
  $M.outputs = [ordered]@{
    exe_default       = [ordered]@{ path="$buildRoot\bin\gw_demo_sdl2.exe"; sha256=(Sha "$buildRoot\bin\gw_demo_sdl2.exe"); size=(Get-Item "$buildRoot\bin\gw_demo_sdl2.exe").Length }
    exe_deterministic = [ordered]@{ path="$buildRoot\bin\gw_demo_sdl2.det.exe"; sha256=(Sha "$buildRoot\bin\gw_demo_sdl2.det.exe"); size=(Get-Item "$buildRoot\bin\gw_demo_sdl2.det.exe").Length }
    base_c_sha256 = (Sha "$buildRoot\work\ifctitle_creature_probe_closure.base.c"); closure_c_sha256 = (Sha "$buildRoot\work\ifctitle_creature_probe_closure.c")
    objects = $manifestObjects }
  $M.finished = (Get-Date).ToString('o')
}
Save
Write-Host "REBUILD done: deterministic exe $($M.outputs.exe_deterministic.sha256)"
Write-Host "Outputs: $buildRoot\bin   Manifest: $Work\rebuild_manifest.json"
if($CacheLock){ $CacheLock.Dispose() }
