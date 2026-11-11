<#
 GWRecomp - rebuild the v0.7 demo executable from a CLEAN checkout of this repository plus explicit, hash-verified dependencies.
 It reads nothing from historical/frozen project trees: sources come from git, the lifter dependency (pcrecomp) from a pinned commit +
 a versioned patch, and the canonical evidence inputs from tools/rebuild/evidence_inputs.json (SHA-256 verified).

 usage: powershell -NoProfile -File tools\rebuild\rebuild.ps1 -Work <unique dir on E:> [-Commit <sha|ref>] [-Lift regenerate|reuse] [-Audit] [-ReuseObjectCacheId <branch-agent>] [-ObjectCacheDiagnostics] [-DryRun]
 Phases: 1 toolchain lock | 2 clean checkout | 3 eol policy | 4 pcrecomp (pinned commit + patch) | 5 evidence inputs
         6 build (python driver; lift regenerated) | 7 deterministic link | 8 manifest
 Everything is written under -Work (must be on E:). See tools\rebuild\README_BUILD.md.
#>
param([Parameter(Mandatory)][string]$Work,
      [string]$Commit = 'HEAD',
      [ValidateSet('regenerate','reuse')][string]$Lift = 'regenerate',
      [switch]$Audit,
      [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,23}$')][string]$ReuseObjectCacheId,
      [switch]$UseCurrentObjectCacheSources,
      [switch]$ObjectCacheDiagnostics,
      [switch]$DryRun,
      [string]$PcrecompSource = 'E:\GWRecomp\third_party\pcrecomp',
      [string]$Python = 'E:\GWRecomp\.venv\Scripts\python.exe')
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path          # <repo>\tools\rebuild
$repoRoot = (Resolve-Path "$here\..\..").Path
if(-not $Work.StartsWith('E:\')){ throw 'all builds and temporaries must live on E:' }
if(Test-Path -LiteralPath $Work){ throw "work dir $Work already exists (each BuildId requires a new directory)" }
$BuildId = Split-Path -Leaf $Work.TrimEnd('\')
$CacheRoot = $null; $CacheLock = $null
if($ReuseObjectCacheId){
  $CacheRoot = "E:\GWRecomp\build\reusable-object-cache\$ReuseObjectCacheId"
  if(-not $CacheRoot.StartsWith('E:\GWRecomp\build\reusable-object-cache\',[StringComparison]::OrdinalIgnoreCase)){
    throw 'object cache path escaped the E: cache root'
  }
  $WorkFull = [System.IO.Path]::GetFullPath($Work)
  $CacheFull = [System.IO.Path]::GetFullPath($CacheRoot)
  $workPrefix = $WorkFull.TrimEnd('\') + '\'
  $cachePrefix = $CacheFull.TrimEnd('\') + '\'
  if($WorkFull.Equals($CacheFull,[System.StringComparison]::OrdinalIgnoreCase) -or
     $WorkFull.StartsWith($cachePrefix,[System.StringComparison]::OrdinalIgnoreCase) -or
     $CacheFull.StartsWith($workPrefix,[System.StringComparison]::OrdinalIgnoreCase)){
    throw 'BuildId Work and reusable object cache must be separate, non-overlapping E: paths'
  }
}
if($DryRun){
  [pscustomobject]@{ Mode='DRY-RUN'; BuildId=$BuildId; Work=$Work; WorkExists=(Test-Path -LiteralPath $Work)
    ObjectCache=if($CacheRoot){$CacheRoot}else{'disabled (historical per-build object directory)'}
    ObjectCacheSourceOverlay=[bool]$UseCurrentObjectCacheSources
    ObjectCacheDiagnostics=[bool]$ObjectCacheDiagnostics
    CacheExists=if($CacheRoot){Test-Path -LiteralPath $CacheRoot}else{$false}
    Lock='not acquired in DRY-RUN'; NoBuildOrWrites=$true } | Format-List
  return
}
if($CacheRoot){
  New-Item -ItemType Directory -Force $CacheRoot | Out-Null
  try { $CacheLock = [System.IO.File]::Open((Join-Path $CacheRoot 'workspace.lock'),[System.IO.FileMode]::OpenOrCreate,[System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::None) }
  catch { throw "object cache '$ReuseObjectCacheId' is already in use; use a distinct branch-agent cache id or retry later" }
}
$PCRE_COMMIT = '35548b8d0fd8aa853da67edcf7cd6134f6b9cdc7'
$src = "$Work\src"; $tmp = "$Work\tmp"
New-Item -ItemType Directory -Force $Work, $tmp | Out-Null
$objectDir = if($CacheRoot){Join-Path $CacheRoot 'objects'}else{"$src\work\native_ifctitle_plugin_load_at_objs"}
$objectCacheManifest = Join-Path $Work 'object-cache-usage.json'
$M = [ordered]@{ schema='gwrecomp-rebuild/1'; build_id=$BuildId; started=(Get-Date).ToString('o'); work=$Work; object_cache_id=$ReuseObjectCacheId; object_cache_path=$CacheRoot; object_cache_diagnostics=[bool]$ObjectCacheDiagnostics; lift=$Lift; requested_commit=$Commit; pcrecomp_commit=$PCRE_COMMIT; phases=[ordered]@{} }
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
Get-ChildItem Env: | ? { $_.Name -match '^(GWRECOMP_|GW_)' } | % { Remove-Item "Env:$($_.Name)" }
$env:TEMP=$tmp; $env:TMP=$tmp; $env:TMPDIR=$tmp; $env:PYTHONDONTWRITEBYTECODE='1'
if($CacheRoot){ $env:GWRECOMP_OBJECT_CACHE=$objectDir; $env:GWRECOMP_OBJECT_CACHE_LOCKED='1'; $env:GWRECOMP_OBJECT_CACHE_USAGE=$objectCacheManifest }
if($ObjectCacheDiagnostics){ $env:GWRECOMP_OBJECT_CACHE_DIAGNOSTICS='1' }
$MINGW = 'E:\msys64\mingw32\bin'; $env:PATH = "$MINGW;E:\msys64\usr\bin;" + $env:PATH
$CLANG_X86 = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\bin\clang.exe'
$CLANG_X64 = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\x64\bin\clang.exe'

# resolve the commit to build (exact sha) and the object store to clone from
$c0 = "git -C `"$repoRoot`" rev-parse --verify $Commit"; $r0 = Run $c0; $COMMIT_SHA = "$r0".Trim()
$c1 = "git -C `"$repoRoot`" rev-parse --path-format=absolute --git-common-dir"; $r1 = Run $c1; $RepoSource = "$r1".Trim()
$M.commit = $COMMIT_SHA

Phase '1_toolchain' {
  $lock = Get-Content "$here\toolchain.lock.json" -Raw | ConvertFrom-Json
  $got = [ordered]@{ clang_x64_sha=Sha $CLANG_X64; clang_x86_sha=Sha $CLANG_X86; ld=(& "$MINGW\ld.exe" --version)[0]; gcc=(& "$MINGW\gcc.exe" --version)[0]
    python=((& $Python --version) -join ''); python_exe_sha256=Sha $Python; sdl2_dll_sha=Sha "$MINGW\SDL2.dll"; libSDL2_sha=Sha 'E:\msys64\mingw32\lib\libSDL2.dll.a'
    msys_packages=((& E:\msys64\usr\bin\pacman.exe -Q mingw-w64-i686-SDL2 mingw-w64-i686-gcc mingw-w64-i686-crt-git mingw-w64-i686-binutils) -join '; ') }
  $bad = @(); foreach($k in 'clang_x64_sha','clang_x86_sha','ld','gcc','python','sdl2_dll_sha','libSDL2_sha','msys_packages'){ if($got[$k] -ne $lock.tools.$k){ $bad += "$k : have '$($got[$k])' want '$($lock.tools.$k)'" } }
  if($got.python_exe_sha256 -ne $lock.python_exe_sha256){ $bad += 'python_exe_sha256' }
  $pk = & $Python -I -c "import importlib.metadata as m;print(';'.join(sorted(d.metadata['Name']+'=='+d.version for d in m.distributions())))"
  if($pk -ne ($lock.python_packages -join ';')){ $bad += "python packages differ: $pk" }
  foreach($p in $lock.external_inputs.PSObject.Properties){ if(-not (Test-Path -LiteralPath $p.Name) -or (Sha $p.Name) -ne $p.Value){ $bad += "external input changed/missing: $($p.Name)" } }
  $M.toolchain = $got; if($bad){ throw ("toolchain.lock mismatch:`n" + ($bad -join "`n")) }
}
Phase '2_clean_checkout' {
  Run "git clone --no-checkout --local `"$RepoSource`" `"$src`"" | Out-Null
  Run "git -C `"$src`" checkout --detach $COMMIT_SHA" | Out-Null
  $c2 = "git -C `"$src`" rev-parse HEAD"; $r2 = Run $c2; if("$r2".Trim() -ne $COMMIT_SHA){ throw "checkout HEAD mismatch" }
  $c3 = "git -C `"$src`" status --porcelain"; $r3 = Run $c3; if("$r3".Trim()){ throw "checkout not clean: $r3" }
  $M.checkout_head = $COMMIT_SHA
}
if($UseCurrentObjectCacheSources){
  Phase '2b_object_cache_source_overlay' {
    $overlayRows = @()
    foreach($rel in 'tests\test_ifctitle_creature_probe.py','tools\rebuild\object_cache.py'){
      $sourcePath = Join-Path $repoRoot $rel
      $destination = Join-Path $src $rel
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
  # tools\rebuild\.. .gitattributes pins CRLF for the four patched sources and LF for the two CD-DA files, independent of core.autocrlf
  $want = @{ 'tests/test_ifctitle_creature_probe.c'='w/crlf'; 'tests/test_ifctitle_creature_probe.py'='w/crlf'; 'runtime/recomp_context.c'='w/crlf'; 'tools/lift_entry_path.py'='w/crlf'; 'runtime/gw_cdda_audio.c'='w/lf'; 'runtime/gw_cdda_audio.h'='w/lf' }
  $bad = @()
  foreach($f in $want.Keys){ $c4 = "git -C `"$src`" ls-files --eol $f"; $r4 = "$(Run $c4)"; if($r4 -notmatch [regex]::Escape($want[$f])){ $bad += "$f : $r4" } }
  if($bad){ throw ("eol policy not honoured by this checkout:`n" + ($bad -join "`n")) }
}
Phase '4_pcrecomp' {
  Run "git clone --no-checkout `"$PcrecompSource`" `"$src\third_party\pcrecomp`"" | Out-Null
  Run "git -C `"$src\third_party\pcrecomp`" config core.autocrlf true" | Out-Null
  Run "git -C `"$src\third_party\pcrecomp`" checkout --detach $PCRE_COMMIT" | Out-Null
  $o = & $Python -I "$here\apply_pcrecomp_patch.py" "$src\third_party\pcrecomp" "$here\patches\P01_pcrecomp_local_mods.patch" "$here\patches\P01_pcrecomp_local_mods.json" 2>&1; $o | Write-Host
  if($LASTEXITCODE){ throw ($o -join "`n") }
}
Phase '5_evidence_inputs' {
  $ev = Get-Content "$here\evidence_inputs.json" -Raw | ConvertFrom-Json
  foreach($e in $ev.files){
    $dst = Join-Path $src $e.path
    if(-not (Test-Path -LiteralPath $e.source)){ throw "evidence source missing: $($e.source)" }
    New-Item -ItemType Directory -Force (Split-Path $dst) | Out-Null; Copy-Item -LiteralPath $e.source $dst
    if((Sha $dst) -ne $e.sha256){ throw "evidence hash mismatch: $($e.path)" }
  }
  New-Item -ItemType Directory -Force "$src\work", "$src\bin" | Out-Null
  $M.evidence_placed = @($ev.files).Count
}
$env:GWRECOMP_BUILD_SDL2_INTERACTIVE = '1'; $env:GWRECOMP_PYTHON = $Python
if($Lift -eq 'reuse'){ $env:GWRECOMP_REUSE_EXISTING_LIFT = '1' }
if($Audit){ $env:PYTHONPATH = "$here\audit"; $env:GW_AUDIT_LOG = "$Work\audit.jsonl" }
Phase '6_build' {
  Push-Location $src
  try { & cmd.exe /c "`"$Python`" tests\test_ifctitle_creature_probe.py > `"$Work\build.log`" 2>&1" } finally { Pop-Location }
  if($LASTEXITCODE){ throw "driver exit $LASTEXITCODE (see $Work\build.log)" }
  if(-not (Test-Path "$src\bin\gw_demo_sdl2.exe")){ throw 'no exe produced' }
}
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
Phase '7_deterministic_link' {
  $od = $objectDir
  # Keep this list aligned with the runtime objects emitted by the V20 native probe build.
  # The v0.7 reference uses its own historical rebuild script and does not link this Miles driver.
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
      $workObjectPrefix = ([System.IO.Path]::GetFullPath("$src\work\native_ifctitle_plugin_load_at_objs")).TrimEnd('\') + '\'
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
  $a = @('--target=i686-w64-windows-gnu','-m32','-o',"$src\bin\gw_demo_sdl2.det.exe") + $objs + @('-L','E:\msys64\mingw32\lib','-lSDL2','-lbcrypt','-lwinmm','-lm','-Wl,--no-insert-timestamp')
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
    exe_default       = [ordered]@{ path="$src\bin\gw_demo_sdl2.exe"; sha256=(Sha "$src\bin\gw_demo_sdl2.exe"); size=(Get-Item "$src\bin\gw_demo_sdl2.exe").Length }
    exe_deterministic = [ordered]@{ path="$src\bin\gw_demo_sdl2.det.exe"; sha256=(Sha "$src\bin\gw_demo_sdl2.det.exe"); size=(Get-Item "$src\bin\gw_demo_sdl2.det.exe").Length }
    base_c_sha256 = (Sha "$src\work\ifctitle_creature_probe_closure.base.c"); closure_c_sha256 = (Sha "$src\work\ifctitle_creature_probe_closure.c")
    objects = $manifestObjects }
  $M.finished = (Get-Date).ToString('o')
}
Save
Write-Host "REBUILD done: deterministic exe $($M.outputs.exe_deterministic.sha256)"
if($CacheLock){ $CacheLock.Dispose() }
