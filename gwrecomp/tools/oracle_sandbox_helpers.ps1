function Assert-OracleSandbox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][scriptblock]$Verifier,
        [Parameter(Mandatory=$true)][string]$Path
    )
    # PowerShell-native contract: normal completion is success; verifier THROW
    # is failure. $LASTEXITCODE intentionally has no role here.
    try {
        & $Verifier -Path $Path
        return $true
    } catch {
        throw "Oracle sandbox verification failed: $($_.Exception.Message)"
    }
}

function Get-OracleTreeManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Root)
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $items = [System.Collections.Generic.List[object]]::new()
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($rootPath)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) {
            if ($item.PSIsContainer) {
                if ($item.Name -notin @('$RECYCLE.BIN','System Volume Information')) { $pending.Push($item.FullName) }
                continue
            }
            $relative = $item.FullName.Substring($rootPath.Length).TrimStart('\')
            $extension = $item.Extension.ToLowerInvariant()
            if ($item.Name -ieq 'ADDRESS.TXT' -or $item.Name -ieq 'GW.ERR') { continue }
            if ($item.Length -gt 2GB -or ($extension -in @('.txt','.err','.log','.trace','.trc','.dmp','.dump') -and $item.Length -gt 512MB)) { continue }
            $items.Add([pscustomobject]@{ Relative=$relative; Length=[long]$item.Length; Hash=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash })
        }
    }
    return $items
}

function Test-OracleSeedRestored {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Seed,[Parameter(Mandatory=$true)][string]$Stage)
    $source = Get-OracleTreeManifest -Root $Seed
    if ($source.Count -eq 0) { return $false }
    foreach ($entry in $source) {
        $target = Join-Path $Stage $entry.Relative
        if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { return $false }
        $item = Get-Item -LiteralPath $target -Force
        if ($item.Length -ne $entry.Length) { return $false }
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256 -ErrorAction Stop).Hash -ne $entry.Hash) { return $false }
    }
    return $true
}

function Restore-OracleSeedSafely {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Seed,[Parameter(Mandatory=$true)][string]$Stage)
    $source = Get-OracleTreeManifest -Root $Seed
    if ($source.Count -eq 0) { throw 'Seed contains no eligible guest files; refusing to claim it was restored.' }
    $copied = 0
    foreach ($entry in $source) {
        $from = Join-Path $Seed $entry.Relative
        $to = Join-Path $Stage $entry.Relative
        if (Test-Path -LiteralPath $to -PathType Leaf) {
            $existing = Get-Item -LiteralPath $to -Force
            if ($existing.Length -ne $entry.Length -or (Get-FileHash -LiteralPath $to -Algorithm SHA256 -ErrorAction Stop).Hash -ne $entry.Hash) {
                throw "Seed conflict at '$($entry.Relative)'; preserving both contents and refusing overwrite."
            }
            continue
        }
        $parent = Split-Path -Parent $to
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Copy-Item -LiteralPath $from -Destination $to
        $copied++
    }
    if (-not (Test-OracleSeedRestored -Seed $Seed -Stage $Stage)) { throw 'Seed restore postcondition failed; original seed was preserved.' }
    return $copied
}

function Enable-OracleConfigs {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$OracleDirectory,[Parameter(Mandatory=$true)][string]$Stage)
    $files = @(Get-ChildItem -LiteralPath $OracleDirectory -Filter '*.conf' -File)
    if ($files.Count -eq 0) { throw 'No official oracle configs found to enable.' }
    foreach ($file in $files) {
        $text = [IO.File]::ReadAllText($file.FullName)
        if ($text -match '(?im)^\s*mount\s+C\s+E:\\GWRecomp\\build\\dosboxx_oracle\\__VHDX_REQUIRED__\s*$') {
            $backup = "$($file.FullName).vhdx-disabled.bak"
            if (-not (Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $file.FullName -Destination $backup }
            $text = [regex]::Replace($text, '(?im)^\s*mount\s+C\s+E:\\GWRecomp\\build\\dosboxx_oracle\\__VHDX_REQUIRED__\s*$', "mount C $Stage")
            [IO.File]::WriteAllText($file.FullName, $text, [Text.Encoding]::ASCII)
        }
        $mounts = @([regex]::Matches($text, '(?im)^\s*mount\s+C\s+(\S+)\s*$'))
        if ($mounts.Count -ne 1 -or $mounts[0].Groups[1].Value.TrimEnd('\') -ine $Stage.TrimEnd('\')) {
            throw "Config $($file.Name) does not mount the verified staging path; leaving it disabled."
        }
    }
    $sentinel = Join-Path $OracleDirectory '__VHDX_REQUIRED__'
    if (Test-Path -LiteralPath $sentinel -PathType Leaf) { Remove-Item -LiteralPath $sentinel -Force }
}

function Test-OracleConfigsReady {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$OracleDirectory,[Parameter(Mandatory=$true)][string]$Stage)
    $files = @(Get-ChildItem -LiteralPath $OracleDirectory -Filter '*.conf' -File)
    if ($files.Count -eq 0) { return $false }
    foreach ($file in $files) {
        $text = [IO.File]::ReadAllText($file.FullName)
        $mounts = @([regex]::Matches($text, '(?im)^\s*mount\s+C\s+(\S+)\s*$'))
        if ($mounts.Count -ne 1 -or $mounts[0].Groups[1].Value.TrimEnd('\') -ine $Stage.TrimEnd('\')) { return $false }
    }
    return $true
}
