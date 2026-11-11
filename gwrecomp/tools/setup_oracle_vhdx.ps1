# Compatibility entry point. The only supported physical setup now mounts the
# bounded VHDX over the exact legacy guest-C staging path and is fail-closed.
Write-Warning 'This setup script was superseded. Running the supported admin setup.'
& (Join-Path $PSScriptRoot 'setup_oracle_vhdx_admin.ps1')
