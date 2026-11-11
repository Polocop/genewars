# Script de inicio rápido para GeneWars Recompilado (GWRecomp)
$ErrorActionPreference = "Stop"
$Workspace = "E:/GWRecomp"
Set-Location $Workspace

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "       GENEWARS RECOMPILADO (GWRecomp) - SDL2     " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

$ExePath = "$Workspace/bin/gw_demo_sdl2.exe"
if (-not (Test-Path $ExePath)) {
    Write-Host "[ERROR] No se encuentra el ejecutable en $ExePath" -ForegroundColor Red
    Write-Host "Asegúrate de compilar el proyecto antes de ejecutar." -ForegroundColor Yellow
    Exit 1
}

Write-Host "[INFO] Entorno configurado correctamente." -ForegroundColor Green
Write-Host "[INFO] Arrancando bin/gw_demo_sdl2.exe en modo interactivo..." -ForegroundColor Green
Write-Host "[INFO] (Pulsa Esc para opciones, F7 para FPS sin límite)" -ForegroundColor DarkGray
Write-Host ""

& $ExePath
