$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$pythonExe = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
    throw ".venv icinde python.exe bulunamadi. Once sanal ortami ve bagimliliklari kurun."
}

Write-Host "[1/3] Python ortami kontrol ediliyor..."
& $pythonExe --version

Write-Host ""
Write-Host "[2/3] Build bagimliliklari yukleniyor..."
& $pythonExe -m pip install -r requirements.txt

Write-Host ""
Write-Host "[3/3] EXE build baslatiliyor..."
& $pythonExe -m PyInstaller WindowsSoftwareInventoryAnalyzer.spec

Write-Host ""
Write-Host "Build tamamlandi."
Write-Host "EXE yolu: $projectRoot\dist\WindowsSoftwareInventoryAnalyzer.exe"
Write-Host ""
Write-Host "Calistirmak icin:"
Write-Host "dist\WindowsSoftwareInventoryAnalyzer.exe"
