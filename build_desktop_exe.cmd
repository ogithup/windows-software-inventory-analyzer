@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%build_desktop_exe.ps1"

if errorlevel 1 (
  echo.
  echo Build basarisiz oldu.
  exit /b 1
)

echo.
echo Build basarili.
echo EXE: %SCRIPT_DIR%dist\WindowsSoftwareInventoryAnalyzer.exe
endlocal
