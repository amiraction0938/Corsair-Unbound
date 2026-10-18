@echo off
title Corsair Unbound Updater
echo ==========================================
echo   Corsair Unbound - Windows Updater
echo ==========================================
echo.
echo Downloading the latest updater script, please wait...

set "PS1_URL=https://github.com/amiraction0938/Corsair-Unbound/releases/latest/download/corsair-unbound-updater.ps1"
set "TEMP_PS1=%TEMP%\corsair-updater.ps1"

powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri '%PS1_URL%' -OutFile '%TEMP_PS1%'"

if not exist "%TEMP_PS1%" (
    echo.
    echo [ERROR] Failed to download the updater script.
    echo Please check your internet connection and try again.
    pause
    exit /b 1
)

echo.
echo Running updater...
powershell -NoProfile -ExecutionPolicy Bypass -File "%TEMP_PS1%"

echo.
echo Done.
pause