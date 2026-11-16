@echo off
setlocal
title Corsair Unbound Updater
echo ==========================================
echo   Corsair Unbound - Windows Updater
echo ==========================================
echo.
echo Downloading the latest updater script, please wait...

set "PS1_URL=https://github.com/amiraction0938/Corsair-Unbound/releases/latest/download/corsair-unbound-updater.ps1"
rem SECURITY/BUG FIX: use a unique file name and delete any old copy first. The old fixed name
rem (%TEMP%\corsair-updater.ps1) meant that a FAILED download still "succeeded" the exist-check
rem whenever an older copy was lying around, and that stale (or planted) script was then executed.
set "TEMP_PS1=%TEMP%\corsair-updater-%RANDOM%%RANDOM%.ps1"
if exist "%TEMP_PS1%" del /f /q "%TEMP_PS1%" >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}; try { Invoke-WebRequest -UseBasicParsing -Uri '%PS1_URL%' -OutFile '%TEMP_PS1%' -ErrorAction Stop } catch { Write-Host $_.Exception.Message; exit 1 }"
if errorlevel 1 goto :download_failed
if not exist "%TEMP_PS1%" goto :download_failed

echo.
echo Running updater...
powershell -NoProfile -ExecutionPolicy Bypass -File "%TEMP_PS1%"
set "RESULT=%ERRORLEVEL%"
del /f /q "%TEMP_PS1%" >nul 2>&1

echo.
if not "%RESULT%"=="0" echo [WARNING] The updater finished with an error (code %RESULT%).
echo Done.
pause
exit /b %RESULT%

:download_failed
if exist "%TEMP_PS1%" del /f /q "%TEMP_PS1%" >nul 2>&1
echo.
echo [ERROR] Failed to download the updater script.
echo Please check your internet connection and try again.
pause
exit /b 1
