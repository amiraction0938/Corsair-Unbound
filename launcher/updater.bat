@echo off
title Corsair Unbound Updater
echo Starting secure updater...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0updater.ps1"
echo.
pause