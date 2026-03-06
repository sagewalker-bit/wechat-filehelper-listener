@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0calibrate.ps1" %*
endlocal

