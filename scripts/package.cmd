@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0package.ps1" %*
endlocal

