@echo off
title ScanOps
cd /d "%~dp0"

REM Install if deps are missing (checks uvicorn, so a half-finished venv re-installs).
if not exist "..\backend\.venv\Lib\site-packages\uvicorn\" (
  echo [Setup] Installing offline dependencies...
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
  if errorlevel 1 ( echo Install failed. & pause & exit /b 1 )
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1"
pause
