@echo off
cd /d "%~dp0"
where python >nul 2>nul
if %errorlevel%==0 (
  python scanops_scanner_gui.py
) else (
  py -3 scanops_scanner_gui.py
)
if errorlevel 1 pause
