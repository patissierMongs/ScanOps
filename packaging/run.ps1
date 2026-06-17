# ScanOps server - team opens http://<server-ip>:8770/ in a browser.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$py = Join-Path $backend ".venv\Scripts\python.exe"

if (-not (Test-Path $py)) {
  Write-Host "[ERROR] Run packaging\install.ps1 first." -ForegroundColor Red
  exit 1
}
Set-Location $backend
Write-Host "ScanOps running -> http://localhost:8770/  (Ctrl+C to stop)" -ForegroundColor Green
& $py -m uvicorn scanops.main:app --host 0.0.0.0 --port 8770
