# ScanOps offline (air-gapped) install - installs deps from local wheelhouse, no internet.
# Prerequisite: Python 3.12 (x64) on the server (pre-installed). Wheelhouse ships cp312 wheels
# only (matches the bundled all-in-one Python 3.12.8); pure-python deps are version-independent.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot          # ScanOps/
$backend = Join-Path $root "backend"
$wheelhouse = Join-Path $root "packaging\wheelhouse"

Write-Host "ScanOps offline install starting..." -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  Write-Host "[ERROR] Python 3.12 (x64) is required. Please install it first." -ForegroundColor Red
  exit 1
}
if (-not (Test-Path (Join-Path $root "frontend\dist\index.html"))) {
  Write-Host "[WARN] frontend\dist missing - running API only." -ForegroundColor Yellow
}

# 1) venv
$venv = Join-Path $backend ".venv"
if (-not (Test-Path $venv)) { python -m venv $venv }
$py = Join-Path $venv "Scripts\python.exe"

# 2) offline install (--no-index : no network)
& $py -m pip install --no-index --find-links $wheelhouse -r (Join-Path $backend "requirements.txt")
if ($LASTEXITCODE -ne 0) {
  Write-Host "[ERROR] pip install failed (exit $LASTEXITCODE)." -ForegroundColor Red
  exit 1
}

Write-Host "Install complete. Run: packaging\run.ps1 (or START.bat)" -ForegroundColor Green
