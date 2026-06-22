# ScanOps offline (air-gapped) install - installs deps from local wheelhouse, no internet.
# Prerequisite: Python 3.12 (x64) on the server (pre-installed). Wheelhouse ships cp312 wheels
# only (matches the bundled all-in-one Python 3.12.8); pure-python deps are version-independent.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot          # ScanOps/
$backend = Join-Path $root "backend"
$wheelhouse = Join-Path $root "packaging\wheelhouse"

Write-Host "ScanOps offline install starting..." -ForegroundColor Cyan

# --- Python 3.12 (x64) 선택: py 런처(-3.12) 우선, 없으면 python ---
function Test-Py312x64($exe, $launcherArgs) {
  try {
    $info = & $exe @launcherArgs -c "import sys,struct;print('%d.%d' % sys.version_info[:2]);print(struct.calcsize('P')*8)" 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    if ($info[0] -eq "3.12" -and $info[1] -eq "64") { return @{ exe = $exe; args = $launcherArgs } }
  } catch {}
  return $null
}

$cand = @()
if (Get-Command py -ErrorAction SilentlyContinue)     { $cand += ,@("py", @("-3.12")) }
if (Get-Command python -ErrorAction SilentlyContinue) { $cand += ,@("python", @()) }

$pick = $null
foreach ($c in $cand) { $pick = Test-Py312x64 $c[0] $c[1]; if ($pick) { break } }

if (-not $pick) {
  Write-Host "[ERROR] Python 3.12 (x64) 를 찾지 못했습니다." -ForegroundColor Red
  Write-Host "        wheelhouse 는 cp312-win_amd64 컴파일 휠만 포함합니다(SQLAlchemy/greenlet/pydantic_core)." -ForegroundColor Yellow
  Write-Host "        해결: ① Python 3.12 (64-bit) 설치  또는  ② 다른 버전용 휠을 wheelhouse 에 추가." -ForegroundColor Yellow
  if (Get-Command python -ErrorAction SilentlyContinue) {
    $cur = & python -c "import sys,struct;print('%d.%d-%dbit' % (sys.version_info[0],sys.version_info[1],struct.calcsize('P')*8))" 2>$null
    Write-Host "        현재 감지된 python: $cur" -ForegroundColor Yellow
  }
  exit 1
}
$base = $pick.exe; $baseArgs = $pick.args

if (-not (Test-Path (Join-Path $root "frontend\dist\index.html"))) {
  Write-Host "[WARN] frontend\dist missing - running API only." -ForegroundColor Yellow
}

# 1) venv (선택된 3.12 x64 인터프리터로)
$venv = Join-Path $backend ".venv"
if (-not (Test-Path $venv)) { & $base @baseArgs -m venv $venv }
$py = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path $py)) {
  Write-Host "[ERROR] venv 생성 실패 ($venv). ensurepip/venv 모듈을 확인하세요." -ForegroundColor Red
  exit 1
}

# 2) offline install (--no-index : no network)
& $py -m pip install --no-index --find-links $wheelhouse -r (Join-Path $backend "requirements.txt")
if ($LASTEXITCODE -ne 0) {
  Write-Host "[ERROR] 오프라인 휠 설치 실패 (exit $LASTEXITCODE)." -ForegroundColor Red
  Write-Host "        가장 흔한 원인: 파이썬 버전/아키텍처 불일치(휠은 cp312-win_amd64 전용) 또는 pip 누락." -ForegroundColor Yellow
  Write-Host "        직접 진단: `"$py`" -m pip install --no-index --find-links `"$wheelhouse`" -r `"$backend\requirements.txt`"" -ForegroundColor Yellow
  exit 1
}

Write-Host "Install complete. Run: packaging\run.ps1 (or START.bat)" -ForegroundColor Green
