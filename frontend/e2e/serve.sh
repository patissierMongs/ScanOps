#!/usr/bin/env bash
# E2E 백엔드 런처 — Playwright webServer 가 호출. 깨끗한 데이터 디렉터리에 시드한 뒤
# 빌드된 SPA(dist)를 FastAPI 로 서빙한다(같은 오리진, 실제 운영과 동일한 구성).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # frontend/e2e
REPO="$(cd "$HERE/../.." && pwd)"                       # 저장소 루트

export SCANOPS_DATA_DIR="${SCANOPS_DATA_DIR:-$REPO/backend/.e2e-data}"
export SCANOPS_SCAN_SCOPE=""          # E2E 는 스코프 제한 없이
export SCANOPS_E2E_PASSWORD="${SCANOPS_E2E_PASSWORD:-scanops-e2e}"
# seed.py 는 스크립트 디렉터리를 sys.path 에 올리므로 backend 를 명시적으로 얹어 scanops 를 찾게 한다.
export PYTHONPATH="$REPO/backend${PYTHONPATH:+:$PYTHONPATH}"

rm -rf "$SCANOPS_DATA_DIR"            # 매 실행 신선한 상태

# dist 가 없으면(로컬 최초 실행) 먼저 빌드. CI 는 별도 build 스텝이 선행한다.
if [ ! -f "$REPO/frontend/dist/index.html" ]; then
  echo "[e2e] dist 없음 → 빌드"
  (cd "$REPO/frontend" && npm run build)
fi

cd "$REPO/backend"
python "$HERE/seed.py"
exec python -m uvicorn scanops.main:app --host 127.0.0.1 --port 8770
