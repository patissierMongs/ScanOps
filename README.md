# ScanOps

사내 팀용 **네트워크 노출 점검 라이프사이클 플랫폼**.
nmap 스캔 → 분류·위험등급·KISA/NIS 근거 → 발견 영속 → 담당/마감 배정 →
**재스캔으로 조치 자동 검증** → 부서통보 → 감사 리포트까지 한 루프로 닫는다.

설계·결정·데이터모델은 [`DESIGN.md`](./DESIGN.md) 참고.

## 구성
- **backend/** — FastAPI + SQLite (단일 진실원천). 스캔 실행·파싱·분류·라이프사이클 API.
- **frontend/** — React + Vite. 빌드된 `dist/` 를 FastAPI 가 한 포트로 서빙.
- **packaging/** — 에어갭 설치용 wheelhouse + 설치/실행 스크립트.
- **scanner/** — ScanOps 서버 없이 스캔 서버에서 단독 실행하는 nmap 래퍼.
- **scripts/** — taxonomy 시드 생성 등.

## 빠른 시작 (개발)
```powershell
# 백엔드
cd backend
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m uvicorn scanops.main:app --port 8770
# 프론트 (Node.js 20.19+ 또는 22.12+, 개발 핫리로드, /api 는 8770 으로 프록시)
cd frontend && npm install && npm run dev
```

## 에어갭(오프라인) 배포
일반 오프라인 ZIP은 wheelhouse 계약에 맞는 **Python 3.12 (x64)** 와 **nmap**이 필요합니다.
Python을 설치할 수 없는 Windows x64 서버는 Python 3.12 런타임이 포함된 all-in-one ZIP을 사용하세요.
```powershell
# 1) 프론트 빌드(Node.js 20.19+ 또는 22.12+, 인터넷 되는 PC에서 1회) → frontend/dist 생성
cd frontend && npm install && npm run build
# 2) ScanOps 폴더 전체를 대상 서버로 복사 후:
powershell -ExecutionPolicy Bypass -File packaging\install.ps1   # wheelhouse 에서 오프라인 설치
packaging\start.bat                                             # 서버 실행 (0.0.0.0:8770)
```
- 최초 실행 시 `backend/data/INITIAL_ADMIN.txt` 에 관리자(admin) 임시 비밀번호 생성.
- 팀은 `http://<서버IP>:8770/` 브라우저 접속.

## 단독 스캐너
스캔 서버에서 ScanOps 전체를 실행할 필요가 없으면 `scanner/scanops_scanner.py`만 복사해서 사용한다.
Python 3.8+ 와 nmap 만 있으면 Windows/Linux/macOS에서 동작하며, 생성된 `.xml`을 ScanOps의
`스캔 > XML 가져오기`로 업로드하면 된다.
```powershell
python scanner\scanops_scanner_gui.py
python scanner\scanops_scanner.py 10.0.0.10 --ports 22,80,443 --name branch-a
python scanner\scanops_scanner.py --targets-file targets.txt --ports 1-1024 --batch-size 128 --name weekly
python scanner\scanops_scanner.py --resume scanops_scans\weekly.state.json
```
자세한 사용법은 [`scanner/README.md`](./scanner/README.md) 참고.

## 역할
- **admin** — 사용자 관리 + 전체 권한 + 감사 로그 열람
- **auditor** — 스캔 실행·발견 운영(상태/담당/마감)·통보
- **viewer** — 열람 전용

## 보안/운영
- **스캔 허용 대역(scope)** — `SCANOPS_SCAN_SCOPE` 에 CIDR/IP 를 콤마·공백으로 지정하면
  그 범위 밖 타겟은 스캔 시작 전에 거절된다(오타·잘못 붙여넣은 사외 대역 스캔 사고 방지).
  **빈 값만** 제한 없음이며, 잘못된 토큰이나 정상+오류 혼합 설정은 health 503과 함께 전체가 거절된다.
  예: `SCANOPS_SCAN_SCOPE="10.0.0.0/8 192.168.0.0/16"`.
- **인증 토큰 폐기** — 본인 비밀번호 변경과 관리자 비밀번호 재설정은 해당 사용자의 기존 토큰을
  모두 즉시 무효화한다. 계정 비활성화도 기존 토큰을 즉시 거절한다. 본인 변경 후에는 새 비밀번호로
  다시 로그인해야 하며, 변경·재설정은 감사 로그에 남는다.
- **업로드 한도** — XML/XLSX는 파일별·묶음별 한도를 청크 단위로 검사하고, 업로드 요청 본문도
  multipart 파싱 완료 전에 상한을 적용한다. 인터넷 경계에 배치할 때는 프록시에도 동일하거나 더 작은
  요청 본문 한도를 설정한다.
- **감사 로그** — 로그인(성공/실패)·스캔 실행/중지/이어하기/가져오기·규칙 변경을
  `누가·언제·무엇`으로 기록. `GET /api/audit`(admin 전용)로 조회.
- **재시작 안전성** — 서버가 재시작되면 워커가 사라진 실행은 `interrupted` 로 정직하게
  표기된다(좀비 '실행 중' 방지). 자동 복구는 하지 않으며, 필요 시 **[이어하기]** 로 수동 재개.

## 스캔 결과 식별과 라이프사이클
- Nmap `service`는 프로토콜 분류·taxonomy·위험 규칙의 안정 키로 유지한다.
- HTTP/NSE의 자기신고 `Server`는 별도 관측 증거로 저장한다. 화면·검색·내보내기·감사 리포트의
  표시 식별자는 **Server → product+version → service** 순서지만, Server가 taxonomy를 덮어쓰지는 않는다.
- `open`과 UDP의 `open|filtered`는 활성 finding이다. `closed`/`filtered` 행 자체는 새 finding으로
  인입하지 않고, 실제로 검사한 host/port/proto 범위에서 활성 finding이 사라졌을 때만 닫힘 처리한다.
  전체 단계 스캔은 실제 생존 확인 호스트만, 선택 재스캔은 선택한 키만 닫힘 후보로 삼는다.

## 테스트
```powershell
cd backend && .venv\Scripts\python -m pip install -r requirements-dev.txt
cd backend && .venv\Scripts\python -m pytest -q
```
CI(`.github/workflows/ci.yml`)에서 백엔드 pytest(Python 3.11/3.12) + 프론트
`npm test`/`npm audit`/빌드를 PR마다 자동 검증한다. 별도 Runtime E2E와 Package Runtime Smoke는
실제 Nmap·브라우저·오프라인 ZIP 실행 계약을 검증한다.

## 자산 출처
스캔·식별·분류 도메인 로직(서비스 taxonomy 105종, 추측/확인 식별, NSE 추출)은
자매 프로젝트 `nmapParser` 의 검증된 로직을 포팅한 것. (원본 불변, 복제 사용)
