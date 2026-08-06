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
일반 오프라인 ZIP은 `install.ps1` 이 요구하는 **Python 3.12 (x64)** 와 **nmap**이 필요합니다.
Python을 설치할 수 없는 Windows x64 서버는 Python 런타임이 포함된 all-in-one ZIP을 사용하세요.
all-in-one 은 **3.12 / 3.13** 두 런타임으로 만들 수 있습니다.

```powershell
python packaging\build_allinone.py                  # 3.12 → ..\ScanOps_allinone.zip
python packaging\build_allinone.py --python 3.13    # 3.13 → ..\ScanOps_allinone_py313.zip
```
두 번들 모두 압축만 풀고 `START.bat` 을 실행하면 됩니다(대상에 Python 설치 불필요). 앱 의존성
버전은 두 번들이 동일하며, 런타임과 바이너리 휠(cp312/cp313)만 다릅니다. 스캔 실행에만 nmap이
따로 필요하고, XML 가져오기는 nmap 없이도 동작합니다.
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
Python 3.8+ 와 nmap 만 있으면 Windows/Linux/macOS에서 동작한다. 생성 폴더의 `.xml`과
`*.manifest.json`을 ScanOps의 `스캔 > 폴더째 가져오기`로 함께 업로드하면 제외 대상과 성공한
실행 단위의 미관측 범위까지 검증해 반영한다. XML만 올리는 구형 경로는 관측된 호스트만 닫힘 판정한다.
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
- 다만 `service`로 **분류가 전혀 안 되는** 경우에 한해 Server 배너를 **보조 분류 키**로 쓴다.
  Server 헤더가 나왔다는 것은 `http-server-header`/`http-headers`가 실제 HTTP 응답을 받아냈다는
  뜻이라, nmap의 저신뢰 추측(`uniconv`·`apple-iphoto` 등)보다 강한 증거다. taxonomy는 제품명이
  아니라 서비스명으로 키가 잡혀 있으므로 "이 포트는 HTTP로 말한다"는 사실만 되돌려 `http`
  (TLS 증거가 있으면 `https`)로 분류한다. 이미 `service`로 분류되는 발견은 건드리지 않아 기존
  위험등급이 흔들리지 않으며, 보조 키가 쓰인 건은 `관측근거` 항목으로 판정 이유를 남긴다.
- **조직 위험규칙**은 `service`뿐 아니라 **제품(`product_rule`)·CPE(`cpe_rule`)**로도 걸 수 있다.
  `service`가 저신뢰 추측이라 못 잡히는 포트도 제품/CPE로는 잡힌다. 두 규칙은 **부분일치**다 —
  nmap의 product에는 `Samba smbd`처럼 서술 접미사가 붙고 CPE는 여러 개가 `;`로 이어져 저장되므로
  정확일치로는 실무에서 쓸 수 없다. 규칙 화면이 저장 전에 **매칭 발견 수**를 보여주므로 과매칭을
  눈으로 확인할 수 있다. 예: `cpe_rule`에 `openbsd:openssh`, `product_rule`에 `vsftpd`.
- `open`과 UDP의 `open|filtered`는 활성 finding이다. `closed`/`filtered` 행 자체는 새 finding으로
  인입하지 않는다. 정상 완료된 구조화 실행 단위(단계 스캔 전체 또는 레거시의 완료 배치)는
  **제외 후 유효 타깃 × 요청한 port/proto 범위**에서 미관측된 기존 finding도 닫는다. 제외한 타깃은
  판정 범위 밖이라 열린 상태를 유지하고, 선택 재스캔은 선택한 키만 닫힘 후보로 삼는다. 실패·중지된
  실행 단위의 결과는 닫힘에 쓰지 않으며, 그 전에 완료·인입된 레거시 배치의 판정은 유지된다. 단독
  스캐너는 원본 XML을 바꾸지 않고 versioned manifest의 파일 크기·SHA-256·실제 target을 검증해 같은
  계약을 전달한다. TCP 식별 단계와 `--host-timeout` 실행은 관측 보강만 하며 미관측 닫힘 권한은 없다.

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
