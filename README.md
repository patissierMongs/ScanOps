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
일반 오프라인 ZIP은 `install.ps1` 이 요구하는 **Python 3.13 / 3.12 (x64)** 와 **nmap**이 필요합니다
(3.13 을 먼저 찾습니다). Python을 설치할 수 없는 Windows x64/x86 서버는 Python 런타임이
포함된 all-in-one ZIP을 사용하세요 — 기본 런타임은 **3.13** 입니다.

```powershell
python packaging\build_allinone.py                  # 3.13 → ..\ScanOps_allinone.zip
python packaging\build_allinone.py --python 3.12    # 3.12 → ..\ScanOps_allinone_py312.zip
python packaging\build_allinone.py --arch x86       # 3.13 x86 → ..\ScanOps_allinone_x86.zip
```
세 번들 모두 압축만 풀고 `START.bat` 을 실행하면 됩니다(대상에 Python 설치 불필요). 앱 의존성
버전은 동일하며 런타임과 바이너리 휠의 Python ABI/Windows 아키텍처만 다릅니다. x86은 검증된
CPython 3.13 조합만 지원합니다. 스캔 실행에만 nmap이 따로 필요하고, XML 가져오기는 nmap 없이도
동작합니다.

빌드는 실행에 쓰이지 않는 것만 덜어냅니다(대화형/개발용 표준 라이브러리, 이 앱이 쓰지 않는
SQLAlchemy 방언, 의존성이 함께 배포한 자기 테스트 코드). **기능을 없애는 절단은 하지 않습니다** —
예를 들어 OpenSSL 은 로그인 해시(`hashlib.pbkdf2_hmac`)가 3.12+ 부터 순수 파이썬 대체 구현 없이
`_hashlib` 만 쓰므로 빼면 아무도 로그인하지 못합니다. 덜어낸 이름을 앱이나 의존성이 실제로
import 하면 빌드가 그 자리에서 멈추고(`verify_stdlib_drop`), 같은 검사가 CI 에서도 돕니다
(`backend/tests/test_bundle_slim.py` — 덜어낸 모듈을 전부 막은 인터프리터로 로그인·조회·xlsx
내보내기까지 실제로 태워 봅니다). `--max-mb` 로 산출물 크기 상한을 강제할 수 있습니다.

크기 참고(3.13, 슬림 적용): **약 15 MB**. 이 중 임베디드 CPython 런타임만 약 9.8 MB
(`python313.dll` 2.5 · 표준 라이브러리 2.9 · OpenSSL 2.2 · `sqlite3.dll` 0.85)이고, 나머지는
`pydantic_core` 2.0 · SQLAlchemy 1.6 · 프론트 dist 0.5 입니다. 이 구성으로 한 파일 10 MB 밑은
나오지 않습니다 — 위 항목은 모두 서버가 부팅하고 로그인하는 데 필요합니다.

### 반출 한도에 맞춰 조각으로 나누기
파일 하나의 크기 제한(USB·메일·반출 심사)이 있으면 **지우지 말고 나눕니다.**

```powershell
python packaging\build_allinone.py --split-mb 10 --max-mb 10
# -> ScanOps_allinone.zip.001 (10.0 MB), .002 (5.0 MB), JOIN.bat, .sha256
```
- 받는 쪽에서 **반디집/7-Zip 은 `.001` 을 그대로 열면** 됩니다(나머지 조각은 같은 폴더에 두세요).
- 그런 도구가 없는 서버는 함께 들어 있는 **`JOIN.bat`** 을 실행하면 Windows 기본 `copy /b` 로
  되붙이고 SHA-256 까지 확인합니다. 값이 다르면 합친 파일을 지우고 멈춥니다 — USB 복사가
  중간에 잘린 채로 압축을 풀다 마는 사고를 막기 위해서입니다.
- 형식은 zip 분할 볼륨(`.z01`)이 아니라 단순 바이트 분할입니다. 분할 볼륨은 전용 도구가 없으면
  손쓸 방법이 없지만, 바이트 분할은 도구가 없어도 `copy /b` 로 되돌릴 수 있습니다.
- `--max-mb` 는 **조각 하나의** 한도로 판정합니다(분할하지 않으면 전체 크기).
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

### 스캔 프리셋 (웹 ↔ 단독 스캐너 동기화)
자주 쓰는 스캔 구성은 이름을 붙여 프리셋으로 저장한다. 프리셋 본문은 nmap 플래그가 아니라
**웹 UI 와 같은 옵션 키**로 저장되므로 웹 스캐너와 단독 스캐너가 같은 파일을 해석할 수 있다.
- 웹: 스캔 화면의 `프리셋 선택… / 현재 구성 저장` → 서버 `data/scan_presets.json` 에 저장(auditor 이상).
- 단독 스캐너: `--save-preset`/`--preset` → 스캐너 폴더의 `scanops_presets.json` 에 저장.
- 동기화: 단독 스캐너가 웹서버에 도킹해 **먼저 이름 충돌(같은 이름·다른 내용)을 확인**하고,
  하나라도 있으면 양쪽 모두 그대로 둔 채 충돌 목록만 보고한다(종료 코드 3). 충돌이 없으면 합집합으로
  맞춰 **같은 내용의 프리셋 파일이 두 곳에 존재**하게 된다.
```powershell
python scanner\scanops_scanner.py --sync --server http://<서버IP>:8770 --username auditor1
```

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
- **핑거프린트 시그니처** — `-sV`가 식별하지 못해 `unknown`으로 남은 포트는, `fingerprint-strings`가
  남긴 원시 응답을 `backend/scanops/seed/fingerprint_signatures.json`의 표와 대조해 제품을 되돌린다.
  nmap의 `nmap-service-probes`는 서구 소프트웨어 중심이라 Tibero 같은 국내 엔터프라이즈 제품은
  match 줄이 없어 unknown으로 남는데, 응답 본문에는 제품명이 그대로 들어 있는 경우가 많다.
  **이 표는 코드가 아니라 데이터다** — 파일을 고치고 서버를 재시작하면 반영되며, DB 시드와 달리
  기존 설치에도 그대로 적용된다. 관측된 `service`/`product`가 있으면 **절대 덮어쓰지 않고**,
  판정에 쓰인 시그니처는 비고에 `fingerprint=<id>`로 남는다. 표가 깨져도 스캔 인입은 계속된다.
  제품이 채워지면 표시 식별자·검색·`product_rule`이 함께 살아난다.
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
