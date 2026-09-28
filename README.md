# ScanOps

nmap 스캔 결과를 발견(finding) 단위로 저장하고, 담당 배정부터 재스캔 조치 확인, 감사 리포트까지 한 화면에서 관리하는 사내 네트워크 노출 점검 도구입니다.

**한국어** | [English](README.en.md)

![XML 가져오기부터 재스캔 조치 확인까지](docs/images/scan-import-flow.gif)

위 화면은 저장소에 들어 있는 `samples/scanA.xml`(3000·8080·9000 포트 열림)을 가져오고, 3000 포트를 `처리중`으로 바꾼 뒤, 3000 포트가 닫힌 `samples/scanB.xml`을 가져와 자동으로 닫힘이 확인되는 과정입니다. 나머지 데이터는 `test_samples/`의 가상 스캔 결과와 자산대장입니다.

## 주요 기능

| 기능 | 설명 |
|---|---|
| 스캔 실행 | 대상 IP(Internet Protocol)·대역을 입력하면 서버가 nmap을 실행합니다. 기본은 단계 스캔(호스트 발견 → TCP(Transmission Control Protocol) 포트 찾기 → UDP(User Datagram Protocol) 포트 찾기 → 서비스 식별)이며, 중지·이어하기를 지원합니다. |
| 결과 가져오기 | 다른 곳에서 돌린 nmap XML(Extensible Markup Language) 파일이나 단독 스캐너 결과 폴더를 그대로 업로드합니다. |
| 발견 관리 | 포트마다 발견 하나가 생기고, 상태(미조치·처리중·정상처리)·마감·담당자를 지정합니다. 컬럼 빌더로 표 구성을 바꾸고 CSV(Comma-Separated Values)·XLSX(Excel 통합 문서)로 내보냅니다. |
| 재스캔 조치 확인 | 다음 스캔에서 포트가 닫혀 있으면 발견을 자동으로 닫고 이력에 남깁니다. 선택한 발견만 다시 스캔할 수도 있습니다. |
| 분류와 위험등급 | 서비스 105종 분류표로 위험등급과 KISA(한국인터넷진흥원)·국정원(NIS, National Intelligence Service) 근거를 붙입니다. 조직 규칙은 서비스·제품·CPE(Common Platform Enumeration)로 걸 수 있습니다. |
| 시간축 히트맵 | 스캔 회차별로 포트가 새로 열렸는지, 계속 열려 있는지, 닫혔는지를 한 표로 봅니다. |
| 자산대장·부서통보 | 엑셀/CSV 자산대장을 올리면 IP로 부서·담당자를 연결합니다. 부서별 통보문을 만들어 기록합니다(외부 전송은 하지 않습니다). |
| 사용자·감사 | admin / auditor / viewer 세 역할, 로그인·스캔·규칙 변경 감사 로그, 감사 리포트(xlsx)를 제공합니다. |
| 오프라인 설치 | 인터넷이 없는 Windows 서버에 wheel 묶음과 빌드된 화면을 함께 복사해 설치합니다. |
| 단독 스캐너 | ScanOps 서버 없이 스캔 서버에서 `scanner/scanops_scanner.py`만으로 nmap을 돌리고, 결과를 나중에 가져옵니다. |

### 화면

| 대시보드 | 발견 관리 |
|---|---|
| ![대시보드](docs/images/dashboard.png) | ![발견 관리](docs/images/findings.png) |
| **발견 상세** | **시간축 히트맵** |
| ![발견 상세](docs/images/finding-detail.png) | ![시간축 히트맵](docs/images/heatmap.png) |
| **스캔** | **자산대장** |
| ![스캔](docs/images/scans.png) | ![자산대장](docs/images/assets.png) |
| **부서통보** | **로그인** |
| ![부서통보](docs/images/notify.png) | ![로그인](docs/images/login.png) |

## 사용 방법

### 1. 준비물

- Python 3.11 이상(CI(Continuous Integration)는 3.11·3.12에서 테스트합니다)
- nmap(스캔 실행에만 필요합니다. XML 가져오기는 nmap 없이 동작합니다)
- Node.js 20.19+ 또는 22.12+(화면을 수정하거나 개발 서버를 띄울 때만 필요합니다. 빌드된 화면 `frontend/dist/`가 저장소에 들어 있습니다)

### 2. 설치와 실행

Linux/macOS:

```bash
cd backend
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn scanops.main:app --port 8770
```

Windows(PowerShell):

```powershell
cd backend
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m uvicorn scanops.main:app --port 8770
```

백엔드가 API(Application Programming Interface)와 화면을 같은 포트로 제공합니다. 브라우저에서 `http://127.0.0.1:8770/`에 접속합니다. 다른 PC에서 접속하려면 `--host 0.0.0.0`을 붙입니다.

### 3. 첫 로그인

1. 처음 실행하면 저장소 최상위 `data/INITIAL_ADMIN.txt`에 `admin` 계정의 임시 비밀번호가 생깁니다. 데이터 폴더는 환경변수 `SCANOPS_DATA_DIR`로 바꿀 수 있습니다.
2. `admin`으로 로그인하면 비밀번호 변경 창이 뜹니다. 변경하면 `INITIAL_ADMIN.txt`는 자동으로 지워집니다.
3. `사용자` 메뉴에서 auditor(스캔·발견 운영)나 viewer(열람 전용) 계정을 만듭니다.

### 4. 기본 사용 흐름

1. **자산대장**에서 자산 목록(xlsx/xls/csv)을 올립니다. IP가 같은 발견에 부서와 담당자가 붙습니다. 예시 파일: `test_samples/assets_*.csv`
2. **스캔**에서 대상을 입력하고 `스캔 실행`을 누르거나, `XML 가져오기`로 기존 결과를 올립니다. 예시 파일: `test_samples/scan_*.xml`, `samples/scanA.xml`
3. **발견 관리**에서 검색·필터로 대상을 좁히고, 행을 눌러 상태·마감·담당자를 지정합니다.
4. 조치가 끝나면 다시 스캔하거나(`마감·처리중 재검증`, `선택 재스캔`) 새 결과를 가져옵니다. 닫힌 포트는 자동으로 닫힘 처리됩니다.
5. **히트맵**과 **이력**에서 변화를 확인하고, **부서통보**에서 부서별 통보문을 만듭니다.
6. **대시보드**의 `감사 리포트(xlsx) 내보내기`로 증빙을 받습니다.

데모 데이터를 API로 한 번에 넣으려면 서버를 띄우고 비밀번호를 바꾼 뒤 다음을 실행합니다. `samples/scanA.xml`과 `samples/scanB.xml`을 차례로 가져와 조치 확인 과정을 만듭니다.

```bash
python samples/seed_demo.py <변경한 admin 비밀번호>
```

### 5. 스캔 허용 대역

`SCANOPS_SCAN_SCOPE`에 CIDR(Classless Inter-Domain Routing) 대역이나 IP를 공백·콤마로 지정하면 그 범위 밖 대상은 스캔 전에 거절합니다. 비워 두면 제한이 없습니다.

```bash
SCANOPS_SCAN_SCOPE="10.0.0.0/8 192.168.0.0/16" .venv/bin/python -m uvicorn scanops.main:app --port 8770
```

### 6. 오프라인(에어갭) 배포

일반 오프라인 ZIP은 `install.ps1`이 요구하는 **Python 3.13 / 3.12 (x64)** 와 nmap이 대상 서버에 있어야 합니다.

```powershell
powershell -ExecutionPolicy Bypass -File packaging\install.ps1   # wheelhouse에서 오프라인 설치
packaging\start.bat                                             # 0.0.0.0:8770 으로 서버 실행
```

Python을 설치할 수 없는 서버에는 Python 런타임이 들어 있는 all-in-one ZIP을 만듭니다. 압축을 풀고 `START.bat`을 실행하면 됩니다.

```powershell
python packaging\build_allinone.py                  # Python 3.13 x64
python packaging\build_allinone.py --python 3.12    # Python 3.12 x64
python packaging\build_allinone.py --arch x86       # Python 3.13 x86
```

파일 크기 제한에 맞춰 나누는 방법(`--split-mb`), 번들 구성, 폴더째 가져오기 규칙은 [운영 상세](docs/OPERATIONS.md)에 있습니다.

### 7. 단독 스캐너

스캔 서버에 ScanOps 전체를 설치하지 않고 `scanner/scanops_scanner.py`만 복사해 씁니다. Python 3.8 이상과 nmap만 있으면 됩니다.

```bash
python scanner/scanops_scanner.py 10.0.0.10 --ports 22,80,443 --name branch-a
python scanner/scanops_scanner_gui.py
```

생성된 `.xml`과 `*.manifest.json`을 `스캔 > 폴더째 가져오기`로 올립니다. 자세한 옵션은 [scanner/README.md](scanner/README.md)를 보세요.

### 8. 테스트

```bash
cd backend && python -m pip install -r requirements-dev.txt && python -m pytest -q
cd frontend && npm ci && npm test
```

## 기술 스택

| 영역 | 사용 기술 |
|---|---|
| 백엔드 | Python, FastAPI 0.115.6, Uvicorn 0.34.0, SQLAlchemy 2.0.36, Pydantic 2.10.4, pydantic-settings 2.7.1, python-multipart 0.0.20, openpyxl 3.1.5 |
| 데이터베이스 | SQLite(파일 하나, `data/scanops.db`) |
| 프론트엔드 | React 18.3.1, Vite 7.3.6, @vitejs/plugin-react 5.2.0, SheetJS(xlsx) 0.20.3(저장소에 동봉) |
| 스캔 | nmap, 단계 스캔 엔진 `engine/`(Python 표준 라이브러리만 사용) |
| 단독 스캐너 | Python 3.8+ 표준 라이브러리, GUI(Graphical User Interface)는 tkinter |
| 테스트 | pytest 8.3.4, httpx 0.28.1, Node.js 내장 테스트 러너(`node --test`) |
| 배포 | Windows용 wheelhouse(CPython 3.12/3.13), 임베디드 Python all-in-one ZIP, PowerShell 설치 스크립트 |
| CI | GitHub Actions(`.github/workflows/`) |

## 문서

- [진행 기록](docs/PROGRESS.md): 최종 목표, 기능별 구현 상태, 작업 이력
- [운영 상세](docs/OPERATIONS.md): 오프라인 배포, 폴더째 가져오기, 스캔 결과 식별, 스캔 성능 정책
- [설계서](docs/DESIGN.md): 아키텍처, 데이터 모델, API 목록
- [단계 스캔 엔진](engine/README.md), [단독 스캐너](scanner/README.md), [검증 랩](lab/README.md)
- [서드파티 고지](THIRD_PARTY_NOTICES.md)

## 라이선스

[MIT License](LICENSE)
