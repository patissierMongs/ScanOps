# ScanOps 진행 기록

**한국어** | [English](PROGRESS.en.md)

이 문서의 구현 상태는 문서나 커밋 메시지가 아니라 2026-09-27 시점의 코드를 직접 읽고 확인한 결과입니다. 테스트 통과만으로 완료로 적지 않았습니다.

## 최종 목표

nmap 스캔 결과를 발견(finding) 단위로 데이터베이스에 저장하고, 발견마다 다음 과정이 실제로 동작하게 하는 것입니다.

1. 스캔으로 발견 생성
2. 서비스 분류·위험등급·KISA(한국인터넷진흥원)/국정원(NIS, National Intelligence Service) 근거 자동 부여
3. 담당·마감 배정
4. 재스캔으로 조치 결과 확인
5. 감사 리포트로 증빙

여기에 더해 인터넷이 없는 Windows 서버에 오프라인으로 설치해 팀이 한국어 화면으로 브라우저에서 쓰는 것이 목표입니다(`docs/DESIGN.md` 8절).

## 현재 구현 상태

| 기능 | 상태 | 확인한 코드 위치 |
|---|---|---|
| 로그인·토큰 인증, 최초 관리자 비밀번호 발급과 강제 변경 | 구현됨 | `backend/scanops/api/auth.py`, `backend/scanops/seed/bootstrap.py` |
| 역할 3종(admin/auditor/viewer)과 사용자 관리 | 구현됨 | `backend/scanops/api/deps.py` `require_role`, `backend/scanops/api/users.py` |
| nmap XML(Extensible Markup Language) 가져오기 | 구현됨 | `backend/scanops/api/scans.py` `POST /import`, `backend/scanops/scanning/nmap_parse.py` |
| 결과 폴더째 가져오기(단계 스캔 폴더·단독 스캐너 manifest) | 구현됨 | `backend/scanops/api/scans.py` `POST /import-bundle` |
| 웹에서 스캔 실행(단계 스캔 엔진) | 구현됨 | `backend/scanops/api/scans.py` `POST /run-staged`, `engine/scanops_engine/pipeline.py` |
| 한 번에 실행·직접 명령 실행 | 구현됨 | `backend/scanops/api/scans.py` `POST /run`, `POST /run-command` |
| 스캔 중지·이어하기·재시도 대기 호스트 재스캔 | 구현됨 | `backend/scanops/api/scans.py` `/{scan_id}/stop`, `/resume`, `/retry-timeouts` |
| 스캔 허용 대역(`SCANOPS_SCAN_SCOPE`) | 구현됨 | `backend/scanops/scanning/scope.py` `check_scope` |
| 서비스 분류표 105종과 위험등급, KISA/NIS 근거 | 구현됨 | `backend/scanops/seed/categories.json`, `backend/scanops/scanning/taxonomy.py` |
| 단종 제품(EOL, End of Life) 판정 | 구현됨 | `backend/scanops/seed/eol_products.json`, `backend/scanops/scanning/taxonomy.py` |
| `unknown` 포트의 응답 원문 시그니처 대조 | 구현됨 | `backend/scanops/scanning/fingerprints.py`, `backend/scanops/seed/fingerprint_signatures.json` |
| 조직 위험 규칙(서비스·제품·CPE(Common Platform Enumeration)) | 구현됨 | `backend/scanops/api/rules.py` |
| 발견 상태·마감·담당 배정과 변경 이력 | 구현됨 | `backend/scanops/api/findings.py` `PATCH /{fid}`, `GET /{fid}/events` |
| 재스캔으로 닫힘 판정(미관측 포트 자동 닫힘) | 구현됨 | `backend/scanops/scanning/ingest.py` `ingest`, `_close_row` |
| 선택 재스캔·마감/처리중 일괄 재검증 | 구현됨 | `backend/scanops/api/findings.py` `POST /rescan`, `/rescan-due`, `/rescan-command` |
| 컬럼 빌더와 CSV(Comma-Separated Values)/XLSX(Excel 통합 문서) 내보내기 | 구현됨 | `frontend/src/ui/ColumnBuilder.jsx`, `backend/scanops/api/findings.py` `GET /export` |
| 시간축 히트맵 | 구현됨 | `backend/scanops/api/heatmap.py`, `frontend/src/views/Heatmap.jsx` |
| 자산대장 가져오기(xlsx/xls/csv)와 IP(Internet Protocol) 매칭 | 구현됨 | `frontend/src/lib/assetImport.js`, `backend/scanops/api/assets.py` `POST /bulk`, `/import` |
| 부서통보문 생성·기록 | 구현됨 | `backend/scanops/api/notifications.py` |
| 통보 외부 발송(메일 등) | 미구현 | 에어갭 전제라 의도적으로 없음(`backend/scanops/api/notifications.py` 모듈 설명) |
| 감사 로그와 감사 리포트(xlsx) | 구현됨 | `backend/scanops/api/audit.py`, `backend/scanops/api/reports.py` `GET /audit` |
| 대시보드 지표 | 구현됨 | `backend/scanops/api/dashboard.py`, `frontend/src/views/Dashboard.jsx` |
| 스캔 프리셋과 단독 스캐너 동기화 | 구현됨 | `backend/scanops/api/presets.py` `POST /sync`, `scanner/scanops_scanner.py` |
| 단독 스캐너(CLI(Command-Line Interface)·GUI(Graphical User Interface)) | 구현됨 | `scanner/scanops_scanner.py`, `scanner/scanops_scanner_gui.py` |
| 프로세스 워치독 | 부분 구현 | 한 번에 실행은 끊긴 XML을 복구해 닫힘 권한 없이 인입(`backend/scanops/api/scans.py` `WATCHDOG_RC` 분기), 단계 스캔은 실패로 마감하고 인입하지 않음(`_engine_worker`의 `rc != 0` 분기) |
| 스캔 진행 표시 | 부분 구현 | 설계서의 SSE(Server-Sent Events) 로그 스트림 대신 `GET /{scan_id}/progress`, `/stages` 폴링으로 제공 |
| 스캔 간 비교 API(Application Programming Interface) `GET /api/diff` | 미구현 | 라우트 없음. 같은 정보는 히트맵(`/api/heatmap`)과 발견 이력으로 제공 |
| 웹에서 스캔 산출물 파일 내려받기 | 미구현 | `backend/scanops/api/scans.py`에 다운로드 라우트 없음 |
| 오프라인 설치 패키지(wheelhouse·all-in-one ZIP) | 구현됨 | `packaging/install.ps1`, `packaging/build_allinone.py`, `packaging/build_zip.py` |
| CI(Continuous Integration) | 구현됨 | `.github/workflows/ci.yml`, `runtime-e2e.yml`, `package-runtime-smoke.yml` |

### 이번 확인에서 돌려 본 것

- 백엔드 테스트(`python -m pytest -q`, Python 3.11): 1024개 통과, 5개 건너뜀, 1개 실패. 실패한 `test_package_runtime_commands_have_a_hard_timeout`은 개인정보 정리 전에도 같은 방식으로 실패했고, 이 컨테이너에서 고아 프로세스가 회수되지 않아 생기는 환경 문제로 보입니다.
- 프론트엔드 테스트(`npm test`): 110개 모두 통과.
- 로컬 서버를 띄우고 `test_samples/`의 가상 데이터와 `samples/scanA.xml`, `samples/scanB.xml`을 가져와 화면과 재스캔 닫힘을 확인했습니다. `127.0.0.1` 대상 웹 스캔도 끝까지 돌아가는 것을 확인했습니다.

## 작업 이력

`git log`에서 뽑았고 날짜는 한국 표준시(KST, Asia/Seoul)입니다. 원래 커밋에는 `+0900`과 `+0000` 시간대가 섞여 있어 모두 KST로 바꿨습니다.

| 기간 | 주요 작업 |
|---|---|
| 2026-06-18 | 첫 커밋. 실행 안정성·보안·CI 보강, 직접 명령 스캔, nmapParser 스캔 빌더 이식, 자산대장 변경 미리보기 |
| 2026-06-19 | 단계 스캔 엔진(`engine/`) 도입과 백엔드 연동(`run-staged`), 취약 포트 재스캔을 백그라운드 엔진으로 전환, 단계 타임라인 화면 |
| 2026-06-21 ~ 06-25 | 기본 스캔 프로파일 조정, 용도 근거 패널과 시간축 히트맵, 저장소 크기 축소, 발견 단위 재스캔과 결과 드로어, 위험 규칙 관리 병합 |
| 2026-06-29 | 단독 스캐너 품질 점검(QA, Quality Assurance) 8회(QA-031 ~ QA-059 수정, 8회차에 추가 결함 0건) |
| 2026-07-21 ~ 07-29 | 통합 검증 샘플·시나리오·리포트(`test_samples/`), 깨진 XML 가져오기를 400으로 처리, 검증 자산 재현성 보강 |
| 2026-08-04 ~ 08-12 | 스캔 범위·제어 보강, Server 식별값 보존, 오프라인 설치 스크립트 PowerShell 5 호환, 포트/IP 범위 제외와 저강도 스캔, 프리셋 동기화, Python 3.13 번들 |
| 2026-08-14 ~ 08-19 | TLS(Transport Layer Security) 증거 복구, 상태 근거 표시, UDP(User Datagram Protocol) 식별 포트별 격리, 닫힘 감사 도구, 미관측 호스트 닫힘 방지, 컴플라이언스 근거·담당 배정·NSE(Nmap Scripting Engine) 노출 신호, EOL 반영 |
| 2026-08-21 ~ 08-25 | 호스트 시간 상한 제거와 프로세스 워치독 도입, 처리량 옵션을 부하 상한으로 정리, 미확정 관측 접기, 결과 폴더 묶음 가져오기, 지연 추적 패널, 리뷰 지적 수정 다수(PR(Pull Request) #54 병합) |
| 2026-09-27 | 개인정보 정리(테스트 픽스처·샘플·스크립트), 상세 문서를 `docs/`로 이동, README 한국어/영어 분리와 스크린샷, 진행 기록 추가 |
