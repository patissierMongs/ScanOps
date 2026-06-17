# ScanOps 재구축 설계 (REBUILD) — 2026-06-16

> 이 문서는 "프레임워크부터 새로 만든다 + 처음에 완벽한 설계" 목표에 따라, **참고 프로젝트를 실제로 테스트까지 돌려 평가한 결과**를 근거로 한 재구축 단일 진실원천이다. `HANDOFF.md`/`DESIGN.md`를 대체하지 않고 그 위에 **실측 평가 + 확정 설계**를 더한다.

## 0. 실측 평가 결론 (테스트 실행 포함)

| 자산 | 실측 | 판정 | 근거 |
|---|---|---|---|
| 백엔드 `backend/` | **pytest 32/32 통과(3.37s)** | **재사용 + 확장** | diff/라이프사이클 엔진(`ingest.py`)이 실nmap XML 회귀로 핀고정. 시니어급 레이어링·안전한 subprocess(shell=False+화이트리스트)·PBKDF2. 재작성 시 손해 명백. |
| 스캔 로직 `scanning/` | nmapParser 충실 이식 + 개선(105종·high43·KISA/NIS) | **유지 + 소폭 패치** | 누락 4건: rdp-ntlm-info Target_Name, banner `ostype`, guessed-service(nmap-services), UDP 프리셋. 우선순위 낮음. |
| 프론트 `frontend/src` | 291줄·기능 빈약 | **완전 그린필드** | 이전 세션 실패 지점. |
| TSnmap 기능 | 7뷰 전부 실재·로직 DOM 분리 양호 | **순수로직 포트 + 뷰 재작성** | dc-runtime 폐기, JSX로. |

**사용자 결정 규칙 적용**: "최대한 새로, 단 진짜 우수+재작성이 못할 것 같으면 재사용" → 백엔드는 그 "재사용" 조건에 정확히 부합(검증됨). 프론트는 새로.

## 1. 확정 스택 (DESIGN §0 유지)
FastAPI + SQLite(백엔드, **재사용**) / React 18 + Vite(프론트, **재구축**) · 단일 포트 SPA 서빙 · 로컬계정+역할(admin/auditor/viewer) · 완전 에어갭 · 서버 nmap · KISA+NIS · 한국어 UI · win_amd64 + Python 3.10–3.13.

## 2. 백엔드 확장 (가산만 — 기존 엔드포인트 불변)
- `GET/POST/DELETE /api/rules` — RiskRule CRUD. 응답에 규칙별 **매칭 발견 수** 포함.
- `GET /api/events` — 전역 이력 피드. 필터: `type, host, since, until`. 페이지네이션(`limit/offset`). FindingEvent + Finding 조인(host/port/service 동반).
- `GET /api/findings/export?cols=a,b&fmt=csv|xlsx&state=&risk=…` — **선택 컬럼** 내보내기. CSV는 **UTF-8 BOM**. 컬럼 원천은 `reports._row`/`_HEADERS` 재사용.
- `POST /api/findings/rescan-command` — body `{finding_ids:[...]}` → 포트 distinct·정렬·호스트 묶어 nmap 명령 문자열. `nmap_runner.build_command` 재사용.
- 각 엔드포인트 pytest 추가, 기존 32 회귀 유지.

## 3. 프론트 아키텍처 (그린필드)
```
frontend/src/
  main.jsx            진입
  app/
    App.jsx           셸: 헤더/탭/세션. <ErrorBoundary key={view}> 로 뷰 격리
    ErrorBoundary.jsx 뷰별 크래시 격리(HANDOFF 함정: 빈화면 방지)
    session.js        토큰/유저 상태(localStorage), 401 처리
  api/client.js       fetch 래퍼(토큰 주입, 에러 정규화) — useEffect 직접 .then 반환 금지
  lib/                프레임워크 무관 순수로직 (TSnmap 포트, 단위 검증 대상)
    columns.js        컬럼 정의·5프리셋·셀값 해석(cellValue)
    exportCols.js     buildExport·CSV(BOM)·XLSX(SheetJS)
    assetImport.js    unmergeFillWs·detectHeaderRow·computeAutoMap·normHeader
    rescan.js         선택 발견 → nmap 재스캔 명령(백엔드와 동일 규칙, 클라 미리보기)
  ui/                 공용 컴포넌트(Pill, Toast, Drawer, Modal, Table, DnDList)
  styles/tokens.css   디자인 토큰(OKLCH 색·간격·타이포)
  views/
    Login, Dashboard, Findings, Rules, History, Assets, Notifications, Scans, Users
```
**규칙(HANDOFF §8 함정 준수):**
- `useEffect(()=>{ load(); },[])` — Promise 반환 금지. ErrorBoundary `key={view}` 필수.
- 의존성 최소화. SheetJS(xlsx)만 도메인 라이브러리로 추가(import/export). 빌드 시 dist에 번들 → 런타임 무영향.

## 4. 뷰 스펙 (목업은 참고만 — 기능 우선 재설계)
1. **Findings(발견) — 핵심.** 좌: 컬럼빌더 패널(필드 팔레트·선택컬럼 DnD·프리셋 셀렉트·저장·표시형식·내보내기) / 우: 발견 테이블(선택·정렬·필터·검색·마감초과강조·위험만). 하단/드로어: 선택발견 → 재스캔명령, 2단계 정상처리, undo 토스트.
2. **Rules(위험규칙).** 금지서비스·포트규칙 추가/삭제 + 규칙별 매칭 발견 수. 추가 즉시 발견 위험등급 반영(백엔드 재분류는 차기, v1은 표시 카운트).
3. **History(전역이력).** 한 화면 타임라인 + 타입필터. `/api/events`.
4. **Assets(자산대장).** 고급 엑셀 임포트(병합해제·헤더감지·자동매핑·다중시트) + 목록/편집.
5. **Notifications(부서통보).** 부서별 그룹·통보문 생성·복사/파일(.txt BOM)·이력.
6. **Dashboard.** 위험/상태/부서 지표·마감초과.
7. **Scans.** 실행(프리셋·타겟)/XML 가져오기/로그.
8. **Users(admin).** 계정·역할.

## 5. 빌드 순서 (각 단계 verify — Goal-Driven)
1. 백엔드 4엔드포인트 + pytest → **verify: 새 테스트 통과 + 기존 32 회귀.**
2. 프론트 기반(셸·라우터·API·토큰·lib 포트) → verify: 빌드 성공, 로그인·탭전환 빈화면0(CDP).
3. 컬럼빌더 → verify: CDP로 DnD·프리셋·내보내기, **CSV 선두 BOM 바이트(EF BB BF) 확인.**
4. 현황고급 + 위험규칙 → verify: 재스캔명령 생성, 규칙 추가→매칭카운트.
5. 전역이력 → verify: 타입필터 동작.
6. 자산 엑셀고급 → verify: 병합/헤더 샘플 xlsx 통과.
7. 통보/대시보드/스캔/사용자 → verify: 각 동작.
8. 전체 회귀 + 브라우저 E2E(콘솔0·예외0·빈화면0) → dist 재빌드 → **에어갭 zip 재생성.**

## 6. 검증 환경 (모든 환경 활용)
- 백엔드: `backend/.venv/Scripts/python.exe -m pytest -q` (Win) / 필요시 WSL Ubuntu 교차검증.
- 프론트 빌드: `cd frontend && npm run build`.
- E2E: Chrome `--remote-debugging-port=9222` + `samples/shot*.mjs` CDP. 토큰 `samples/.token`.
- 서버: `SCANOPS_DATA_DIR=<dir> .venv/Scripts/python.exe -m uvicorn scanops.main:app --port 8770`.
- 좀비서버 함정: 재시작 전 `taskkill //F //IM python.exe` + 포트 LISTENING 확인. 임시 admin 비번은 로그인 API로 검증 후 안내.

## 7. 완료 정의 (HANDOFF §10)
TSnmap 7뷰 **기능**(특히 컬럼빌더·위험규칙·전역이력·엑셀고급)이 살아 영속 백엔드에 연결, 완전 오프라인 설치/실행, 백엔드 테스트 + 프론트 E2E(빈화면0) 통과, 한국어 UI로 전 기능 사용 가능. **형태만이 아니라 기능까지.**
