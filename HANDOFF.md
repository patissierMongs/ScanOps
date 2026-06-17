# ScanOps 인수인계 / 재구축 스펙 (HANDOFF)

> **이 파일 하나로** 새 세션이 ScanOps를 *제대로*(기능까지) 완성한다. `/clear` 직후 이 문서 + 글로벌 `~/.claude/CLAUDE.md` + 프로젝트 파일을 먼저 읽고 시작할 것.
> 작성 사유: 이전 세션이 "두 프로젝트 장점을 합쳐 하나의 완성품"을 만들랬는데 **(1) 프론트를 미니멀로 축소**하고 **(2) 나중엔 TSnmap의 디자인(형태)만 베끼고 기능(속)은 안 가져옴**. 같은 실수 반복 금지.

---

## 0. 한 줄 목표
**TSnmap(풍부한 운영 UI/UX) + nmapParser(스캔·분류 로직)를 하나의 완성된 통합 제품 `ScanOps`로.**
핵심 원칙 ⚠️: **TSnmap의 "기능"을 이식한다. "디자인"만 베끼지 않는다.** 통합 = 기능 통합.

## 1. 절대 반복 금지 (CLAUDE.md 위반 사례 → 교정)
- **범위 축소 금지.** `Simplicity First`는 *불필요한 복잡성*을 막는 것이지 *요청된 핵심 기능*을 빼는 게 아니다. 컬럼 빌더 같은 간판 기능을 "단순화"로 빼지 말 것.
- **형태≠기능.** 색·폰트·카드만 옮기고 컴포넌트의 실제 동작(드래그&드롭 컬럼 구성, 프리셋, 규칙 편집 등)을 빼면 통합 실패.
- **Think Before Coding.** UI 풍부도/범위가 애매하면 *만들기 전에* 물어볼 것. 조용히 축소 결정하지 말 것. (이전 실패의 직접 원인)
- **Goal-Driven 검증.** 각 기능은 *동작까지* 확인: 백엔드 `pytest`, 프론트 CDP로 콘솔/예외/탭전환 빈화면 확인.

## 2. 현재 상태 — 무엇을 재사용하고 무엇을 다시 할지
경로: `C:\Users\upica\claude\ScanOps`

| 영역 | 상태 | 처리 |
|---|---|---|
| **백엔드** `backend/` | **완성·32 테스트 통과**. 라이프사이클 동작. | **그대로 재사용.** 아래 §5 엔드포인트만 추가. |
| **프론트** `frontend/` | 디자인(IBM Plex+OKLCH)은 좋으나 **기능 빈약**(단순 목록/편집만) | **이번 핵심: 기능을 TSnmap 수준으로 재구축.** 디자인 시스템(`src/styles.css`)·폰트(`public/fonts`)는 유지. |
| **에어갭 패키징** `packaging/` | wheelhouse(멀티버전 cp310–313), install/run/START 스크립트 | 유지. 프론트 기능 추가 후 dist 재빌드 + zip 재생성. |
| **시드/샘플** `samples/`, `scripts/` | categories 시드 생성기, 실nmap 샘플, CDP 검증 스크립트 | 유지·활용. |

> 권장: **백엔드는 버리지 말 것**(32테스트·에어갭 검증 완료). "처음부터"는 *프론트 기능을 제대로 다시 짜는 것* + *백엔드 일부 추가*를 의미. 백엔드까지 재작성하면 검증된 자산 낭비.

### 현재 백엔드 인벤토리
- 모델(8): `User, Asset, ScanRun, Finding, FindingEvent, RiskRule, Category, Notification`
  - **`RiskRule` 모델은 이미 있음** — 위험규칙 UI는 백엔드 모델 재사용, 엔드포인트+화면만 추가.
  - 안정 finding 키 = `host_ip|port|proto`. Finding에 운영필드(status/owner/deadline/dept/manual_note) + 분류필드(category/usage/risk_level/compliance_json) 보유.
- 엔드포인트: auth(login,me) · users(list,create) · scans(list,get,import,run,resume) · findings(list,get,events,patch) · assets(list,create,patch,delete,import) · notifications(preview,send,history) · dashboard · reports(audit xlsx)

## 3. TSnmap에서 가져올 기능 (원본 `Column Builder A.dc.html`, 수정 금지·이식만)
7개 뷰의 *기능*을 ScanOps에 구현. 각 항목은 "동작"까지.
1. **컬럼 빌더 (간판)** — 발견 테이블에 표시/내보낼 컬럼을 **드래그&드롭으로 구성·추가/삭제/순서변경**, **프리셋 5종**(표준 보고서/포트 인벤토리/서비스 핑거프린트/OS·호스트/직접구성) 저장·전환, 표시형식, **선택 컬럼 CSV/XLSX 내보내기(UTF-8 BOM)**.
2. **현황 관리 고급** — 필터/검색, 마감일→기한초과 강조, **재스캔 명령어 자동 생성**(선택 발견의 포트 모아 nmap 명령 문자열), **2단계 정상처리**, **되돌리기(undo)**.
3. **위험 서비스 규칙 UI** — 금지 서비스·포트 규칙 추가/삭제, **매칭되는 발견 카운트** 표시. (백엔드 RiskRule 재사용)
4. **이력 전역 타임라인** — 발견별 드로어 말고, **전체 변화 이력**을 한 화면에서 타임라인 + 타입 필터(NEW_OPEN/CLOSED/CHANGED/…)로.
5. **자산대장 엑셀 가져오기 고급** — 병합셀 해제(forward-fill), 헤더 행 자동감지(+수동조정), 다중시트, 컬럼 자동매핑. (TSnmap 구현 `onAssetFile/unmergeFillWs/detectHeaderRow/computeAutoMap` 참고)
6. **부서별 통보 / 정상·복귀** — 이미 ScanOps에 기본 있음, TSnmap 수준으로 다듬기.
7. **디자인 언어** — IBM Plex + OKLCH. **이미 이식 완료**(유지). 토스트/되돌리기 패턴 활용.

## 4. nmapParser에서 가져올 것 (이미 백엔드에 이식 완료 — 유지)
taxonomy 105종, 추측/확인 식별, NSE 추출, compute_remarks, phase1 프리셋. (`backend/scanops/scanning/`)

## 5. 이번에 추가할 백엔드 엔드포인트 (TSnmap 기능 지원)
- `GET/POST/DELETE /api/rules` — 위험규칙 CRUD (+ 응답에 매칭 카운트 포함)
- `GET /api/events` — 전역 이력 피드(type/host/기간 필터, 페이지네이션)
- `GET /api/findings/export?cols=...&fmt=csv|xlsx` — **선택 컬럼** 내보내기, CSV는 UTF-8 BOM
- `POST /api/findings/rescan-command` — 선택 발견 id들 → nmap 재스캔 명령 문자열 생성
- (undo: 프론트에서 직전 PATCH 상태 보관 후 역적용, 또는 이벤트 기반 — 간단히 프론트 토스트+직전값 복원으로 충분)

## 6. 사용자 확정 결정 (재질문 불필요)
풀스택 FastAPI+SQLite / React+Vite · 공용서버 1대 · 로컬계정+역할(admin/auditor/viewer) · **완전 에어갭 설치** · 서버 nmap 실행(관리자) · 컴플라이언스 **KISA+NIS** · 범위 **풀세트** · **한국어 UI** · 지원 **win_amd64 + Python 3.10–3.13**.

## 7. 빌드 순서 (각 단계 verify)
1. 백엔드 추가 엔드포인트(§5) + pytest → verify: 새 테스트 통과
2. 컬럼 빌더(프리셋·드래그&드롭·내보내기) → verify: CDP로 컬럼 변경·내보내기 동작, BOM 바이트 확인
3. 위험규칙 UI + 현황 고급(재스캔명령/undo/2단계) → verify: 규칙 추가→발견 위험등급 반영, 명령 생성
4. 전역 이력 타임라인 → verify: 이벤트 필터 동작
5. 자산 엑셀 고급(병합/헤더감지) → verify: 병합·헤더 샘플 xlsx 통과
6. 전 기능 회귀 + 브라우저 E2E(콘솔0/예외0/탭전환 빈화면0) → dist 재빌드 → **에어갭 zip 재생성**

## 8. 기술 함정 — 절대 반복 금지 (메모리 `scanops-airgap-packaging.md`에도 있음)
- **ASCII 전용**: `.bat`/`.ps1`/`requirements.txt`에 한글 금지(cp949가 깨 읽음 → "배치파일 아님"/`UnicodeDecodeError`). 한글은 앱 코드(파이썬 UTF-8)·UI(브라우저)만.
- **wheelhouse 멀티버전**: `py -3.10/-3.11/-3.12/-3.13 -m pip download -r requirements.txt -d wheelhouse` (실인터프리터라야 마커 정확 → **greenlet** 포함; SQLAlchemy가 Python<3.13에서 요구).
- **설치 견고성**: `install.ps1`은 `$LASTEXITCODE` 확인; `start.bat`은 "venv 존재"가 아니라 "**uvicorn 설치됨**"으로 판단(부분설치 복구).
- **React useEffect가 Promise 반환 금지**: `useEffect(load,[])`에서 load가 `api().then()` 반환하면 언마운트 때 cleanup으로 호출돼 `TypeError`→**앱 전체 빈화면**. `useEffect(()=>{load();},[])`로 감싸고 **ErrorBoundary**(`key={view}`) 필수.
- **좀비 서버**: admin 임시비번은 첫 부팅에만 `data/INITIAL_ADMIN.txt` 생성. 비번 알려주기 전 **로그인 API로 검증**. 재시작 전 `taskkill //F //IM python.exe` + `netstat | grep :8770`에 LISTENING 없는지 확인.
- **프론트 캐시**: 수정 후 브라우저가 옛 해시 번들 캐시 → CDP 검증 시 `Network.setCacheDisabled` + `?t=`로 버스트, 사용자는 Ctrl+Shift+R.

## 9. 실행 / 검증
- 서버: `cd backend && SCANOPS_DATA_DIR=<dir> .venv/Scripts/python.exe -m uvicorn scanops.main:app --host 0.0.0.0 --port 8770`
- 테스트: `cd backend && .venv/Scripts/python.exe -m pytest -q`
- 프론트 빌드: `cd frontend && npm run build` (dist → FastAPI가 한 포트로 서빙)
- 프론트 E2E: `samples/shot.mjs`(스크린샷), `samples/shot2.mjs`(탭전환 빈화면/예외) — Chrome `--remote-debugging-port=9222`로 띄우고 node 실행. 토큰은 `samples/.token`.
- 데모 시드(실nmap 2스캔 라이프사이클): `python samples/seed_demo.py <admin_pw>`

## 10. 완료 정의 (Definition of Done)
TSnmap의 7개 뷰 **기능**이 ScanOps에 살아있고(특히 컬럼 빌더·위험규칙·전역이력·엑셀고급), 영속 백엔드에 연결되며, 완전 오프라인 설치/실행되고, 백엔드 테스트 + 프론트 E2E(빈화면0)가 통과하고, 한국어 UI로 팀이 브라우저에서 전 기능을 쓸 수 있을 때. **"형태만"이 아니라 "기능까지" 통합되어야 완료.**

## 11. 참고 경로
- TSnmap 원본(이식 참고, 수정 금지): `C:\Users\upica\claude\TSnmap\Column Builder A.dc.html`, `support.js`, `작업정리.md`
- nmapParser 원본(이식 참고, 수정 금지): `C:\Users\upica\claude\nmapParser1\nmapParser.py`, `categories.xlsx`
- 기존 설계 근거: `ScanOps/DESIGN.md` (아키텍처·데이터모델·로드맵 A–J)
- 메모리 색인: `~/.claude/projects/C--Users-upica-claude-TSnmap/memory/MEMORY.md`
