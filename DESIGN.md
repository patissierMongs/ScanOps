# ScanOps — 설계서 (Single Source of Truth)

> 사내 팀용 **네트워크 노출 점검 라이프사이클 플랫폼**.
> nmap 스캔부터 발견(finding)의 영속·분류·배정·마감·재스캔 조치검증·감사까지 **한 루프로 닫는다.**
> 기존 `TSnmap`(휘발성 UI 데모)·`nmapParser`(정적 CSV 생성기)의 빈틈 — *"기록 시스템(system-of-record)의 부재"* — 를 정면으로 해결한다.

## 0. 확정된 결정 (변경 시 이 표를 갱신)

| 항목 | 결정 |
|---|---|
| 핵심 성격 | **지속 라이프사이클 플랫폼** — 발견에 안정 ID, 상태를 DB에 영속 |
| 스캔 | **스캔+운영 올인원** — 서버가 직접 nmap 실행 |
| 대상 | **사내 팀 도구** — 공용 서버 1대 + 브라우저 접속 |
| 스택 | **FastAPI + SQLite (백엔드) / React + Vite (프론트, 빌드된 정적 자산)** |
| 인증 | **로컬 계정 + 역할** (admin / auditor / viewer) |
| 설치 | **완전 에어갭** — 인터넷 0. Python·의존성·프론트 dist 전부 동봉 |
| nmap | 서버에 설치됨, 관리자 권한(-sS/-O 가능) |
| 컴플라이언스 | **KISA + 국정원(NIS)** 근거 매핑 |
| 재사용 | nmapParser의 **taxonomy + 식별 로직 + NSE 추출** 전부 포팅 (원본 불변, 복제) |
| 완성 범위(v1) | **풀세트** — 핵심 루프 + 부서통보 + 자산대장 + 감사리포트 + 대시보드 |
| UI 언어 | 한국어 |

## 1. 아키텍처

```
[브라우저(React 정적 dist)]  ──HTTP/JSON──  [FastAPI]
                                              │
                          ┌───────────────────┼───────────────────┐
                          │                   │                   │
                     [nmap 실행]         [SQLite DB]         [정적 자산 서빙]
                     subprocess          (단일 진실원천)      (프론트 dist)
                     XML 산출            findings/상태/이력
```
- 프론트는 **빌드 타임에만** Node 필요 → 산출된 `dist/`만 배포. 런타임은 **Python + nmap**만.
- FastAPI가 API + 정적 dist를 한 포트로 서빙(단일 서버 1대 요건 충족).
- 에어갭: 의존성은 `packaging/wheelhouse/`(pip --no-index) + 임베디드 Python 후보 + 프론트 dist 동봉.

## 2. 데이터 모델 (핵심)

**안정 finding 키 = `host_ip|port|proto`** — 서비스/버전이 바뀌어도 같은 포트면 같은 발견. 이 키가 상태·담당·마감·이력을 스캔 간에 이어주는 등뼈.

- **User**(id, username, password_hash, role[admin/auditor/viewer], display_name, is_active, created_at)
- **Asset**(id, ip, hostname, dept, owner, asset_no, note) — 자산대장. finding.dept/owner 자동 매칭 소스.
- **ScanRun**(id, name, targets, command, status[running/done/failed/canceled], started_at, finished_at, raw_xml_path, host_count, port_count, created_by)
- **Finding**(id, **finding_key**(uniq), host_ip, hostname, port, proto, state[open/closed/filtered], service, product, version, banner, cpe, rtt,
  identification[확인/추측/tcpwrapped/미확인], category, usage, risk_level[high/medium/low/info], remarks, nse_json, compliance_json,
  first_scan_id, last_scan_id, first_seen, last_seen,
  status[미조치/처리중/정상처리/예외승인/재발], owner_user_id, deadline, dept,
  created_at, updated_at)
- **FindingEvent**(id, finding_id, scan_id, type[NEW_OPEN/CLOSED/REOPENED/SERVICE_CHANGED/VERSION_CHANGED/STATUS_CHANGE/ASSIGN/DEADLINE/NOTE/EXCEPTION], detail, actor_user_id, created_at) — 이력 타임라인 + 감사 추적.
- **RiskRule**(id, kind[banned_service/port_rule], service, port, risk_level, note, created_by) — taxonomy 위에 얹는 조직 커스텀 규칙.
- **Category**(id, service_name(lower, uniq), category, usage, risk_level, encryption, auth, exposure, compliance_json, desc) — 포팅한 taxonomy(시드).
- **Notification**(id, dept, finding_ids_json, body, channel[clipboard/file/log], sent_at, sent_by) — 부서통보 기록.

## 3. 핵심 루프 (조치 라이프사이클)

```
1) 스캔 실행(nmap) ─▶ 2) XML 파싱 + 식별품질 판정 ─▶ 3) taxonomy 분류 + 위험등급 + 컴플라이언스 매핑
        │
        ▼
4) finding upsert(안정키) ─▶ NEW_OPEN/REOPENED/SERVICE_CHANGED/CLOSED 이벤트 자동 생성
        │
        ▼
5) 운영: 담당 배정·마감 설정·상태 전이(미조치→처리중→정상처리/예외승인)
        │
        ▼
6) 재스캔 ─▶ diff ─▶ "마감 걸린 그 포트, 닫혔나?" 자동 검증 ─▶ 정상처리 확정 or 재발(REOPENED)
        │
        ▼
7) 감사 리포트(누가·언제·무엇을·어느 근거로) 산출
```
**이게 핵심 차별점:** diff가 *기한·배정·상태와 묶여* 조치 완료를 자동 검증한다. (기존 두 도구엔 없음)

## 4. 모듈 (백엔드)

```
backend/scanops/
  config.py            설정(경로, 시크릿, nmap 경로)
  db.py                SQLAlchemy 엔진/세션 (SQLite, WAL)
  models.py            ORM
  schemas.py           Pydantic I/O
  security.py          비밀번호 해시(pbkdf2/argon2), 토큰
  auth.py              로그인·역할 가드
  main.py              FastAPI 앱 + 정적 dist 서빙
  api/                 라우터: auth, scans, findings, assets, notifications, reports, dashboard, rules, users
  scanning/
    presets.py         포팅: phase1 옵션/프리셋(DEFAULT_OPTIONS)
    nmap_runner.py     subprocess(cmd_list, shell=False) 실행·로그 스트림·취소
    nmap_parse.py      포팅: XML→finding, compute_identification_status, NSE 추출, compute_remarks
    taxonomy.py        포팅: categories 로더 + 분류/위험/컴플라이언스 적용
    compliance.py      KISA/NIS 근거 매핑 규칙
  seed/                categories.json, compliance.json, 기본 admin
```

## 5. API 표면(요약)

- `POST /api/auth/login`, `GET /api/auth/me`
- `POST /api/scans` (스캔 실행), `GET /api/scans`, `GET /api/scans/{id}`, `GET /api/scans/{id}/log`(SSE)
- `GET /api/findings`(필터/검색), `PATCH /api/findings/{id}`(상태/담당/마감), `GET /api/findings/{id}/events`
- `GET /api/diff?base=&target=` (스캔 간 변화)
- `GET/POST/PATCH /api/assets`, `POST /api/assets/import`(xlsx)
- `POST /api/notifications`(부서별 통보 생성), `GET /api/notifications`
- `GET /api/reports/audit`(xlsx 감사 리포트), `GET /api/dashboard`(요약 지표)
- `GET/POST /api/rules`(위험 규칙), `GET/POST /api/users`(admin)

## 6. 보안 원칙

- nmap 호출은 **`subprocess.Popen(list, shell=False)`** 만 — 명령 주입 차단(nmapParser 원칙 계승).
- 타겟·옵션 화이트리스트 검증, 출력 인자(-oX 등) 서버가 강제.
- 비밀번호 해시 저장, 역할 기반 접근(스캔 실행=auditor↑, 사용자 관리=admin).
- 스캔 결과는 민감정보(IP/배너) → 접근 인증 필수, 감사 로그 보존.

## 7. 로드맵 (빌드 순서 — 루프가 이 순서로 진행)

- [x] **A. 기반**: 스캐폴드·DESIGN·DB 모델(8테이블)·config·security·앱 부팅 — 검증 완료
- [x] **B. 인증/사용자**: 로컬 계정·역할·로그인·시드 admin — 6 테스트 통과
- [x] **C. 스캔 엔진**: presets/runner/parse 포팅, XML 가져오기·실행→finding upsert+diff 이벤트, 발견 운영 PATCH — 8 테스트 통과(재스캔 조치검증 포함). bytes 파싱 버그 수정.
- [x] **D. taxonomy/컴플라이언스**: 105종 시드(high 43)·위험규칙 상향·KISA/NIS·인입 자동적용 — 5 테스트 통과
- [x] **E. 라이프사이클**: 상태/담당/마감·diff 조치검증·이력·마감초과 지표 — C/G 에서 구현·검증
- [x] **F. 자산대장 + 부서통보**: IP→부서 매칭·xlsx 가져오기·부서별 통보문 — 3 테스트 통과
- [x] **G. 감사 리포트 + 대시보드**: 위험/상태/부서 지표·마감초과·xlsx 감사리포트 — 3 테스트 통과
- [x] **H. 프론트엔드**(React+Vite): 로그인·대시보드·발견관리(이력 드로어·상태/마감 편집)·스캔(실행/가져오기)·자산대장·부서통보 — vite 빌드 성공, **전체 HTTP E2E 통과**(SPA 서빙·로그인·가져오기·대시보드·리포트)
- [x] **I. 에어갭 패키징**: wheelhouse(18 wheel)·dist·install/run 스크립트·README — **신규 venv `--no-index` 오프라인 설치 실증**(네트워크 0, 28라우트 임포트)
- [x] **J. 최종 검증**: 백엔드 25 테스트 통과·HTTP E2E·에어갭 설치 검증 완료 + 이전 프로젝트 비교/평가

> 백엔드 누적 **25 테스트 통과** + 프론트 **E2E 검증 완료**. API 전부 구현(auth/scans/findings/assets/notifications/dashboard/reports/users), React SPA 를 FastAPI 가 한 포트로 서빙.

## 8. 완료 정의 (Definition of Done)

각 발견이 **스캔으로 생성→분류·근거 자동 부여→담당·마감 배정→재스캔으로 조치 검증→감사 리포트에 증빙**되는 전 과정이 실제로 동작하고, **완전 오프라인 설치/실행**되며, 백엔드 테스트가 통과하고, 한국어 UI로 팀이 브라우저에서 쓸 수 있을 때.
