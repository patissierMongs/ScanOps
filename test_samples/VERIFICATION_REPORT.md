# ScanOps 통합 검증 리포트

실제 백엔드(FastAPI+SQLite)를 기동하고, **실제 docker 서비스에 nmap 포트스캔을 수행**한 뒤,
헤드리스 Chromium(CDP)으로 **실제 빌드된 프론트엔드(dist)를 관리자로 조작**하며 14개 영역의
사용 케이스를 검증했다. 아래는 재현 절차, 결과, 그리고 발견된 미비점이다.

- 검증일: 2026-07-21
- 백엔드: `uvicorn scanops.main:app :8770` (프론트 dist 동일 포트 서빙)
- 브라우저: 실제 UI 클릭/입력/파일업로드(`DOM.setFileInputFiles`)로 구동. API는 검증(assert)에만 사용.
- 전 구간 **JS 예외 0, 콘솔 error 0, 빈 화면 0**.

---

## 1. 테스트 샘플 (요구사항: 스캔결과·자산대장 각 5개, 300줄 이상)

`test_samples/generate_samples.py` 가 결정론적으로 생성. taxonomy(105종)에 존재하는 서비스명만
사용해 위험등급이 실제로 매겨지도록 구성했고, 스캔 IP 대역과 자산대장 IP 대역을 일치시켜
가져오기 후 부서/담당/연락처가 IP 매칭으로 자동 연결되게 설계.

### 스캔 결과 XML (nmap -oX 형식, 실제 파서가 인입)
| 파일 | 시나리오 | 호스트 | 라인 수 |
|---|---|---:|---:|
| `scan_hq_datacenter.xml` | HQ 데이터센터(웹/DB/모니터링) | 40 | 1093 |
| `scan_dmz_public.xml` | DMZ 공개서버(외부노출 고위험) | 35 | 950 |
| `scan_branch_office.xml` | 지점망(윈도우 RDP/SMB/프린터) | 45 | 899 |
| `scan_ot_network.xml` | OT/산업망(레거시 telnet/ftp/snmp) | 38 | 752 |
| `scan_cloud_vpc.xml` | 클라우드 VPC(redis/mongo/elastic) | 42 | 744 |

### 자산대장 CSV (한글 헤더 + UTF-8 BOM, 프론트 위저드가 인입)
| 파일 | IP 대역 | 행 수 | 라인 수 |
|---|---|---:|---:|
| `assets_cloud.csv` | 172.31.10.x | 340 | 341 |
| `assets_branch.csv` | 10.20.30.x | 330 | 331 |
| `assets_hq.csv` | 10.10.10.x | 320 | 321 |
| `assets_ot.csv` | 192.168.50.x | 310 | 311 |
| `assets_dmz.csv` | 203.0.113.x | 305 | 306 |

가져오기 결과: 스캔 5건 → **발견 372건**(banned/high/medium/low 분포), 자산 **1,605건**,
IP 매칭으로 발견에 부서/담당/연락처 자동 연결(예: 10.10.10.10 → 연구개발팀·문가람).

---

## 2. 실제 docker 포트스캔

`lab/docker-compose.yml` 로 6개 서비스를 172.30.0.0/24 브리지에 기동하고 실제 nmap 스캔 수행:

```
nmap -sV -sC -p- 172.30.0.10-15  →  실제 식별 결과
  172.30.0.10 :80    nginx          → medium
  172.30.0.11 :5432  postgresql     → high
  172.30.0.12 :6379  redis          → high
  172.30.0.13 :21    vsftpd         → high
  172.30.0.14 :80    nginx          → medium
  172.30.0.15        (포트 없음, 살아있음)
```

docker → nmap → XML → ScanOps 가져오기 → 자동 분류/위험등급까지 실 파이프라인 관통 확인.

---

## 3. 사용 케이스 검증 (14개 영역)

각 케이스는 실제 프론트엔드를 조작해 수행했고, 결과는 API/DB로 교차검증했다.
스크립트: `uc_imports.mjs`(UC1–4), `uc_ops_a.mjs`(UC5–7), `uc_ops_b.mjs`(UC8–13), `uc_rescan.mjs`(UC14).

| # | 영역 | 조작 | 결과 |
|---|---|---|---|
| UC1 | 인증/로그인 | 로그인 폼 입력→접속 | ✅ 토큰 발급, 대시보드 진입 |
| UC2 | 스캔 인입 | 스캔 탭에서 XML 5개 업로드 | ✅ 스캔 5건·발견 372건 생성 |
| UC3 | 자산대장 위저드 | CSV 업로드→헤더감지→자동매핑→가져오기 | ✅ 320건 인입·IP매칭 |
| UC4 | 대시보드 | 지표 타일/위험분포/부서별 확인 | ✅ open 374, 부서별 집계 반영 |
| UC5 | 발견 필터/검색 | 위험=상 필터, 검색 telnet | ✅ 필터 UI=API(223), 검색 372→22 |
| UC6 | 발견 운영 | 드로어에서 상태→처리중·마감 설정·저장 | ✅ STATUS_CHANGE+DEADLINE 이벤트 기록 |
| UC7 | 위험 규칙/재분류 | telnet 금지 규칙 추가 | ✅ 22건 즉시 banned 재분류 |
| UC8 | 부서통보 | 부서 선택→통보문 생성→기록 | ✅ 통보문 생성·기록 1건 |
| UC9 | 리포트/내보내기 | 감사 xlsx·발견 CSV·히트맵 xlsx | ✅ xlsx(PK) 유효, CSV UTF-8 BOM 확인 |
| UC10 | 사용자 관리 | auditor 계정 생성 | ✅ role=auditor 생성 |
| UC11 | 이력 타임라인 | 이력 탭 조회 | ✅ 이벤트 379건 |
| UC12 | 감사 로그 | /audit 조회 | ✅ LOGIN·SCAN_IMPORT·RULE_CREATE 기록 |
| UC13 | 히트맵 | 시간축 히트맵 렌더 | ✅ 372행 렌더 |
| UC14 | **재스캔 조치검증 루프** | 실제 포트 toggle 3회 재스캔 | ✅ 자동 정상처리·REOPENED (아래 상세) |

### UC14 — 핵심 라이프사이클 (실제 포트스캔)
호스트를 살린 채 포트만 여닫기 위해 localhost 서비스(8085/8086)를 toggle하며 실제 nmap 재스캔:

1. **기준 스캔**(8085 open) 가져오기 → 발견 생성(open/미조치)
2. **조치완료 시뮬**: 8085 서비스 종료 → 재스캔(8085 closed, 호스트 up) 가져오기
   → **자동 `정상처리` 전환 + `CLOSED` 이벤트** ("포트 닫힘 — 조치 완료 자동 확인")
3. **재발 시뮬**: 8085 재기동 → 재스캔(8085 open) 가져오기
   → **`REOPENED` 이벤트 + 재발 태그(reopened=1) + 상태 미조치 복귀**

`ingest.py` 의 조치검증 의미론 확인: 닫힌 포트가 이전에 `처리중`이었거나 `마감`이 걸려 있으면
CLOSED 이벤트에 "조치 완료 자동 확인"으로 기록(그 외는 단순 "포트 닫힘"), 상태는 모두 정상처리.

---

## 4. 발견된 미비점 / 개선 필요 영역

검증 중 실제로 확인된 항목(심각도 순).

### [중] `/api/diff` 미구현 — 문서·구현 불일치
`DESIGN.md §5` 에 `GET /api/diff?base=&target=`(스캔 간 변화)로 명시돼 있으나 실제 라우트는
없고 **404 Not Found** 를 반환한다. diff 기능 자체는 (a) 가져오기 응답의 counts(new/closed/
reopened…), (b) 히트맵의 "시점 비교" 시트, (c) FindingEvent 타임라인(CLOSED/REOPENED)으로
제공된다. → DESIGN.md에서 `/api/diff` 항목을 실제 표면(heatmap/events)에 맞게 정정하거나,
얇은 diff 엔드포인트를 추가할 것.

### [중] BOM 없는 UTF-8 CSV → 무경고 컬럼 매핑 실패
자산대장 CSV를 **BOM 없이** UTF-8로 저장하면 SheetJS가 한글 헤더·값을 잘못 디코딩해
**IP를 제외한 모든 컬럼(부서/담당자/연락처/호스트명)이 조용히 매핑 실패**한다(경고 없음).
Excel 저장본(BOM 포함)은 정상. 실제로 본 검증에서 BOM 추가 후에야 부서 매칭이 동작했다
(미지정 372→266). → 가져오기 미리보기에서 "필수 컬럼 미매핑" 경고를 띄우거나, 인코딩
자동감지(BOM 없는 UTF-8/CP949) 보강 권장.

### [낮] 영문 헤더 `dept`/`owner` 자동매핑 누락
자동매핑 별칭이 한글 위주(부서/담당자…)라 영문 `dept`/`owner` 헤더는 자동매핑되지 않는다
(`ip`/`hostname`/`contact`/`asset`은 영문 별칭 있음). 수동 매핑은 가능하나, 자동매핑 실패 시
사용자에게 알림이 없어 컬럼이 조용히 누락될 수 있다.

### [낮] 발견 검색 상호작용 불일치
- 검색창은 **Enter 로만** 조회(즉시 필터 아님, 검색 버튼 없음). 반면 위험/상태 드롭다운은
  즉시 적용 → 상호작용이 일관되지 않아 사용자가 "검색이 안 된다"고 오해할 수 있음.
- 검색 대상이 **서비스명/호스트명**뿐이라 포트 번호(예: 8085)로는 검색되지 않는다.

### [정보] 발견별 수동 담당자(owner) 배정 UI 부재
`DESIGN.md` 는 "담당 배정"을 라이프사이클 단계로 명시하고 모델에도 `owner_user_id` 가 있으나,
발견 드로어의 편집 컨트롤은 **상태/마감/메모**뿐이다. 담당자는 자산대장 IP 매칭으로만 파생되며
발견 단위로 특정 사용자를 수동 배정하는 UI는 없다. → 의도된 설계라면 DESIGN 문구 정합화,
아니라면 드로어에 담당자 선택 추가 검토.

### [정보] 호스트 다운 시 정직한 상태 유지(오해 소지)
컨테이너를 통째로 중지하면 호스트가 down 되어 nmap이 "닫힌 포트"와 "도달 불가"를 구분하지
못한다. ScanOps는 이 경우 해당 포트를 **자동 닫힘 처리하지 않는다**(false-resolve 방지 — 올바른
동작). 포트만 닫히고 호스트가 up일 때만 조치검증이 동작한다. 올바르나 운영자가 "왜 안 닫혔지?"로
오해할 수 있어 문서/툴팁 보강 가치가 있음.

---

## 5. 재현 방법

```bash
# 0) 준비: nmap 설치, 백엔드 의존성
apt-get install -y nmap
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -r requirements-dev.txt

# 1) 샘플 생성
python3 test_samples/generate_samples.py

# 2) 백엔드 기동 (스캔 허용대역 지정)
SCANOPS_SCAN_SCOPE="172.30.0.0/24 127.0.0.0/8 10.0.0.0/8 192.168.0.0/16 203.0.113.0/24" \
  .venv/bin/python -m uvicorn scanops.main:app --host 0.0.0.0 --port 8770

# 3) docker 랩 + 실제 포트스캔
cd lab && docker compose up -d
nmap -sV -p- -oX scan.xml 172.30.0.10-15

# 4) 헤드리스 Chromium(CDP :9222) 기동 후 UI 시나리오 실행
node test_samples/uc_imports.mjs   # UC1-4
node test_samples/uc_ops_a.mjs     # UC5-7
node test_samples/uc_ops_b.mjs     # UC8-13
node test_samples/uc_rescan.mjs    # UC14
```

## 6. 결론

- 핵심 루프(스캔→분류·근거→담당·마감→**재스캔 자동 조치검증**→감사)가 실제 UI+실제 포트스캔으로
  관통 동작함을 확인. 프론트 안정성(예외/콘솔에러/빈화면 0) 양호.
- 치명적 결함은 없음. 개선 필요 항목은 대부분 **문서 정합성**과 **가져오기 견고성(인코딩/경고)**,
  일부 **UX 일관성**에 집중됨. 위 4장 목록이 우선 조치 대상.
