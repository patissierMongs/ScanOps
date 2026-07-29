# ScanOps 스트레스/엣지케이스 검증 리포트 (20 케이스)

추출·처리 과정의 데이터 엣지케이스, 확인/취소 반복 분기, 발송·재스캔 로직, 성능/일관성을
각각 다른 상황으로 구성해 **기대결과를 먼저 가정하고 실제 실행 결과와 대조**했다.

- 하네스: `test_samples/stress_api.py`(API 레벨), `test_samples/stress_ui.mjs`(CDP UI 레벨), SC18 실측 재스캔
- 데이터 격리: 기존 데이터와 충돌 없도록 `198.51.100.x`(TEST-NET-2)·`100.64.x` 대역 사용
- **결과: 20/20 PASS** (검증 중 발견한 실제 버그 1건은 이 브랜치에서 수정) · JS 예외 0 · 콘솔 error 0

---

## 1. 추출/파싱 엣지케이스

| # | 상황 | 기대결과 | 실제결과 | 판정 |
|---|---|---|---|---|
| SC01 | 빈 nmaprun(host 0) | 가져오기 성공·counts 전부 0·발견 미생성 | counts 전부 0 | ✅ |
| SC02 | up 호스트·포트 0 | 발견 0·파싱 무오류 | new=0 | ✅ |
| SC03 | closed/filtered 포트만 | 열린포트 없음→발견 0(닫힘=부재) | new=0, findings=0 | ✅ |
| SC04 | 깨진 XML(unclosed) | 400 파싱실패·백엔드 생존·좀비스캔 없음 | **수정 전 500** → 수정 후 400·생존·좀비 0 | ✅(수정) |
| SC05 | 파일 내 중복 finding_key | 동일 host\|port\|proto → 1건 upsert | 9090 findings=1 | ✅ |
| SC06 | 동일 XML 2회(멱등) | 2회차 new=0·unchanged≥1·중복 없음 | 1st new=1 / 2nd unchanged | ✅ |
| SC07 | 유니코드·특수문자·초장문(405자) | 원형 보존·근거 표면화·주입 없음 | 유니코드 보존·evidence 표면화·`<script>` 문자열로만 저장 | ✅ |
| SC08 | UDP `open\|filtered` 상태 | state가 'open'으로 시작→인입(proto=udp) | findings=1, proto=udp | ✅ |

> **SC07 참고:** `nse_json` 은 `FindingOut` 에 원본으로 노출되지 않고(설계) `/evidence`·`remarks`·
> `fingerprint` 로 표면화된다. 저장값(sqlite)에는 엔티티가 정상 복원돼 안전하게 문자열로 보관되며
> 스크립트 주입은 발생하지 않는다.

## 2. 처리/분류

| # | 상황 | 기대결과 | 실제결과 | 판정 |
|---|---|---|---|---|
| SC09 | scaninfo 누락 + 미지 서비스 | 성공·미지 서비스는 info/미분류 기본값 | risk=info, category="" | ✅ |
| SC10 | banned_service 규칙 추가/삭제 | high→banned→(삭제)→high 복원 | 정확히 토글 | ✅ |
| SC11 | port_rule 포트기반 오버라이드 | 포트 6000 → high 상향(서비스 무관) | high | ✅ |

## 3. 확인/취소 반복 분기 (실제 UI 조작)

| # | 상황 | 기대결과 | 실제결과 | 판정 |
|---|---|---|---|---|
| SC12 | 상태 전이 전체 | 미조치→처리중→정상처리→미조치·STATUS_CHANGE 누적 | 전이 정확·이벤트 3회 | ✅ |
| SC13 | markNormal 2단계 확인/취소/되돌림 | 1클릭→'확인?'·4s 자동취소(불변)·2클릭→정상처리·되돌리기→원복 | 4개 분기 모두 정확 | ✅ |
| SC14 | 재스캔 드로어 열기/취소 반복 | 3회 반복해도 잔여 드로어 0·스캔 미생성 | 열기3/닫기3/스캔+0 | ✅ |
| SC15 | 자산 위저드 취소 후 재시도 | 취소=미반영·재시도=정상 반영(업서트) | 취소 후 1605 불변·재시도 정상 | ✅ |

## 4. 발송/재스캔

| # | 상황 | 기대결과 | 실제결과 | 판정 |
|---|---|---|---|---|
| SC16 | 부서통보 발송 + SMTP | 기록 생성·channel=file·외부 SMTP 전송 없음 | 201·channel=file·기록됨 | ✅ |
| SC17 | rescan-command(무실행) | 명령 텍스트만 반환·실제 스캔 미생성 | command 반환·스캔+0 | ✅ |
| SC18 | **실측 재스캔 조치검증(마감 걸린 포트 닫힘)** | closed·자동 정상처리·CLOSED 상세="조치 완료 자동 확인" | 정확히 일치 | ✅ |
| SC19 | rescan-due 일괄 재검증 | 마감초과·처리중 발견 모아 재스캔 생성 | scan_id 반환·대상 hosts 포함 | ✅ |

> **SMTP 관련 결론:** 코드베이스에 SMTP/이메일 전송 구현이 **전혀 없다**(에어갭 설계). 통보는
> `channel="file"` 로 기록만 하고, 실제 외부 전송은 프론트의 복사/`.txt 저장` 으로 사람이 수행한다.
> 이는 문서(`DESIGN.md`, notifications.py 주석 "외부 전송 없음")와 일치하는 **의도된 동작**이다.

## 5. 스트레스/최적화

| # | 상황 | 기대결과 | 실제결과 | 판정 |
|---|---|---|---|---|
| SC20 | 반복 PATCH race + 대량 응답시간 | 15회 연속변경 일관·STATUS_CHANGE 누락없음·목록/내보내기 <2s | 최종=미조치·이벤트 30회·PATCH 평균 9ms·목록(380건) 35ms·내보내기 17ms | ✅ |

성능은 전 구간 여유(수십 ms). 연속 상태 변경에도 이벤트 로그·최종 상태 일관성 유지, 레이스 없음.

---

## 6. 발견 및 수정한 버그

### [수정됨] 깨진 XML 가져오기 → 500 + 좀비 스캔 (SC04)
- **증상:** `POST /api/scans/import` 에 malformed XML 업로드 시 500 Internal Server Error.
- **원인:** `import_xml()` 에서 `scan_start(xml_bytes)`(내부 `ET.fromstring`) 호출이 `try` 블록
  **밖**에 있어 `ParseError` 가 처리되지 않고 500 으로 전파. 게다가 파싱 실패 전에 이미
  `ScanRun(status="running")` 을 생성해 좀비 스캔이 남을 수 있었다.
- **수정:** `scan_start` 를 앞단 try 로 감싸 파싱 실패 시 **스캔 생성 이전에** 400
  ("XML 파싱 실패")으로 정직하게 거절하고 감사로그(ok=False)를 남기도록 변경.
  (`backend/scanops/api/scans.py` `import_xml`)
- **검증:** malformed·비XML 입력 모두 400, 정상 XML 200(회귀 없음), 백엔드 pytest **194 passed**,
  좀비 running 스캔 0.

## 7. 결론

- 20개 케이스 전부 기대대로 동작. 추출(빈/포트없음/닫힘/중복/유니코드/UDP), 처리(미지서비스/
  규칙 토글/포트룰), 확인·취소·되돌림 반복 분기, 발송·재스캔 로직, 성능/일관성까지 관통 검증.
- 스캔 가져오기의 **깨진 XML 방어 결함(500→400)** 1건을 발견·수정. 나머지는 모두 기대와 일치.
- SMTP 는 미구현(설계상 에어갭)이며 통보는 기록 전용임을 확인.

### 재현
```bash
python3 test_samples/stress_api.py     # SC01-11, 16, 17, 19, 20 — 자기인증, 실패 시 exit 1
node   test_samples/stress_ui.mjs      # SC12-15 (CDP :9222 필요), 실패 시 exit 1
# SC18: localhost 서비스 기동→스캔→마감배정→서비스 종료→재스캔→"조치 완료 자동 확인" 확인
```

## 8. 리뷰 반영 — 하네스 견고화 (PR #33 리뷰 피드백)

PR #33 리뷰에서 검증 자산의 재현성 결함이 정확히 지적되어 모두 수정했다.

| 지적 | 조치 |
|---|---|
| UI 스크립트가 `/home/user/...` 하드코딩 → 타 환경에서 `ERR_MODULE_NOT_FOUND` | 드라이버는 상대 임포트(`./driver.mjs`), 경로는 `import.meta.dirname` 기준으로 도출. `SCANOPS_URL`/`SCANOPS_ADMIN_FILE`/`SCANOPS_SHOTS` env 로 덮어쓰기 가능 |
| SC06(동적 `100.64.*.6`)과 SC19(`198.51.100.6`) 불일치 → fresh DB 에서 `IndexError` | SC19 를 자기완결화(전용 발견 `198.51.100.19` 생성 후 검증). 스테일 상태 의존 제거 |
| 실패해도 exit 0 | `stress_api.py`·모든 `*.mjs` 를 실패 시 **비영(exit 1)** 종료로 변경(CI 연동 가능) |
| XML 5개가 실행마다 SHA 상이(“결정론적” 주장과 불일치) | 버전 선택이 전역 `random` 을 쓰던 것을 `(호스트옥텟,포트)` 기반 결정론으로 교체 → 재실행 시 동일 SHA |
| 제품 수정에 회귀 테스트 부재 | 깨진 XML→400·좀비스캔 0·정상 XML→200 을 검증하는 `test_import_malformed_xml_returns_400_no_orphan_scan` pytest 추가 |

검증: 샘플 2회 생성 시 동일 SHA, **fresh DB 에서 `stress_api.py` 15/15·exit 0**, 다른 cwd(`/tmp`)에서도
자기인증으로 동작, 강제 실패 시 exit 1, 백엔드 pytest 통과(회귀 테스트 포함).
