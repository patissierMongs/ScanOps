# ScanOps 테스트킷 (엣지케이스 스캔 결과 + dirty 자산대장)

현재 ScanOps 의 **작동 수준**을 빠르게 확인하기 위한 샘플 묶음이다.
스캔 결과 파싱·인입·분류·재스캔 조치검증(diff)과 **자산대장 고급 가져오기**(병합셀·헤더감지·
자동매핑·결합셀·중복/누락)를 한 번에 자극한다. 실제 nmap·엑셀 툴 없이 재현·적재된다.

```
scan_01_baseline.xml        기준 스캔 — 15 호스트, 33 개방포트, 온갖 엣지
scan_02_rescan.xml          재스캔 — 조치완료(닫힘)/신규개방/버전변경 diff
scan_03_discovery_only.xml  발견만(up) · 열린 포트 0 (노출 없음)
scan_04_broken.xml          깨진 XML — 가져오기 오류 경로
asset_ledger_dirty.xlsx     일부러 지저분한 자산대장(3 시트, 메인 108 데이터행)
gen_scan_samples.py         스캔 XML 재생성기 (stdlib)
gen_dirty_ledger.py         자산대장 재생성기 (openpyxl)
load_testkit.py             실행 중 서버에 스캔+자산 일괄 적재(헤드리스 시더)
```

## 1. 스캔 결과 샘플이 겨냥하는 엣지케이스

`scan_01_baseline.xml` (10.10.20.0/24, `parse_xml` 이 개방포트만 인입):

| 호스트 | 노린 것 |
|---|---|
| 10.10.20.11 sec-pc-01 | SMB(445)/RDP(3389) 고위험 · **닫힌 telnet 섞임(파서 무시)** · ssl-cert NSE(CN 추출) |
| 10.10.20.12 hr-srv-01 | ssh/http/mysql · **한글 http-title** · http-server-header |
| 10.10.20.13 infra-aix-01 | ftp(anon)/telnet(평문) — 재스캔 조치검증 대상 |
| 10.10.20.14 fin-db-01 | mssql/postgres/**redis(무인증)**/mongo — DB 다중 노출 |
| 10.10.20.15 web-proxy-01 | **8770 이 apple-iphoto 로 오탐**되나 fingerprint-strings 에서 `server=uvicorn` 추출 · **tcpwrapped(443)** |
| 10.10.20.16 misc-01 | **미확인**(unknown) · 이름없는 **추측**(method=table) |
| 10.10.20.17 iot-cam-01 | 서비스/버전에 **XML 특수문자**(`& < > "`) — 이스케이프 경로 |
| 10.10.20.18 dns-01 | **UDP** 53/123/161 · `open\|filtered` · snmp `public` |
| 10.10.20.19 | **다운 호스트**(열린 포트 0) |
| (MAC only) printer-mac | **ipv4 없이 MAC 주소만** — 스코프 누수 방지 확인 |
| 2001:db8:20::a | **IPv6 전용** 호스트 |
| 10.10.20.21 | **PTR 없음**(hostname 공백) · smb-os-discovery hostscript 에 컴퓨터명 |
| 10.10.20.22 legacy-01 | rpcbind/nfs/r-services(평문·고위험) |
| 10.10.20.23 ops-vnc-01 | VNC(무인증) |
| 10.10.20.26 fw-shadow-01 | **전부 filtered**(열린 포트 0) |

`scan_02_rescan.xml` — 11·12·13 재스캔으로 **diff** 를 만든다:
- infra-aix-01: **telnet 닫힘**(조치완료·능동 거부) · **ftp 필터드**(도달불가 추정) · ssh 유지
- sec-pc-01: **rdp 닫힘**(조치완료) · 445 유지 · **winrm(5985) 신규개방**
- hr-srv-01: **nginx 1.18.0 → 1.24.0 버전변경** · mysql 유지

## 2. dirty 자산대장이 겨냥하는 것 (`asset_ledger_dirty.xlsx`)

고급 가져오기(`frontend/src/lib/assetImport.js`)의 정제 경로를 모두 자극한다:

- **제목/부제 행이 헤더 위** → 헤더행 자동감지(메인 시트는 3행이 진짜 헤더)
- **부서 셀 세로 병합** → 병합해제 forward-fill
- **제목 셀 가로 병합**
- **지저분한 헤더명**(`IP 주소`, `관리 부서`, `담당자(성명)`, `연락처 / 내선`) → 자동 컬럼매핑
- **placeholder 토큰**(`-`, `N/A`, `없음`, `미지정`, `해당없음`, `.`) → 빈값 정리
- **결합 셀**(`인프라팀 / 이인프라` 한 칸) → 구분자 분리(part0=부서, part1=담당)
- **중복 IP**(공백 포함 `  10.10.20.12  `) → 업서트
- **IP 누락 행** → 스킵
- **매핑 밖 여분 컬럼**(도입일/위치/비고) → 보존
- **멀티시트**(`자산대장(취합)` / `인프라팀` / `요약`) — 요약 시트는 자산 아님으로 스킵

스캔 샘플과 겹치는 IP(10.10.20.11~26)를 넣어, 가져오면 **IP 매칭으로 발견에 부서/담당/연락처가 자동 연결**된다.

## 3. 적재 방법

### (a) 헤드리스 시더 — 브라우저 없이 한 번에
서버가 8770 에서 돌고 있으면(올인원은 `START.bat`), admin 비밀번호로:
```
python load_testkit.py <admin_password>
# 올인원 번들에서는:  LOAD_SAMPLES.bat <admin_password>
```
스캔 XML 은 실제 `POST /api/scans/import` 로, 자산대장은 프론트 정제 로직을 그대로 포팅해
`POST /api/assets/bulk` 로 넣는다. (openpyxl 은 올인원 런타임에 사전설치되어 있음.)

### (b) 화면에서 수동
- 스캔 XML: **스캔 > XML 가져오기** 에 `scan_01`→`scan_02` 순으로.
- 자산대장: **자산 > 가져오기** 에 `asset_ledger_dirty.xlsx` 업로드 후 헤더행/매핑을 확인.
  (여기서 병합해제·헤더감지·결합셀 매핑 UI 가 실제로 동작하는지 눈으로 검증)

## 4. 실측된 현재 작동 수준 (참고)

로컬 백엔드에 위 시더로 적재한 결과:
- `scan_01` new 33 · `scan_02` new 1/version_changed 1/unchanged 3/**closed 5**(조치완료+미재프로브) · `scan_03` 0
- 자산 129건 적재 · 발견 28건 중 **25건에 부서 자동 연결**
- **`scan_04_broken.xml` 은 `400`(파싱 실패)이 정답이지만 현재 `main` 은 `500` 을 반환한다.**
  `POST /api/scans/import` 가 `scan_start()` 를 `try` 밖에서 호출하는 버그로, 열려 있는
  PR #12(테스트 기반)에서 이미 수정된다. 이 샘플이 그 회귀를 드러낸다.

## 5. 재생성
```
python gen_scan_samples.py     # scan_01~04 재생성
python gen_dirty_ledger.py     # asset_ledger_dirty.xlsx 재생성 (openpyxl 필요)
```
