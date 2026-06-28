# ScanOps Standalone Scanner

ScanOps 서버를 실행하지 않는 별도 스캔 서버용 nmap 래퍼입니다.
`scanops_scanner.py` 파일 하나만 복사해서 실행할 수 있고, Python 표준 라이브러리만 사용합니다.

## 요구사항

- Python 3.8+
- nmap 설치 및 PATH 등록
  - Windows는 `C:\Program Files (x86)\Nmap\nmap.exe`, `C:\Program Files\Nmap\nmap.exe`도 자동 탐지합니다.

## 빠른 실행

GUI:

```powershell
python scanner\scanops_scanner_gui.py
```

Windows에서 `scanner\run_gui.bat`를 더블클릭해도 됩니다.

GUI 기본 흐름:

1. 대상 IP/CIDR/범위를 입력하거나 대상 파일을 선택합니다.
2. 기본값은 `자동 스캔 - 열린 포트와 용도 파악`입니다. 관리자는 한 번만 실행하고, 내부 단계는 스캐너가 자동으로 진행합니다.
3. 결과 폴더와 결과 이름을 확인합니다.
4. `명령 확인`으로 내부적으로 실행될 nmap 명령들을 확인합니다.
5. `스캔 시작`을 누르고, 완료 후 생성된 `.xml` 파일을 ScanOps에 가져옵니다.

CLI:

```powershell
python scanner\scanops_scanner.py 10.0.0.10 --name branch-a
```

```bash
python3 scanner/scanops_scanner.py 10.0.0.10 --name branch-a
```

결과는 기본적으로 `scanops_scans/` 아래에 생성됩니다.

- `branch-a.tcp_discovery.xml`: 전체 TCP에서 열린 포트를 찾은 내부 과정 결과
- `branch-a.tcp_identify.xml`: 발견된 TCP 포트의 서비스/제품/버전/용도 단서
- `branch-a.udp_identify.xml`: 주요 UDP 서비스 확인 결과
- `branch-a.*.nmap`: 사람이 읽는 nmap 로그
- `branch-a.*.gnmap`: grepable 결과
- `branch-a.state.json`: 중단/재개 상태
- `branch-a.manifest.json`: 실행 메타데이터

`--workflow single`을 사용한 경우에는 예전처럼 `branch-a.xml`, `branch-a.nmap`, `branch-a.gnmap` 형태로 한 묶음만 생성됩니다.

## 기본 자동 워크플로

기본값은 단일 nmap 실행이 아니라 다음 실행을 자동으로 묶습니다.

1. 전체 TCP에서 현재 열린 포트를 먼저 찾습니다.
2. 발견된 TCP 포트만 다시 확인해 서비스명, 제품/버전, 웹 제목, 서버 헤더, TLS 인증서, SSH 키 같은 용도 추정 단서를 붙입니다.
3. 주요 UDP 서비스 포트도 확인해 DNS, NTP, SNMP, NetBIOS, RPC 같은 단서를 남깁니다.

과거처럼 nmap을 한 번만 실행해야 하는 경우에는 `--workflow single --profile ...`을 사용합니다.
사용 가능한 단일 프로필은 `basic`, `phase1`, `quick`, `light`입니다.

```bash
python3 scanops_scanner.py 10.0.0.0/24 --workflow single --profile basic --name quick_check
```

## 자주 쓰는 예시

특정 포트 재점검:

```bash
python3 scanops_scanner.py --ports 22,80,443 10.0.3.10 10.0.3.11
```

자동 스캔 기본값:

```bash
python3 scanops_scanner.py 10.0.3.10
```

대상 파일 사용:

```bash
python3 scanops_scanner.py --targets-file targets.txt --ports 1-1024 --name weekly_1024
```

명령만 확인:

```bash
python3 scanops_scanner.py --dry-run --ports 22,80 10.0.3.10
```

배치 실행과 재개:

```bash
python3 scanops_scanner.py --targets-file targets.txt --ports 22,80,443 --batch-size 128 --name branch-a
python3 scanops_scanner.py --resume scanops_scans/branch-a.state.json
```

전달용 zip 생성:

```bash
python3 scanops_scanner.py --ports 22,80,443 10.0.3.10 --zip
```

## ScanOps로 가져오기

생성된 `.xml` 파일을 ScanOps 웹의 `스캔 > XML 가져오기`에서 업로드하면 됩니다.
자동 스캔은 `*.tcp_discovery.xml`, `*.tcp_identify.xml`, `*.udp_identify.xml`처럼 여러 XML이 생깁니다.
`*.manifest.json`의 `import_xml_files` 목록을 기준으로 가져오면 됩니다. 기본 추천 목록은 결과 검토 노이즈를 줄이기 위해 `tcp_discovery`를 제외하고, 용도 단서가 붙은 `tcp_identify`와 `udp_identify` 결과를 우선합니다.
배치 실행을 사용한 경우 `*.b0000.tcp_discovery.xml`, `*.b0001.tcp_discovery.xml`처럼 배치 번호가 붙습니다.

특정 UDP 포트만 확인하려면 `--ports U:53`처럼 지정하면 됩니다. 이 경우 TCP 단계는 건너뛰고 UDP 식별만 실행합니다.

## 안정성과 결과 신뢰성

- **단계 격리(부분 성공)** — 자동 워크플로의 각 단계(발견 → TCP 식별 → UDP 식별)는 독립적으로
  처리됩니다. 한 단계(특히 수다스러운 UDP)가 비정상 종료(예: nmap fatal)해도 **이미 성공한 결과는
  버려지지 않습니다.** 스캔은 `partial` 로 마감되어 정상 종료(코드 0)하고, 실패한 단계만 경고로
  남깁니다. 멀티배치에서도 한 배치의 실패가 나머지 배치를 막지 않습니다.
  - `done`: 모든 단계 성공. `partial`: 일부 단계 실패했지만 가져올 결과가 있음(사용 가능).
    `failed`: 가져올 결과가 전혀 없음(코드 1).
  - `--resume` 으로 실패/중단한 단계만 다시 시도할 수 있습니다(성공한 단계·배치는 건너뜀).
- **멈춤 방지** — 모든 자동 단계에 `--host-timeout`(기본 15분)이 적용되어 한 호스트가 스캔 전체를
  무한정 멈추지 않습니다. `--host-timeout 0` 으로 끌 수 있습니다.
- **결과 요약** — 스캔 끝에 `summary: live_hosts=.. open_tcp=.. open_udp=.. import_xml=..` 를 출력하고,
  가져올 결과가 0이면(호스트 다운/도달 불가) 조용한 성공이 아니라 경고를 남깁니다.
- **안전한 중지** — GUI [중지] 또는 정지 신호(Windows CTRL_BREAK / POSIX SIGINT·SIGTERM)는 강제
  종료가 아니라 정상 종료로 처리되어 상태를 `interrupted` 로 저장하고 재개 경로를 안내합니다(좀비
  '실행 중' 상태 방지). GUI 는 중단/실패 후 재개 경로를 자동으로 채웁니다.
- **스캔 허용 대역(scope)** — `--scan-scope` 또는 `SCANOPS_SCAN_SCOPE` 환경변수에 CIDR/IP 를 지정하면
  그 범위 밖 대상은 스캔 시작 전에 거절됩니다(오타·사외 대역 스캔 사고 방지).
- **숨은 UDP 전용 호스트** — TCP/ICMP/ACK 발견에 침묵하는 호스트는 기본 UDP 식별에서 빠집니다.
  `--udp-all-targets`(GUI: `숨은 UDP 전용 호스트도 확인`)로 원본 대상 전체에 UDP 식별을 강제할 수 있습니다.

종료 코드: `0` 정상/부분(done·partial), `1` 실패(failed)·파일 오류, `2` 입력 오류, `130` 사용자 중지.
