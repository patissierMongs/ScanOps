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

1. 대상 IP/CIDR/범위를 입력하거나 대상 파일을 선택합니다. 필요하면 바로 아래에서 제외할 IP(IP/CIDR/범위)와
   제외할 포트도 입력합니다.
2. 기본값은 `자동 스캔 - 열린 포트와 용도 파악`입니다. 관리자는 한 번만 실행하고, 내부 단계는 스캐너가 자동으로 진행합니다.
   저장해 둔 프리셋이 있으면 `프리셋` 목록에서 골라 그 구성으로 실행할 수 있습니다
   (`현재 구성 저장`·`삭제`·`서버와 동기화` 버튼이 같은 줄에 있습니다).
   노후 장비 대역이면 `자동 스캔 - 저강도(노후 장비 안전)`를 고릅니다.
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

## 스캔 강도 (노후 장비)

기본 강도는 사내망 기준으로 공격적입니다(`-T4`에 `--defeat-rst-ratelimit`, 병렬 100). 10~15년 된
백본/방화벽처럼 control-plane 이 약한 장비에는 `--intensity gentle`을 씁니다. GUI 에서는 실행 방식의
`자동 스캔 - 저강도(노후 장비 안전)`가 같은 설정입니다.

```bash
python3 scanops_scanner.py 10.0.0.0/24 --intensity gentle
python3 scanops_scanner.py 10.0.0.0/24 --intensity gentle --max-rate 80   # 더 낮추기
```

| 항목 | 기본 | `--intensity gentle` |
|---|---|---|
| 타이밍 | `-T4` | `-T3` |
| RST 율제한 우회 | 사용 | **사용 안 함** |
| 병렬 | `--max-parallelism 100` | `10` |
| 호스트 그룹 | `--min-hostgroup 64` | `16` |
| 재시도 (TCP) | `--max-retries 2` | `1` |
| 재시도 (UDP) | `--max-retries 4` | `1` |
| 속도 상한 | 없음 | `--max-rate 150` |

가장 중요한 건 `--defeat-rst-ratelimit`을 쓰지 않는 것입니다. 이 플래그는 장비가 스스로 거는 RST
율제한 보호를 무력화해 오래된 장비의 CPU 를 가장 확실하게 끌어올립니다. `--max-rate`는
`--intensity gentle`이 정한 기본값을 명시 지정으로 덮어쓸 수 있습니다.

UDP 재시도만 TCP 보다 높은 이유는 닫힌 UDP 포트의 ICMP port-unreachable 을 대상 **OS 스택 자체가**
율제한하기 때문입니다(흔히 초당 1회). 재전송을 아끼면 실제로 닫힌 포트가 `open|filtered` 로 남아
'닫혔다'가 아니라 '못 봤다'가 쌓입니다.
저강도는 state 에 저장되어 `--resume` 으로 이어할 때도 같은 강도가 유지됩니다.

```bash
python3 scanops_scanner.py 10.0.0.0/24 --workflow single --profile basic --name quick_check
```

## 프리셋 (저장 · 웹서버와 동기화)

자주 쓰는 스캔 구성을 이름으로 저장해 두고 `--preset 이름`으로 재사용할 수 있습니다.
프리셋 파일은 **이 스크립트와 같은 폴더**의 `scanops_presets.json` 입니다(`--preset-file` 로 변경 가능).

프리셋 본문은 nmap 플래그가 아니라 ScanOps 웹 UI 와 **같은 옵션 키**로 저장됩니다.
그래서 같은 파일을 웹서버와 스캐너 양쪽이 해석할 수 있고, 임의 플래그 주입도 들어오지 못합니다.

```bash
# 현재 구성을 프리셋으로 저장
python3 scanops_scanner.py --workflow single --options syn,version,version_all,fast,open_only,reason \
        --ports 22,80,443 --scripts ssl-cert,http-title --save-preset "웹 점검"

# 자동 스캔 기본 구성을 그대로 저장(웹의 기본 옵션 세트와 동일)
python3 scanops_scanner.py --save-preset "주간 전수"

python3 scanops_scanner.py --list-presets
python3 scanops_scanner.py --preset "웹 점검" 10.0.3.10
python3 scanops_scanner.py --delete-preset "웹 점검"
```

- `--options` 는 웹 UI 의 옵션 키를 그대로 받습니다(`syn`, `connect`, `udp`, `version`, `version_all`,
  `fast`, `t2`, `open_only`, `reason`, `max_retries`, `min_hostgroup`, `max_parallel`, `defeat_rst`, …).
  전체 목록은 잘못된 키를 넣으면 오류 메시지에 출력됩니다.
- `--profile quick`/`light` 는 `--top-ports` 를 쓰는데 웹 옵션 어휘에 대응 키가 없어 프리셋으로
  저장할 수 없습니다. `--options` 와 `--ports` 로 표현한 뒤 저장하세요.
- `--preset` 은 실행 방식·스캔 기법·옵션·NSE 를 결정합니다. 같은 항목(`--options`, `--profile`,
  `--scan-type`, `--udp`, `--scripts`, `--nse-default`, `--no-scripts`)을 명령줄에 같이 주면 어느 쪽이
  이겼는지 알 수 없으므로 **거절**합니다. `--ports`·`--tcp-only`·`--open-only`·`--include-closed` 는
  프리셋 위에 얹는 보정이라 함께 쓸 수 있습니다.
- **자동 워크플로에서 반영되는 것** — 스캔 기법(`-sS`/`-sT`), 타이밍(`-T0`~`-T5`), 포트, NSE,
  열린 포트만 표시, UDP 단계 사용 여부. 나머지 상세 옵션(`-O`, `--traceroute`, `-f` 등)은 단계별 고정
  플래그를 쓰는 자동 워크플로에는 적용되지 않고 `--workflow single` 에서만 그대로 나갑니다.

### 웹서버에 도킹 (프리셋 동기화 + 스캔 결과 업로드)

```bash
python3 scanops_scanner.py --sync --server http://10.0.0.5:8770 --username auditor1
# 비밀번호는 SCANOPS_PASSWORD 환경변수로 주는 것을 권장합니다(명령줄은 같은 호스트의 다른 사용자에게 보입니다).
# 토큰이 있으면: --token "$SCANOPS_TOKEN"

python3 scanops_scanner.py --sync --sync-only presets ...   # 프리셋만
python3 scanops_scanner.py --sync --sync-only results ...   # 스캔 결과만
```

`--sync` 는 두 가지를 함께 합니다.

1. **프리셋 동기화** (아래 규칙)
2. **스캔 결과 업로드** — `--output-dir` 안의 결과를 서버로 올리고 **바로 발견으로 인입**합니다.
   폴더를 찾아 수동 업로드하던 과정이 없어집니다.

**중복은 서버가 막습니다.** 올리기 전에 결과 지문(XML 내용의 SHA-256)을 서버에 물어, 이미 가져온
것은 빼고 새 결과만 전송합니다. 지문은 파일 내용만으로 계산하므로 폴더를 다른 경로로 복사해
도킹해도 같은 결과로 인식됩니다. 강제로 다시 올리려면 `--resend-results` 를 씁니다.

**중단본은 올리지 않습니다.** 중간에 끊긴 스캔은 열린 포트를 다 보지 못한 상태입니다. 그대로
인입하면 못 본 포트가 **미탐**이 되고, 재시도가 잘린 자리의 `filtered` 를 관측으로 믿으면 **오탐**이
됩니다. 발견 관리에서 그 둘은 되돌리기 가장 어려운 오류라, 부분 결과는 사람이 파일을 보고 판단할
재료로만 남깁니다. 도킹은 몇 건을 남겨 두었는지 알려 주고, 그 스캔이 필요하면 `--resume` 으로
완주시킨 뒤 올리면 됩니다.

프리셋 동기화는 **먼저 충돌을 확인한 뒤에만** 합칩니다.

1. 서버 프리셋 목록을 읽어 **같은 이름인데 내용이 다른** 프리셋이 있는지 검사합니다.
   (이름은 앞뒤·연속 공백과 대소문자 차이를 무시하고 비교합니다. 설명과 저장 시각은 비교 대상이 아닙니다 —
   실행 결과가 같으면 같은 프리셋입니다.)
2. 충돌이 하나라도 있으면 **양쪽 모두 그대로 두고** 충돌 목록만 출력한 뒤 종료합니다(종료 코드 `3`).
   부분 병합은 하지 않습니다. 한쪽 이름을 바꾸거나 내용을 같게 맞춘 뒤 다시 실행하세요.
3. 충돌이 없으면 합집합을 서버에 저장하고, 그 최종 목록을 스캐너 파일에도 그대로 씁니다.
   결과적으로 **같은 내용의 프리셋 파일이 스캐너 폴더와 서버 `data/scan_presets.json` 두 곳에 존재**합니다.

서버는 이 병합을 잠금 안에서 읽기→검사→쓰기로 한 번에 처리하므로, 동기화 도중 웹에서 프리셋을
저장해도 어느 한쪽이 조용히 사라지지 않습니다. 확인과 병합 사이에 서버가 바뀌면 `conflict` 로
되돌아오고 스캐너도 자기 파일을 건드리지 않습니다.

같은 이름이고 스캔 동작도 같은데 **설명이나 이름 표기만** 다르면 충돌이 아니라 서버 값으로 맞춥니다
(그것까지 충돌로 보면 동기화가 계속 사람 손을 요구합니다). 다만 로컬 값이 바뀐다는 사실은
`note: ... 서버 값으로 맞췄습니다` 로 출력합니다.

프리셋 이름에는 `/` 와 `\` 를 쓸 수 없습니다(서버 API 의 URL 경로 조각으로도 쓰이기 때문).
이름 비교는 앞뒤·연속 공백과 대소문자 차이를 무시합니다 — `Weekly  Full` 과 `weekly full` 은 같은 이름입니다.

동기화는 ScanOps 의 **auditor 이상** 권한이 필요하고, 서버 감사 로그에 `SCAN_PRESET_SYNC` 로 남습니다.
GUI 에서는 `프리셋` 줄의 `서버와 동기화` 버튼이 같은 동작을 합니다.

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

특정 IP/대역 제외(반복 옵션과 쉼표·공백·줄바꿈을 함께 사용할 수 있음):

```bash
python3 scanops_scanner.py 10.0.0.0/24 --exclude "10.0.0.1, 10.0.0.2" --exclude 10.0.0.128/25
python3 scanops_scanner.py 10.0.0.0/24 --exclude 10.0.0.20-30      # 대상과 같은 범위 문법
```

특정 포트 제외(`--exclude-ports`, nmap 네이티브 전역 필터):

```bash
python3 scanops_scanner.py 10.0.0.10 --exclude-ports 3030          # 3030만 빼고 전부
python3 scanops_scanner.py 10.0.0.10 --exclude-ports "3030,U:161"
```

`--exclude-ports`는 `--ports`와 같은 문법(`3030`, `1-1024`, `T:`/`U:` 접두사)을 쓰며, `-p`를 건드리지
않는 전역 필터라 자동 워크플로의 모든 단계와 `--top-ports` 프리셋에도 그대로 적용됩니다. `T:1-3029,3031-65535`
처럼 범위를 손으로 쪼갤 필요가 없습니다.

`--exclude`는 IPv4 IP/CIDR/마지막 옥텟 범위(`10.0.0.1-10`)를 받으며, 토큰 하나라도 잘못되면 스캔 전체를
입력 오류로 거절합니다.
대상은 먼저 전개·중복 제거하고 `--max-hosts`를 검사한 다음 원래 대상 전체를 `scope`로 검증하며,
그 뒤에 제외 대역을 적용합니다. 따라서 넓은 대역을 전부 제외해 host cap이나 scope를 우회할 수 없습니다.
배치 모드는 제외 후 남은 호스트만 state의 배치에 저장하고, 비배치 모드는 짧은 CIDR/범위 표현을 유지한 채
`--unique`로 중복·겹침 대상을 한 번만 세고 모든 실제 nmap 단계에 하나의 canonical `--exclude a,b`를
전달합니다. 제외 설정은 state에 저장되므로
`--resume` 때 새 값으로 바꿀 수 없고 원래 설정이 그대로 재검증·적용됩니다.

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

생성 폴더를 ScanOps 웹의 `스캔 > 폴더째 가져오기(XML+manifest)`에서 선택합니다. 같은 폴더에 여러 실행의
manifest가 누적되어 있어도 웹이 manifest별 XML 묶음으로 나누어 순서대로 가져옵니다.
자동 스캔은 `*.tcp_discovery.xml`, `*.tcp_identify.xml`, `*.udp_identify.xml`처럼 여러 XML이 생깁니다.
웹은 XML과 같은 폴더의 `*.manifest.json`을 함께 보내 원본 XML의 크기·SHA-256, 제외 후 실제 target,
성공 runstats와 port/protocol 범위를 검증합니다. `import_xml_files`에는 관측 결과뿐 아니라 host가 0이어도
정상 완료된 TCP discovery/single/UDP XML이 포함됩니다. 이 파일이 미관측 닫힘의 증거이므로 discovery를
빼지 마세요. manifest가 있는 디렉터리에서는 계약에 포함되지 않은 진단·잔여 XML을 자동으로 가져오지 않고
건너뛴 개수를 표시합니다. manifest가 없는 다른 디렉터리의 XML은 구형 호환 모드로 관측된 호스트를 기준으로
반영됩니다. 건너뛴 진단 파일이 꼭 필요하면 manifest 없이 별도로 선택하세요.
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
- **시간 상한 없음** — `--host-timeout`·`--script-timeout`은 어느 강도에서도 걸지 않습니다(플래그도
  없앴습니다). 실측에서 소요는 거의 줄지 않은 반면, nmap 은 상한에 걸린 호스트의 포트 표를 **아예
  쓰지 않고** 실행 자체는 `exit="success"` 로 끝냅니다. 그래서 상한 하나가 '살아 있는데 열린 포트가
  없다'로 읽혀 그 호스트의 기존 발견을 전부 닫고 '정상처리'까지 만듭니다 — 되돌리기 가장 어려운
  미탐입니다.
- **결과 요약** — 스캔 끝에 `summary: live_hosts=.. open_tcp=.. open_udp=.. import_xml=..` 를 출력하고,
  관측 결과가 0이면(호스트 다운/도달 불가) 조용한 성공이 아니라 경고를 남깁니다. 정상 완료된 빈 XML은
  manifest와 함께 미관측 닫힘 판정에 사용할 수 있으므로 import 목록에는 남습니다.
- **안전한 중지** — GUI [중지] 또는 정지 신호(Windows CTRL_BREAK / POSIX SIGINT·SIGTERM)는 강제
  종료가 아니라 정상 종료로 처리되어 상태를 `interrupted` 로 저장하고 재개 경로를 안내합니다(좀비
  '실행 중' 상태 방지). GUI 는 중단/실패 후 재개 경로를 자동으로 채웁니다.
  중지 신호를 받으면 nmap 이 그때까지의 결과를 파일에 마저 쓸 때까지 잠깐 기다린 뒤 종료합니다.
- **중단본 분리 보관 + 인입 차단** — 중간에 끊긴 실행의 산출물은 결과 폴더 아래
  **`interrupted/` 하위 폴더**로 옮겨지고, **파일명에도 `.interrupted` 표식이 박힙니다**
  (예: `scanops_scans/interrupted/weekly.10.0.0.5.tcp_discovery.interrupted.xml`).
  폴더만으로 구분하면 파일 하나를 손으로 옮기는 순간 구분이 사라지기 때문입니다.

  **부분 결과는 발견 관리에 넣지 않습니다.** 못 본 포트는 미탐이 되고, 재시도가 잘린 자리의
  `filtered` 를 관측으로 믿으면 오탐이 됩니다. 그래서 세 곳에서 각각 막습니다 —
  도킹(`--sync`)이 목록에 올리지 않고, 웹 `폴더째 가져오기`가 걸러 내며(제외 건수를 표시),
  서버가 이 표식이 붙은 업로드를 거절합니다. 필요하면 `--resume` 으로 완주시킨 뒤 올리세요.

  같은 단계를 여러 번 중단하면 `-2`, `-3` 으로 번호가 붙어 앞선 중단본을 덮어쓰지 않습니다.
  `*.state.json` 과 `*.manifest.json` 은 `--resume` 경로가 깨지지 않도록 원래 위치·이름을
  유지합니다.
- **스캔 허용 대역(scope)** — `--scan-scope` 또는 `SCANOPS_SCAN_SCOPE` 환경변수에 CIDR/IP 를 지정하면
  그 범위 밖 대상은 스캔 시작 전에 거절됩니다. 빈 값만 무제한이며, 잘못된 토큰이나 정상+오류 혼합
  설정도 전체가 입력 오류로 거절됩니다(오타가 제한 해제로 바뀌지 않음).
- **제외 대역(exclude)** — 반복 가능한 `--exclude`에 IPv4 IP/CIDR을 지정하면 자동·단일·UDP-only의
  모든 실제 단계와 명령 확인, 중단 후 재개에 동일하게 적용됩니다. 제외된 호스트는 스캔 결과에 없으므로
  manifest 닫힘 범위에도 들어가지 않아 ScanOps의 기존 finding이 열린 상태를 유지합니다.
- **가져오기 권한 분리** — 성공한 single/TCP discovery는 해당 유효 batch, UDP identify는 실제로 실행한
  UDP target subset에만 미관측 닫힘 권한을 갖습니다. TCP identify와 실패·중단·`--host-timeout` 실행은
  관측 추가만 하며 사라진 finding을 닫지 않습니다. SHA-256은 파일 혼입 방지용 무결성 지문이지 서명이
  아니므로, 웹의 auditor 권한·서버 scope·감사 로그가 신뢰 경계입니다.
- **웹 가져오기 상한** — 제외 후 유효 target이 65,536개를 넘으면 standalone 실행과 기존 manifest는
  그대로 만들되 웹용 닫힘 계약은 생략합니다. 이 경우 XML은 관측 호스트 기준으로만 반영되므로, 정확한
  미관측 닫힘 판정이 필요하면 스캔 범위를 65,536개 이하로 나눕니다.
- **숨은 UDP 전용 호스트** — TCP/ICMP/ACK 발견에 침묵하는 호스트는 기본 UDP 식별에서 빠집니다.
  `--udp-all-targets`(GUI: `숨은 UDP 전용 호스트도 확인`)로 원본 대상 전체에 UDP 식별을 강제할 수 있습니다.

종료 코드: `0` 정상/부분(done·partial), `1` 실패(failed)·파일 오류, `2` 입력 오류,
`3` 프리셋 동기화 충돌(양쪽 변경 없음), `130` 사용자 중지.
