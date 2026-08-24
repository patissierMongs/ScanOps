# ScanOps 샘플 랩 (WSL Docker)

`172.30.0.0/24` docker 브리지에 다양한 포트 프로필 호스트를 띄워, **단계 분리 포트스캔**을
실측하고 샘플 스캔 내역을 쌓는 개발용 랩. 실호스트(톨넷) 대신 완전 재현·완전 인가 환경.

## Windows 오프라인 루프백 랩

Docker나 WSL 없이 Windows 한 대에서 여러 IP와 서로 다른 TCP·UDP 포트를 만들려면
`loopback_lab.ps1`을 사용한다. 한 Python 프로세스가 `127.0.0.2-127.0.0.6`에 정확히
바인딩하므로 인터넷 연결이나 별도 네트워크 어댑터가 필요 없다.

```powershell
cd <repo>\lab
.\loopback_lab.ps1 start       # 백그라운드 시작
.\loopback_lab.ps1 status      # IP별 포트 확인
.\loopback_lab.ps1 check       # 모든 TCP·UDP 응답 자체 검사
.\loopback_lab.ps1 stop        # 정상 종료
```

관리 스크립트 없이 `python loopback_lab.py`로 전경 실행하고 `Ctrl+C`로 종료할 수도 있다.

| IP | 이름 | TCP | UDP |
|---|---|---|---|
| 127.0.0.2 | alpha | 8022, 8080, 8443, 4444 | 1053, 1161 |
| 127.0.0.3 | bravo | 8022, 8080, 8443, 3333 | 1053, 5060 |
| 127.0.0.4 | charlie | 8022, 8080, 8888 | 1161, 11211 |
| 127.0.0.5 | delta | 8080, 8443, 9999 | 1053, 11211 |
| 127.0.0.6 | echo | 8022, 8080, 8443 | 5060 |

TCP 합집합은 `3333,4444,8022,8080,8443,8888,9999`, UDP 합집합은
`1053,1161,5060,11211`이다. 웹 스캔 대상에는 `127.0.0.2-6`을 입력한다. 호스트별 실제
포트와 합집합 포트의 차이가 명확해서 배치 서비스 프로브와 개별 fallback을 함께 검증할 수 있다.
고포트를 사용하므로 로컬 SSH·웹·mDNS 서비스와 충돌할 가능성도 낮다.

> 이 랩은 동일 PC의 루프백 소켓이다. 포트 취합·서비스 프로브·진행 이력 검증에는 적합하지만
> 실제 라우터, 방화벽, 패킷 손실, 호스트별 지연을 재현하지는 않는다.

## 호스트 로스터

| IP | 컨테이너 | 서비스 | 열린 포트 |
|---|---|---|---|
| 172.30.0.10 | lab-web | nginx | 80 |
| 172.30.0.11 | lab-db | postgres | 5432 |
| 172.30.0.12 | lab-cache | redis | 6379 |
| 172.30.0.13 | lab-ftp | vsftpd | 21 |
| 172.30.0.14 | lab-web2 | nginx | 80 |
| 172.30.0.15 | lab-dark | busybox | (없음 — 살아있으나 포트 0) |

> 포트는 host 로 publish 하지 않음 → labnet 브리지에서만 보임. WSL 호스트가 게이트웨이
> `172.30.0.1` 로 브리지에 직접 붙어 있어 컨테이너 IP를 그대로 스캔한다.

## 사용 (WSL에서)

```bash
cd <repo>/lab
# 랩 올리기
docker compose up -d
# 단계 분리 스캔 (Stage0 발견 → 1 TCP찾기 → 3 서비스probe). 샘플은 samples/<ts>/ 에 적재.
python3 staged_scan.py                      # 기본 172.30.0.0/24, 게이트웨이 제외
python3 staged_scan.py 172.30.0.0/24 172.30.0.1
# 포트 올렸다 내렸다 (전이 샘플 만들기)
docker compose stop cache web2 && python3 staged_scan.py   # CLOSED 전이
docker compose start cache web2 && python3 staged_scan.py  # REOPENED 전이
# 랩 내리기
docker compose down
```

`-sS` 는 root 필요 → 스크립트가 passwordless `sudo` 로 자동 호출.

## 산출물 (samples/<타임스탬프>/)

- `stage0-discovery.{xml,gnmap,nmap,stdout.log}` — 호스트 발견
- `stage1-tcp.*` — TCP 전포트 찾기 (버전/NSE 없이, 빠름)
- `stage3-<ip>.*` — 호스트별 서비스 probe (열린 포트에만 -sV + 타겟 NSE)
- `summary.json` — 단계별 명령·소요시간·열린포트·서비스 식별 통합

## 단계 분리가 보여주는 것

- Stage3(서비스 probe)이 전체 시간의 대부분이지만 **Stage1이 찾은 열린 포트에만** 붙음.
- `lab-dark`: Stage0에선 발견되나 Stage1에서 포트 0 → Stage3에서 자동 제외 (불필요 probe 0).
- 토글로 open→closed→reopen 전이를 만들어 ScanOps diff/라이프사이클 샘플 생성.
