# ScanOps 샘플 랩 (WSL Docker)

`172.30.0.0/24` docker 브리지에 다양한 포트 프로필 호스트를 띄워, **단계 분리 포트스캔**을
실측하고 샘플 스캔 내역을 쌓는 개발용 랩. 실호스트(톨넷) 대신 완전 재현·완전 인가 환경.

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
