# scanops-engine — 단계분리 포트스캔 엔진

ScanOps 본체와 **분리된 별도 패키지**. one-liner(전포트+UDP+버전+NSE 한 패스) 대신 내부를
단계로 쪼개 좁혀가며 스캔한다. ScanOps DB/taxonomy 를 모르고 **결과(XML)+이벤트(NDJSON)만 생산**한다.

## 계약 (ScanOps ↔ 엔진)

```
입력  job spec(JSON)          →   출력  events.ndjson + 단계별 nmap XML
```

- **입력**: [lab-spec.json](lab-spec.json) 형태의 job spec (타겟·제외·단계별 설정).
- **출력**: `out_dir/` 에
  - `events.ndjson` — 한 줄 한 이벤트. ScanOps 가 tail 해 진행/단계/에러를 UI 로 흘림.
  - `stage0-discovery.xml`, `stage-tcp-b*.xml`, `stage-udp-b*.xml`, `stage3-<ip>.xml` — ScanOps ingest 입력.
  - `run-state.json` — 단계/호스트 재개 커서 + 중지 플래그.

## 단계

| 단계 | 하는 일 | nmap |
|---|---|---|
| 0 발견 | 대역 → live 호스트 | `-sn` (또는 `pn` 모드=생략) |
| 1 TCP 찾기 | live → 열린 TCP (버전/NSE 없이, 빠름) | `-sS -p- --open --min-rate` |
| 2 UDP 찾기 | live → 열린 UDP (독립) | `-sU -p<주요포트>` |
| 3 서비스 probe | **각 호스트 열린 포트에만** -sV+NSE | `-sV --script ... -p T:..,U:..` |

`targets_ports`({ip:[ports]})를 주면 **0/1/2 를 건너뛰고 Stage 3 만** — 취약포트 재스캔용.
`service.confirm=true` 면 1차에 안 잡힌 포트를 retries↑ 로 2-pass 재확인.

## 이벤트

`job_start · stage_start · stage_progress · hosts_up · ports_open · service · error · stage_done · job_done`

## 실행

```bash
# 단독(편의 플래그)
python -m scanops_engine --target 172.30.0.0/24 --exclude 172.30.0.1 --out ./engine-out/lab

# spec 파일(ScanOps 가 쓰는 방식)
python -m scanops_engine --spec lab-spec.json

# 찾기까지만 / 발견 생략 / UDP 포함
python -m scanops_engine --target 10.0.0.0/24 --no-service
python -m scanops_engine --target 10.0.0.5 --pn --udp
```

`-sS` 는 raw 패킷이 필요 → POSIX 비root 면 자동 `sudo`(passwordless 가정), Windows+Npcap 은 불필요(`sudo auto`가 판단).

## 의존성

표준 라이브러리만(외부 패키지 0) + `nmap` 바이너리. 에어갭 동봉에 적합.
