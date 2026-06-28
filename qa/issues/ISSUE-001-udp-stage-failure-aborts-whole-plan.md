# ISSUE-001 — UDP identify 단계의 exit≠0 이 전체 스캔을 실패시킨다

- **status**: open
- **severity**: high
- **component**: scanner/scanops_scanner.py (`execute_auto`, `run_nmap_stage`, `fail_plan`)
- **reported-by**: user (관찰: "UDP 스캔 중간에 exit1 로 실패하는 케이스")
- **confirmed-by**: troubleshooter (코드 분석)

## 증상
auto 워크플로에서 TCP discovery → TCP identify 가 성공해도, 마지막 `udp_identify`
단계에서 nmap 이 비정상 종료(rc≠0, 예: 수다/증폭 UDP 응답으로 인한 fatal)하면
`execute_auto` 가 `fail_plan` 을 호출해 **플랜 전체를 `failed` 로 마킹하고 rc 를 그대로
반환**한다. 이미 성공적으로 수집한 TCP 결과가 "실패한 스캔"으로 묻힌다.

## 근거 (코드)
`execute_auto`의 각 stage 호출부:
```python
rc = run_nmap_stage(plan, idx, state_path, "udp_identify", ...)
if rc != 0:
    return fail_plan(plan, state_path, rc)   # ← TCP 결과까지 통째로 실패 처리
```
`run_nmap_stage` 는 `subprocess.call` 의 rc 를 그대로 받는다. nmap 은 일부 상황에서
부분 결과(XML)를 쓰고도 비정상 종료할 수 있다. UDP 단계는 가장 불안정한 단계인데,
그 실패가 전체 라이프사이클을 깨뜨리는 구조.

## 기대 동작 (제안 방향, 패치 전 검증 필요)
- UDP identify 는 "best-effort" 단계로 격리: 실패해도 TCP 결과로 플랜을 완료(`done`)
  하되, 해당 stage 를 `failed`/`partial` 로 정직하게 기록하고 경고를 남긴다.
- nmap 이 부분 XML 을 남겼다면 import 후보에서 버리지 않는다(검증 필요).
- 단, discovery/ identify 같은 핵심 단계의 실패는 기존대로 플랜 실패로 둘지 정책 결정 필요.

## 재현 방향
- fake_nmap 하베스에 `FAKE_NMAP_FAIL_STAGE=udp_identify` 로 rc≠0 강제 → 현재는 plan
  status=failed, TCP XML 이 manifest 에 남는지/안 남는지 확인.
- 실측: tailscale 타겟(myarch 100.78.204.76)에 UDP 식별 반복 실행하여 fatal 유도.
