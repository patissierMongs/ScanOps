"""CLI — python -m scanops_engine. --spec job.json 또는 편의 플래그로 단독 실행.

ScanOps 는 보통 --spec 으로 호출(계약). 편의 플래그는 랩/수동 테스트용.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import nmaprun
from .events import EventSink
from .pipeline import Pipeline
from .spec import JobSpec


def _build_spec(a) -> JobSpec:
    if a.spec:
        return JobSpec.from_dict(json.loads(Path(a.spec).read_text(encoding="utf-8")))
    spec = JobSpec(job_id=a.job_id, targets=a.target or [], exclude=a.exclude or [], out_dir=a.out)
    if a.tcp_ports:
        spec.tcp.ports = a.tcp_ports
    spec.udp.enabled = a.udp
    if a.udp_ports:
        spec.udp.ports = a.udp_ports
    if a.nse is not None:
        spec.service.nse = [n for n in a.nse.split(",") if n]
    if a.no_service:
        spec.service.enabled = False
    if a.confirm:
        spec.service.confirm = True
    if a.pn:
        spec.discovery.mode = "pn"
    if a.sudo:
        spec.sudo = a.sudo
    return spec


def main(argv=None) -> int:
    ap = argparse.ArgumentParser("scanops_engine", description="ScanOps 단계분리 포트스캔 엔진")
    ap.add_argument("--spec", help="job spec JSON 경로")
    ap.add_argument("--target", action="append", help="타겟(반복 가능)")
    ap.add_argument("--exclude", action="append", help="제외 타겟(반복 가능)")
    ap.add_argument("--out", default="./engine-out", help="산출 디렉토리")
    ap.add_argument("--job-id", default="job")
    ap.add_argument("--tcp-ports", default=None, help="TCP 포트(기본 1-65535)")
    ap.add_argument("--udp", action="store_true", help="UDP 단계 켜기")
    ap.add_argument("--udp-ports", default=None)
    ap.add_argument("--nse", default=None, help="콤마구분 NSE(빈 문자열=없음)")
    ap.add_argument("--no-service", action="store_true", help="서비스 probe 생략(찾기까지만)")
    ap.add_argument("--confirm", action="store_true", help="서비스 2-pass 정밀 확인")
    ap.add_argument("--pn", action="store_true", help="발견 단계 생략(-Pn)")
    ap.add_argument("--sudo", choices=["auto", "always", "never"], default=None)
    ap.add_argument("--nmap", default="", help="nmap 경로(미지정 시 자동 탐색)")
    ap.add_argument("--no-stdout", action="store_true", help="이벤트 stdout 출력 끄기(파일만)")
    a = ap.parse_args(argv)

    try:
        spec = _build_spec(a).validate()
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"spec 오류: {e}", file=sys.stderr)
        return 2
    if not spec.targets and not spec.targets_ports:
        print("타겟이 없습니다 (--target 또는 --spec).", file=sys.stderr)
        return 2
    nmap = nmaprun.find_nmap(a.nmap)
    if not nmap:
        print("nmap 을 찾을 수 없습니다.", file=sys.stderr)
        return 3

    out = Path(spec.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    sink = EventSink(path=out / "events.ndjson", stdout=not a.no_stdout)
    try:
        counts = Pipeline(spec, sink, nmap).run()
    finally:
        sink.close()
    return 0 if counts["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
