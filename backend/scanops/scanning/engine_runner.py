"""단계분리 엔진 연동 — ScanOps 가 별도 엔진 패키지(engine/scanops_engine)를 제어한다.

엔진은 **subprocess 로만 실행**(backend 는 엔진을 import 하지 않음 — nmap 을 부르던 방식 그대로).
계약: ScanOps 가 job spec(JSON) 을 써서 엔진을 띄우면, 엔진이 out_dir 에
events.ndjson(진행/단계/에러) + 단계별 XML + run-state.json(재개/중지) 을 남긴다.

이 모듈이 하는 일:
- build_job_spec : ScanOps 스캔 옵션 키 → 엔진 단계 설정으로 변환
- spawn          : python -m scanops_engine --spec ... 실행(PYTHONPATH=engine_dir)
- parse_events   : events.ndjson → 단계 요약(상태/소요/카운트/에러) — 진행 타임라인용
- ingest_results : 단계별 XML → 기존 ingest()(diff·라이프사이클)로 finding 인입
- signal_stop/clear_stop/stopped/is_done : run-state.json 기반 중지·재개 제어
"""
from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
import subprocess
import sys
from pathlib import Path

from ..config import get_settings
from . import nmap_runner, process_control, scan_options, taxonomy
from .ingest import ingest
from .nmap_parse import parse_xml

_settings = get_settings()
logger = logging.getLogger(__name__)

_TIMING = {"t0": "-T0", "t1": "-T1", "t2": "-T2", "t3": "-T3", "fast": "-T4", "t5": "-T5"}


def ensure_available() -> Path:
    """Return the vendored engine path or fail before a scan record is created."""
    package = Path(_settings.engine_dir) / "scanops_engine"
    if not (package / "__main__.py").is_file():
        logger.error("vendored scan engine is missing: %s", package)
        raise RuntimeError("스캔 엔진 구성요소가 누락되었습니다. 배포 패키지를 다시 설치하세요.")
    return package


def build_job_spec(scan_id: int, targets: list[str], exclude: list[str], options: list[str],
                   ports: str, nse: list[str] | None, out_dir: Path, batch_size: int,
                   discovery: str = "sn", rescan_units: list | None = None) -> dict:
    """ScanOps 옵션 키를 엔진 단계 설정으로 매핑. 스캔 기법/타이밍/버전강도/UDP/NSE 를 단계로 분배.

    one-liner 옵션(노핑·기법)은 엔진이 단계별로 알아서 처리하므로 그대로 옮기지 않는다.
    """
    opt = set(options or [])
    if "connect" in opt and "syn" in opt:
        raise ValueError("단계 스캔에서는 TCP SYN과 Connect 방식을 동시에 선택할 수 없습니다.")
    if "connect" in opt and "udp" in opt:
        raise ValueError("TCP Connect 단계 스캔은 UDP 스캔과 함께 실행할 수 없습니다.")
    timing = next((_TIMING[k] for k in ("t0", "t1", "t2", "t3", "fast", "t5") if k in opt), "-T4")
    max_retries = 2
    # The engine has protocol-specific stages, so its ``-p`` value does not need Nmap's
    # T:/U: selector used by the legacy combined workflow.
    tcp_spec = nmap_runner.auto_tcp_port_spec(ports)
    udp_spec = nmap_runner.auto_udp_port_spec(ports)
    tcp_ports = tcp_spec.removeprefix("T:")
    udp_ports = udp_spec.removeprefix("U:")
    service = {
        "enabled": True,
        "version_all": not options or ("version_all" in opt and "version_light" not in opt),
        "version_light": "version_light" in opt,
        "timing": timing,
        "max_retries": max_retries,
        "nse": list(scan_options.NSE_DEFAULT_KEYS if nse is None else nse),
    }
    spec: dict = {
        "job_id": f"scan_{scan_id}",
        "targets": list(targets),
        "exclude": list(exclude or []),
        "out_dir": str(out_dir),
        "batch_size": int(batch_size),
        "sudo": "auto",
        "stages": {
            "discovery": {
                "enabled": True,
                "mode": discovery if discovery in ("sn", "pn") else "sn",
                "timing": timing,
                "max_retries": max_retries,
            },
            "tcp": {"enabled": bool(tcp_spec), "ports": tcp_ports, "timing": timing,
                    "scan_type": "connect" if "connect" in opt else "syn",
                    "min_rate": 0, "max_retries": max_retries},
            "udp": {"enabled": "udp" in opt and bool(udp_spec), "ports": udp_ports,
                    "timing": timing, "max_retries": max_retries},
            "service": service,
        },
    }
    if rescan_units is not None:
        spec["rescan_units"] = [dict(u) for u in rescan_units]
        spec["stages"]["service"]["confirm"] = True   # 재스캔: 1차에 안 잡히면 retries↑ 2-pass 재확인
    return spec


def rescan_targets(findings: list[tuple]) -> tuple[list, set]:
    """[(host_ip, port, proto, finding_key)] → ([{ip,port,proto}], scope_keys).

    발견(IP:포트:proto)별 개별 단위 — 항목마다 nmap 1개(그 ip·그 포트만). 중복 제거.
    scope_keys 는 닫힘 판정을 선택 발견으로만 한정하는 데 쓴다(다른 포트 거짓 닫힘 방지).
    """
    units: list[dict] = []
    seen: set = set()
    keys: set = set()
    for ip, port, proto, key in findings:
        proto = (proto or "tcp").lower()
        u = (ip, int(port), proto)
        if u not in seen:
            seen.add(u)
            units.append({"ip": ip, "port": int(port), "proto": proto})
        keys.add(key)
    return units, keys


def describe(spec: dict) -> str:
    """명령 표기용 사람이 읽는 요약."""
    if spec.get("rescan_units"):
        return f"타겟 재스캔(엔진) · {len(spec['rescan_units'])}건 개별(IP:포트별) · Stage3"
    if spec.get("targets_ports"):
        n = sum(len(v) for v in spec["targets_ports"].values())
        return f"타겟 재스캔(엔진) · {len(spec['targets_ports'])}호스트 / {n}포트 · Stage3"
    st = spec["stages"]
    bits = [f"발견 {st['discovery']['mode']}"]
    if st["tcp"]["enabled"]:
        bits.append(f"TCP {st['tcp']['ports']}")
    if st["udp"]["enabled"]:
        bits.append(f"UDP {st['udp']['ports']}")
    bits.append("서비스 --version-all" if st["service"]["version_all"] else "서비스 -sV")
    return "단계스캔(엔진) · " + " · ".join(bits)


def spawn(spec_path: Path, out_dir: Path, log_path: Path) -> subprocess.Popen:
    """엔진을 backend-owned tree로 실행. PYTHONPATH로 vendored package를 주입한다."""
    ensure_available()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_settings.engine_dir) + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [sys.executable, "-m", "scanops_engine", "--spec", str(spec_path), "--no-stdout"]
    with open(log_path, "wb") as logf:
        return process_control.popen_owned(
            cmd, stdout=logf, stderr=subprocess.STDOUT, cwd=str(out_dir), env=env,
            child_guards_parent=True,
        )


def close_owned(process: subprocess.Popen | None) -> None:
    process_control.close_owned(process)


# ── run-state 기반 제어 ──

def _rs_path(out_dir) -> Path:
    return Path(out_dir) / "run-state.json"


def _stop_path(out_dir) -> Path:
    return Path(out_dir) / "stop-requested"


def _read_state(out_dir) -> dict:
    p = _rs_path(out_dir)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    return {}


def signal_stop(out_dir) -> None:
    """엔진 state JSON과 분리된 단조 sentinel로 graceful stop을 요청한다."""
    out = Path(out_dir)
    if not out.exists():
        return
    _stop_path(out).touch(exist_ok=True)


def clear_stop(out_dir) -> None:
    _stop_path(out_dir).unlink(missing_ok=True)
    data = _read_state(out_dir)
    data["stop"] = False
    _rs_path(out_dir).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def stopped(out_dir) -> bool:
    return _stop_path(out_dir).exists() or bool(_read_state(out_dir).get("stop"))


def is_engine_scan(out_dir) -> bool:
    return (Path(out_dir) / "spec.json").exists()


def is_done(out_dir) -> bool:
    return "job" in (_read_state(out_dir).get("stages_done") or [])


# ── 이벤트 → 단계 요약 ──

def parse_events(out_dir) -> dict:
    """events.ndjson 을 단계 요약으로 접는다(라이브 진행·이력 공용). 파일 없으면 빈 결과."""
    path = Path(out_dir) / "events.ndjson"
    stages: dict[str, dict] = {}
    order: list[str] = []
    overall = {"status": "running", "percent": None, "seconds": None, "counts": {}}
    if not path.exists():
        return {"stages": [], "overall": overall}

    def slot(name):
        if name and name not in stages:
            stages[name] = {"stage": name, "status": "pending", "percent": 0, "counts": {}}
            order.append(name)
        return stages.get(name, {})

    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        e, st = ev.get("event"), ev.get("stage")
        if not isinstance(e, str):
            continue
        if (
            e in {"stage_start", "stage_progress", "stage_done", "error"}
            and (not isinstance(st, str) or not st)
        ):
            continue
        if e == "stage_start":
            slot(st).update({"status": "running", "percent": 0})
        elif e == "stage_progress":
            progress = ev.get("percent")
            if isinstance(progress, (int, float)) and not isinstance(progress, bool) and math.isfinite(progress):
                slot(st)["percent"] = max(0, min(100, progress))
            else:
                slot(st)
            stages[st]["status"] = "running"
        elif e == "hosts_up":
            slot("discovery")["counts"]["live"] = ev.get("count")
        elif e == "stage_done":
            s = slot(st)
            cnts = ev.get("counts", {})
            if not isinstance(cnts, dict):
                cnts = {}
            s.update({"status": "stopped" if cnts.get("stopped") else "done",
                      "percent": 100, "seconds": ev.get("seconds"), "counts": cnts})
        elif e == "error":
            s = slot(st)
            label = {"discovery": "호스트 발견", "tcp": "TCP 탐색", "udp": "UDP 탐색",
                     "service": "서비스 식별"}.get(st, "스캔")
            # 원시 이벤트의 cmd/path/rc는 서버 로그에만 남기고 API에는 안정적 메시지만 노출한다.
            s["error"] = f"{label} 단계 실행에 실패했습니다."
            s["status"] = "error"
        elif e == "job_start":
            overall["status"] = "running"
        elif e == "job_done":
            status = ev.get("status")
            if not isinstance(status, str) or status not in {"done", "stopped", "failed"}:
                continue
            seconds = ev.get("seconds")
            if not (
                isinstance(seconds, (int, float))
                and not isinstance(seconds, bool)
                and math.isfinite(seconds)
                and seconds >= 0
            ):
                seconds = None
            counts = ev.get("counts", {})
            if not isinstance(counts, dict):
                counts = {}
            overall.update({"status": status, "seconds": seconds, "counts": counts})

    stage_list = [stages[s] for s in order]
    done = sum(1 for s in stage_list if s["status"] in ("done", "stopped"))
    if overall["status"] != "running":
        overall["percent"] = 100
    elif stage_list:
        cur = next((s for s in stage_list if s["status"] == "running"), None)
        frac = (cur["percent"] or 0) / 100.0 if cur else 0
        overall["percent"] = round(min(done + frac, len(stage_list)) / len(stage_list) * 100, 1)
    return {"stages": stage_list, "overall": overall}


# ── 결과 인입 ──

def _is_ip(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def collect_results(out_dir, scope_keys: set | None = None,
                    force_scanned_hosts: bool = False) -> tuple[list[dict], set[str]]:
    """Return the exact staged observations and hosts used by Finding ingest.

    scope_keys면 그 키만 닫힘 후보 — 다른 포트 거짓 닫힘 방지(기존 ingest 계승).
    force_scanned_hosts는 개별 포트 재스캔의 결과 집계용이다. 명시적 scope_keys가 있으면
    closure 권한은 ingest가 그 키 집합으로 판단하며 discovery 관측 여부와 분리된다. 전체
    스캔에서는 성공한 TCP/UDP sweep을 open 상태의 근거로 보존하고, 같은 키의 stage3
    식별값만 덮어쓴다.
    """
    out = Path(out_dir)
    state = _read_state(out)
    open_map = state.get("open_map") or {}
    live = state.get("live") or []
    scanned = set(open_map.keys()) | {h for h in live if isinstance(h, str) and _is_ip(h)}
    if force_scanned_hosts and scope_keys:
        scanned.update(key.split("|", 1)[0] for key in scope_keys)

    by_key: dict[tuple, dict] = {}
    if not force_scanned_hosts:
        # Service probing is enrichment, not authority over a successful open-port sweep.
        # In particular, a flaky mixed/Windows probe must not close a port just proven open.
        for pattern in ("stage-tcp-b*.xml", "stage-udp-b*.xml"):
            for x in sorted(out.glob(pattern)):
                try:
                    fallback = parse_xml(x.read_bytes())
                except Exception:
                    continue
                for f in fallback:
                    # Sweep proves openness only. It has not run the service/NSE probes and
                    # therefore must not erase an existing identity when stage3 misses a key.
                    f["identity_observed"] = False
                    by_key.setdefault((f["host_ip"], f["port"], f["proto"]), f)
    for x in sorted(out.glob("stage3-*.xml")):
        try:
            fnd = parse_xml(x.read_bytes())
        except Exception:
            continue
        for f in fnd:
            by_key[(f["host_ip"], f["port"], f["proto"])] = f   # confirm/base 중복 제거(존재값 우선)
    return list(by_key.values()), scanned


def ingest_results(db, scan, out_dir, scope_keys: set | None = None,
                   force_scanned_hosts: bool = False, *, commit: bool = True) -> dict:
    """단계별 XML → finding 인입. 명시적 scope_keys는 완료 스캔의 closure 권한."""
    findings, scanned = collect_results(
        out_dir, scope_keys=scope_keys, force_scanned_hosts=force_scanned_hosts,
    )

    enriched = taxonomy.enrich_all(db, findings)
    counts = ingest(
        db, scan.id, enriched, scanned, scope_keys=scope_keys, commit=False,
    )
    from ..api.assets import match_assets
    match_assets(db, commit=False)
    scan.host_count = len({f["host_ip"] for f in findings})
    scan.port_count = len(enriched)
    if commit:
        db.commit()
    else:
        db.flush()
    return counts
