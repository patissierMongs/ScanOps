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
import os
import subprocess
import sys
from pathlib import Path

from ..config import get_settings
from . import taxonomy
from .ingest import ingest
from .nmap_parse import parse_xml

_settings = get_settings()

_TIMING = {"t0": "-T0", "t1": "-T1", "t2": "-T2", "t3": "-T3", "fast": "-T4", "t5": "-T5"}


def build_job_spec(scan_id: int, targets: list[str], exclude: list[str], options: list[str],
                   ports: str, nse: list[str], out_dir: Path, batch_size: int,
                   discovery: str = "sn", rescan_ports: dict | None = None) -> dict:
    """ScanOps 옵션 키를 엔진 단계 설정으로 매핑. 스캔 기법/타이밍/버전강도/UDP/NSE 를 단계로 분배.

    one-liner 옵션(노핑·기법)은 엔진이 단계별로 알아서 처리하므로 그대로 옮기지 않는다.
    """
    opt = set(options or [])
    timing = next((_TIMING[k] for k in ("t0", "t1", "t2", "t3", "fast", "t5") if k in opt), "-T4")
    service = {
        "enabled": True,
        "version_all": "version_all" in opt,
        "version_light": "version_light" in opt,
        "max_retries": 4,
    }
    if nse:
        service["nse"] = list(nse)            # 비우면 엔진 기본 NSE 사용
    spec: dict = {
        "job_id": f"scan_{scan_id}",
        "targets": list(targets),
        "exclude": list(exclude or []),
        "out_dir": str(out_dir),
        "batch_size": int(batch_size),
        "sudo": "auto",
        "stages": {
            "discovery": {"enabled": True, "mode": discovery if discovery in ("sn", "pn") else "sn"},
            "tcp": {"enabled": True, "ports": ports or "1-65535", "timing": timing,
                    "min_rate": 1000, "max_retries": 2},
            "udp": {"enabled": "udp" in opt, "timing": "-T3"},
            "service": service,
        },
    }
    if rescan_ports is not None:
        spec["targets_ports"] = {ip: list(ps) for ip, ps in rescan_ports.items()}
        spec["stages"]["service"]["confirm"] = True   # 재스캔: 1차에 안 잡히면 retries↑ 2-pass 재확인
    return spec


def rescan_targets(findings: list[tuple]) -> tuple[dict, set]:
    """[(host_ip, port, finding_key)] → ({ip: [ports]}, scope_keys).

    호스트별로 그 호스트의 포트만 모은다(기존 동기 재스캔의 host×port 교차곱 제거).
    scope_keys 는 닫힘 판정을 선택 발견으로만 한정하는 데 쓴다(다른 포트 거짓 닫힘 방지).
    """
    ports_by_ip: dict[str, set] = {}
    keys: set = set()
    for ip, port, key in findings:
        ports_by_ip.setdefault(ip, set()).add(int(port))
        keys.add(key)
    return {ip: sorted(ps) for ip, ps in ports_by_ip.items()}, keys


def describe(spec: dict) -> str:
    """명령 표기용 사람이 읽는 요약."""
    if spec.get("targets_ports"):
        n = sum(len(v) for v in spec["targets_ports"].values())
        return f"타겟 재스캔(엔진) · {len(spec['targets_ports'])}호스트 / {n}포트 · Stage3"
    st = spec["stages"]
    bits = [f"발견 {st['discovery']['mode']}", f"TCP {st['tcp']['ports']}"]
    if st["udp"]["enabled"]:
        bits.append("UDP")
    bits.append("서비스 --version-all" if st["service"]["version_all"] else "서비스 -sV")
    return "단계스캔(엔진) · " + " · ".join(bits)


def spawn(spec_path: Path, out_dir: Path, log_path: Path) -> subprocess.Popen:
    """엔진을 subprocess 로 실행. PYTHONPATH 로 엔진 패키지를 주입(에어갭 vendored)."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_settings.engine_dir) + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [sys.executable, "-m", "scanops_engine", "--spec", str(spec_path), "--no-stdout"]
    logf = open(log_path, "wb")
    return subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, cwd=str(out_dir), env=env)


# ── run-state 기반 제어 ──

def _rs_path(out_dir) -> Path:
    return Path(out_dir) / "run-state.json"


def _read_state(out_dir) -> dict:
    p = _rs_path(out_dir)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    return {}


def signal_stop(out_dir) -> None:
    """엔진이 단계/호스트 경계에서 감지할 stop 플래그를 쓴다(graceful). 엔진 스캔이 아니면 무해."""
    out = Path(out_dir)
    if not out.exists():
        return
    data = _read_state(out)
    data["stop"] = True
    _rs_path(out).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def clear_stop(out_dir) -> None:
    data = _read_state(out_dir)
    data["stop"] = False
    _rs_path(out_dir).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def stopped(out_dir) -> bool:
    return bool(_read_state(out_dir).get("stop"))


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
        e, st = ev.get("event"), ev.get("stage")
        if e == "stage_start":
            slot(st).update({"status": "running", "percent": 0})
        elif e == "stage_progress":
            slot(st)["percent"] = ev.get("percent")
            stages[st]["status"] = "running"
        elif e == "hosts_up":
            slot("discovery")["counts"]["live"] = ev.get("count")
        elif e == "stage_done":
            s = slot(st)
            cnts = ev.get("counts", {})
            s.update({"status": "stopped" if cnts.get("stopped") else "done",
                      "percent": 100, "seconds": ev.get("seconds"), "counts": cnts})
        elif e == "error":
            s = slot(st)
            s["error"] = ev.get("message") or f"rc={ev.get('rc')}"
            s["status"] = "error"
        elif e == "job_start":
            overall["status"] = "running"
        elif e == "job_done":
            overall.update({"status": ev.get("status"), "seconds": ev.get("seconds"),
                            "counts": ev.get("counts", {})})

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


def ingest_results(db, scan, out_dir, scope_keys: set | None = None) -> dict:
    """단계별 서비스 XML(stage3-*) → finding 인입. 닫힘 판정은 실제 스캔한 호스트로 한정.

    scope_keys(타겟 재스캔)면 그 키만 닫힘 후보 — 다른 포트 거짓 닫힘 방지(기존 ingest 계승).
    """
    out = Path(out_dir)
    state = _read_state(out)
    open_map = state.get("open_map") or {}
    live = state.get("live") or []
    scanned = set(open_map.keys()) | {h for h in live if isinstance(h, str) and _is_ip(h)}

    by_key: dict[tuple, dict] = {}
    for x in sorted(out.glob("stage3-*.xml")):
        try:
            fnd = parse_xml(x.read_bytes())
        except Exception:
            continue
        for f in fnd:
            by_key[(f["host_ip"], f["port"], f["proto"])] = f   # confirm/base 중복 제거(존재값 우선)
    findings = list(by_key.values())

    enriched = taxonomy.enrich_all(db, findings)
    counts = ingest(db, scan.id, enriched, scanned, scope_keys=scope_keys)
    from ..api.assets import match_assets
    match_assets(db)
    scan.host_count = len({f["host_ip"] for f in findings})
    scan.port_count = len(enriched)
    return counts
