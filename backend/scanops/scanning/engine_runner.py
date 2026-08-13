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
import xml.etree.ElementTree as ET
from pathlib import Path

from ..config import get_settings
from . import nmap_runner, process_control, scan_options, taxonomy
from .ingest import ingest
from .nmap_parse import parse_xml

_settings = get_settings()
logger = logging.getLogger(__name__)

_TIMING = {"t0": "-T0", "t1": "-T1", "t2": "-T2", "t3": "-T3", "fast": "-T4", "t5": "-T5"}
ENGINE_REQUIRED_FILES = (
    "__init__.py",
    "__main__.py",
    "cli.py",
    "events.py",
    "nmaprun.py",
    "pipeline.py",
    "process_control.py",
    "spec.py",
    "state.py",
)
_ENGINE_UNAVAILABLE_MESSAGE = (
    "스캔 엔진 구성요소가 누락되었거나 손상되었습니다. 배포 패키지를 다시 설치하세요."
)


def ensure_available() -> Path:
    """Return a runnable vendored engine path or fail before creating a scan."""
    package = Path(_settings.engine_dir) / "scanops_engine"
    try:
        for name in ENGINE_REQUIRED_FILES:
            source = package / name
            if not source.is_file():
                raise FileNotFoundError(source)
            # ``is_file`` does not prove that the service account can read the package.
            with source.open("rb") as handle:
                handle.read(1)
    except OSError:
        logger.exception("vendored scan engine is missing or unreadable: %s", package)
        raise RuntimeError(_ENGINE_UNAVAILABLE_MESSAGE) from None

    env = dict(os.environ)
    env["PYTHONPATH"] = str(_settings.engine_dir) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        probe = subprocess.run(
            [sys.executable, "-m", "scanops_engine", "--help"],
            cwd=str(_settings.engine_dir),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        logger.exception("vendored scan engine entrypoint probe failed: %s", package)
        raise RuntimeError(_ENGINE_UNAVAILABLE_MESSAGE) from None
    if probe.returncode != 0:
        logger.error(
            "vendored scan engine entrypoint is not runnable: %s (probe rc=%s)",
            package,
            probe.returncode,
        )
        raise RuntimeError(_ENGINE_UNAVAILABLE_MESSAGE)
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


# ── 산출물 완결성 → 닫힘 권한 ────────────────────────────────────────────────
#
# 엔진 파서(collect_results)는 XML 이 없거나 ParseError 면 그 파일을 빈 목록으로 취급하고
# 넘어간다. 그 상태로 닫힘을 진행하면 '못 본 포트'가 '닫힌 포트'가 되고, 닫힘은 상태까지
# '정상처리'로 바꾸므로 되돌리기 가장 어려운 미탐이 된다.
#
# 그래서 **있는 파일만 훑지 않고 "이번 실행이 만들기로 한 집합"과 대조**한다. rc=0 이고
# stages_done 에 job 이 있어도 파일이 아예 없을 수 있는데, glob 만으로는 그게 안 보인다.
#
# 역할을 둘로 가른다 — 섞으면 한쪽 오류가 반대쪽 오류를 만든다.
#   authority  : 무엇이 열려 있는지를 정하는 산출물(discovery·sweep). 부재/잘림 → 닫힘 권한 박탈
#   enrichment : 서비스 상세(stage3). 부재/잘림 → 증거만 불완전, 닫힘 권한은 유지
# 단 재스캔(rescan_units·targets_ports)에는 sweep 이 없고 stage3 가 유일한 근거이므로
# 그때는 stage3 가 authority 다.


def _xml_run_finished(path: Path) -> bool:
    """단독 스캐너 xml_run_completed 와 같은 계약(호스트 수 대조는 엔진이 배치별로 쪼개
    실행하므로 제외). 파싱되고 <runstats><finished exit="success"> 가 정확히 하나여야 한다."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return False
    finished = root.findall("./runstats/finished")
    return len(finished) == 1 and finished[0].get("exit") == "success"


def _stage3_path(out: Path, ip: str, tag: str, confirm: bool = False) -> Path:
    """pipeline._probe_protocol 의 이름 규칙."""
    return out / f"stage3-{str(ip).replace('.', '_')}-{tag}{'-confirm' if confirm else ''}.xml"


def _probe_found_nothing(path: Path) -> bool:
    """1차 probe 가 빈손이었는가 — 엔진이 확인 패스를 도는 조건(pipeline._probe_host)."""
    try:
        return not parse_xml(path.read_bytes())
    except Exception:                       # 못 읽으면 이미 broken 으로 잡힌다
        return False


def _stage3_expected(out: Path, ip: str, tag: str, confirm_enabled: bool) -> list[Path]:
    """base + (필요하면) 확인 패스.

    확인 패스는 **1차가 빈손일 때만** 돈다(`sp.confirm and not found`). 그래서 base 를 실제로
    읽어 같은 조건을 재현한다 — 무조건 기대하면 1차에서 찾은 정상 실행이 전부 부재 판정된다.
    """
    base = _stage3_path(out, ip, tag)
    expected = [base]
    if (confirm_enabled and base.exists() and _xml_run_finished(base)
            and _probe_found_nothing(base)):
        expected.append(_stage3_path(out, ip, tag, confirm=True))
    return expected


def _rescan_authority_xml(out: Path, spec: dict) -> list[Path]:
    """재스캔의 기대 산출물 — pipeline._rescan_units/_service 의 이름 규칙을 따른다.

    재스캔에는 sweep 이 없어 stage3 가 유일한 근거다. 그래서 확인 패스 산출물도 authority 다
    — 운영 재스캔 spec 은 build_job_spec 이 service.confirm=True 로 만든다.
    """
    confirm = bool(((spec.get("stages") or {}).get("service") or {}).get("confirm", False))
    expected: list[Path] = []
    for unit in spec.get("rescan_units") or []:
        try:
            ip = str(unit["ip"])
            port, proto = int(unit["port"]), str(unit.get("proto") or "tcp")
        except (KeyError, TypeError, ValueError):
            continue
        expected += _stage3_expected(out, ip, f"{proto}{port}", confirm)   # tag=f"{proto}{port}"
    for ip in (spec.get("targets_ports") or {}):
        expected += _stage3_expected(out, ip, "tcp", confirm)
    return expected


def expected_enrichment_xml(out_dir, spec: dict) -> list[Path]:
    """전체 스캔에서 서비스 probe 가 만들기로 한 stage3 집합.

    있는 파일만 훑으면 'probe 는 돌았는데 XML 을 못 만든' 경우가 증거 손실인 채로 정상 완료로
    숨는다. open_map(=sweep 이 연 포트)과 service 설정에서 기대 집합을 세운다.
    """
    out = Path(out_dir)
    svc = ((spec.get("stages") or {}).get("service") or {})
    if not svc.get("enabled", True):
        return []
    confirm = bool(svc.get("confirm", False))
    open_map = _read_state(out).get("open_map") or {}
    expected: list[Path] = []
    for ip, protos in sorted((open_map or {}).items()):
        if not isinstance(protos, dict):
            continue
        for proto in ("tcp", "udp"):
            if protos.get(proto):
                expected += _stage3_expected(out, ip, proto, confirm)
    return expected


def expected_authority_xml(out_dir, spec: dict, force_scanned_hosts: bool = False) -> list[Path]:
    """이번 실행이 만들기로 한 authority 산출물."""
    out = Path(out_dir)
    if force_scanned_hosts:
        return _rescan_authority_xml(out, spec)
    # discovery 를 먼저 세운다. 이게 깨졌으면 live 자체가 오염이라 아래 계산은 의미가 없다 —
    # 그래도 목록에 들어가 있으므로 완결성 검사에서 걸려 권한이 박탈된다.
    # 단 -Pn(mode="pn")·비활성 이면 엔진이 nmap 을 돌리지 않고 타깃을 그대로 live 로 쓴다
    # (pipeline._discovery). 만들지도 않는 파일을 기대하면 정상 실행이 전부 partial 이 된다.
    disc = (spec.get("stages") or {}).get("discovery") or {}
    runs_discovery = disc.get("enabled", True) and disc.get("mode", "sn") != "pn"
    expected = [out / "stage0-discovery.xml"] if runs_discovery else []
    state = _read_state(out)
    live = [h for h in (state.get("live") or []) if isinstance(h, str)]
    if not live:
        # 생존 0 이면 엔진이 sweep 을 아예 돌리지 않는다(pipeline.run).
        return expected
    batch = max(1, int(spec.get("batch_size") or 256))
    count = -(-len(live) // batch)          # ceil — pipeline._batches 와 같은 분할
    stages = spec.get("stages") or {}
    for proto in ("tcp", "udp"):
        if (stages.get(proto) or {}).get("enabled", True):
            expected += [out / f"stage-{proto}-b{i}.xml" for i in range(count)]
    return expected


def artifact_report(out_dir, spec: dict, force_scanned_hosts: bool = False) -> dict:
    """기대 산출물 대비 실제 산출물. authority 가 하나라도 어긋나면 닫으면 안 된다."""
    out = Path(out_dir)
    expected = expected_authority_xml(out, spec, force_scanned_hosts)
    missing = [p.name for p in expected if not p.exists()]
    broken = [p.name for p in expected if p.exists() and not _xml_run_finished(p)]
    enrichment_missing: list[str] = []
    enrichment_broken: list[str] = []
    if not force_scanned_hosts:
        # 전체 스캔에서 stage3 는 enrichment 다. 어긋나도 sweep 의 안전한 권한을 뺏지 않지만,
        # 증거가 빠졌다는 사실은 남겨야 한다 — 안 그러면 손실이 정상 완료로 숨는다.
        expected_enrich = expected_enrichment_xml(out, spec)
        enrichment_missing = [p.name for p in expected_enrich if not p.exists()]
        seen = {p.name for p in expected_enrich}
        enrichment_broken = sorted(
            {p.name for p in expected_enrich if p.exists() and not _xml_run_finished(p)}
            # 기대 집합 밖의 산출물(확인 패스 등)도 깨졌으면 증거 저하로 센다.
            | {p.name for p in out.glob("stage3-*.xml")
               if p.name not in seen and not _xml_run_finished(p)})
    return {"authority_missing": missing, "authority_broken": broken,
            "enrichment_missing": enrichment_missing,
            "enrichment_broken": enrichment_broken}


# nmap 이 NSE/소켓을 매끄럽게 돌리지 못했다고 알리는 표식. XML 에는 남지 않고 로그로만 나온다.
# 단독 스캐너(scanops_scanner.NMAP_NSE_PROBLEM_MARKERS)와 같은 목록이어야 두 경로가 같이 움직인다.
UNCLEAN_MARKERS = ("NSOCK ERROR", "Trying to delete NSI", "QUITTING!")
_UNCLEAN_KEEP = 5
_UNCLEAN_TAIL_BYTES = 256 * 1024


def log_problems(log_path: Path) -> list[str]:
    """실행 로그에서 정상 종료를 부정하는 줄을 찾는다.

    rc=0 이고 XML 이 exit="success" 여도 NSE/소켓이 정리되지 못한 채 끝날 수 있다.
    그 사실은 로그에만 있으므로 여기서 보지 않으면 볼 곳이 없다 — 그대로 두면 '못 본
    포트'가 '닫힌 포트'로 기록된다.
    """
    try:
        data = Path(log_path).read_bytes()[-_UNCLEAN_TAIL_BYTES:]
    except OSError:
        return []
    # nmap 이 Windows API 에서 받아 뱉는 오류 문구는 ANSI 코드페이지라 UTF-8 로 못 읽는다.
    # 표식 자체는 ASCII 이므로 replace 로 읽어도 탐지에는 지장이 없다.
    text = data.decode("utf-8", "replace")
    found: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and any(marker in stripped for marker in UNCLEAN_MARKERS):
            found.append(stripped[:200])
            if len(found) >= _UNCLEAN_KEEP:
                break
    return found


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
    # ``scanned`` is the authoritative set that reached the staged scan, even when no
    # port was open.  Counting finding rows makes a successful -Pn/cached discovery of
    # a zero-open host disagree with the engine's final ``counts.live`` value.
    scan.host_count = len(scanned)
    scan.port_count = len(enriched)
    if commit:
        db.commit()
    else:
        db.flush()
    return counts
