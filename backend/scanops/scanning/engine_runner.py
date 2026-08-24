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
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from ..config import get_settings
from . import nmap_parse, nmap_runner, process_control, scan_options, scan_summary, taxonomy
from .ingest import ingest
from .nmap_parse import observed_at, parse_xml

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
                   discovery: str = "sn", rescan_units: list | None = None,
                   exclude_ports: str = "", watchdog_seconds: int | None = None) -> dict:
    """ScanOps 옵션 키를 엔진 단계 설정으로 매핑. 스캔 기법/타이밍/버전강도/UDP/NSE 를 단계로 분배.

    one-liner 옵션(노핑·기법)은 엔진이 단계별로 알아서 처리하므로 그대로 옮기지 않는다.
    """
    opt = set(options or [])
    if "connect" in opt and "syn" in opt:
        raise ValueError("단계 스캔에서는 TCP SYN과 Connect 방식을 동시에 선택할 수 없습니다.")
    if "connect" in opt and "udp" in opt:
        raise ValueError("TCP Connect 단계 스캔은 UDP 스캔과 함께 실행할 수 없습니다.")
    timing = next((_TIMING[k] for k in ("t0", "t1", "t2", "t3", "fast", "t5") if k in opt), "-T4")
    # 재전송 상한은 프로토콜마다 별개다 — UDP 는 ICMP 율제한 때문에 응답이 늦고 드물어,
    # TCP 와 같은 값을 쓰면 '닫혔다'가 아니라 '못 봤다'가 늘어난다.
    max_retries = scan_options.MAX_RETRIES_DEFAULT
    udp_max_retries = scan_options.UDP_MAX_RETRIES_DEFAULT
    # The engine has protocol-specific stages, so its ``-p`` value does not need Nmap's
    # T:/U: selector used by the legacy combined workflow.
    tcp_spec = nmap_runner.auto_tcp_port_spec(ports)
    udp_spec = nmap_runner.auto_udp_port_spec(ports)
    tcp_ports = tcp_spec.removeprefix("T:")
    udp_ports = udp_spec.removeprefix("U:")
    selected_nse = list(scan_options.NSE_DEFAULT_KEYS if nse is None else nse)
    service = {
        "enabled": True,
        "version_all": not options or ("version_all" in opt and "version_light" not in opt),
        "version_light": "version_light" in opt,
        "timing": timing,
        "max_retries": max_retries,
        "udp_max_retries": udp_max_retries,
        "nse": scan_options.filter_nse_proto(selected_nse, "tcp"),
        "udp_nse": scan_options.filter_nse_proto(selected_nse, "udp"),
        "workers": scan_options.SERVICE_WORKERS_DEFAULT,
    }
    spec: dict = {
        "job_id": f"scan_{scan_id}",
        "targets": list(targets),
        "exclude": list(exclude or []),
        # 포트 제외는 엔진이 모든 단계 인자에 싣는다(pipeline._exclude_args).
        "exclude_ports": (exclude_ports or "").strip(),
        "out_dir": str(out_dir),
        "batch_size": int(batch_size),
        "sudo": "auto",
        # nmap 프로세스당 상한(초). 0 = 끔. --host-timeout 과 달리 그때까지 쓰인 XML 을
        # 남기고 실행을 비정상 종료로 표시하므로, 관측을 버리면서 성공으로 끝내지 않는다.
        "watchdog_seconds": int(scan_options.WATCHDOG_SECONDS_DEFAULT
                                if watchdog_seconds is None else watchdog_seconds),
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
                    "timing": timing, "max_retries": udp_max_retries},
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


def _unit_scope(units) -> tuple[str, str]:
    """재스캔 단위 목록 -> (TCP 포트 표기, UDP 포트 표기)."""
    ports: dict[str, list[int]] = {"tcp": [], "udp": []}
    for unit in units or []:
        try:
            proto = str(unit.get("proto") or "tcp").lower()
            ports.setdefault(proto, []).append(int(unit["port"]))
        except (KeyError, TypeError, ValueError):
            continue
    return (",".join(str(p) for p in sorted(set(ports["tcp"]))),
            ",".join(str(p) for p in sorted(set(ports["udp"]))))


def describe(spec: dict) -> str:
    """명령 표기용 사람이 읽는 요약 + 기계 판독용 범위 꼬리표.

    꼬리표(`범위: T:… U:…`)가 없으면 이력 요약이 이 문장을 nmap argv 로 오인해 '기본 1000개
    TCP' 라고 단언한다. 전 포트 TCP+UDP 스캔이 상위 1000개 TCP 스캔으로 보이는 셈이다.
    무엇을 스캔했는지는 spec 이 알고 있으므로, 아는 쪽이 적어 준다.
    """
    if spec.get("rescan_units"):
        tcp, udp = _unit_scope(spec["rescan_units"])
        head = f"타겟 재스캔(엔진) · {len(spec['rescan_units'])}건 개별(IP:포트별) · Stage3"
        return f"{head}  ·  {scan_summary.scope_note(tcp, udp)}"
    if spec.get("targets_ports"):
        n = sum(len(v) for v in spec["targets_ports"].values())
        tcp = ",".join(str(p) for p in sorted({
            int(p) for ports in spec["targets_ports"].values() for p in ports
        }))
        head = f"타겟 재스캔(엔진) · {len(spec['targets_ports'])}호스트 / {n}포트 · Stage3"
        return f"{head}  ·  {scan_summary.scope_note(tcp, '')}"
    st = spec["stages"]
    bits = [f"발견 {st['discovery']['mode']}"]
    if st["tcp"]["enabled"]:
        bits.append(f"TCP {st['tcp']['ports']}")
    if st["udp"]["enabled"]:
        bits.append(f"UDP {st['udp']['ports']}")
    bits.append("서비스 --version-all" if st["service"]["version_all"] else "서비스 -sV")
    note = scan_summary.scope_note(
        st["tcp"]["ports"] if st["tcp"]["enabled"] else "",
        st["udp"]["ports"] if st["udp"]["enabled"] else "",
    )
    return "단계스캔(엔진) · " + " · ".join(bits) + f"  ·  {note}"


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
    return [path for group in _enrichment_units(out_dir, spec) for path in group[0]]


# 엔진이 실패한 UDP 묶음을 포트별로 쪼갤 때의 상한(pipeline._MAX_SPLIT_UNITS 와 같은 값).
# 넘으면 엔진이 쪼개지 않으므로 대체 산출물도 존재하지 않는다.
_MAX_SPLIT_UNITS = 32


def _enrichment_units(out_dir, spec: dict,
                      superseded: set[str] | None = None,
                      ) -> list[tuple[list[Path], list[Path]]]:
    """(ip, proto) 마다 (묶음 산출물, 대체 가능한 분할 산출물).

    정상 경로는 프로토콜당 한 프로세스라 묶음 파일 하나가 나온다. 그 묶음이 죽으면 엔진이
    포트별로 쪼개 다시 돌리므로(pipeline._split_units), **쪼갠 것이 전부 완결되면 얻을 증거는
    같다.** 묶음 이름만 기대하면 완전 복구를 '증거 손실'로 오탐한다 — 최초 묶음이 실패했다는
    사실은 service_retry/service_split 이벤트가 이미 남긴다.

    대체 집합은 엔진이 실제로 쪼갤 수 있는 조건(UDP · 2개 이상 · 상한 이내)일 때만 만든다.
    """
    out = Path(out_dir)
    svc = ((spec.get("stages") or {}).get("service") or {})
    if not svc.get("enabled", True):
        return []
    confirm = bool(svc.get("confirm", False))
    state = _read_state(out)
    open_map = state.get("open_map") or {}
    units: list[tuple[list[Path], list[Path]]] = []
    # 실패해서 대체 실행에 자리를 넘긴 묶음 산출물. 호출부가 '기대 밖' 으로 다시 세지
    # 않도록 이름만 넘긴다 - 실제 증거 손실은 대체 집합의 기대치가 판단한다.
    superseded = superseded if superseded is not None else set()
    covered: set[tuple[str, str, int]] = set()
    # 새 엔진은 공통 포트가 많은 배치를 한 Nmap으로 식별한다. 생산자가 coverage에 정확한
    # 산출물·호스트를 적으므로, 성공한 배치 산출물 하나를 호스트별 파일 N개로 지어내지 않는다.
    for entry in state.get("coverage") or []:
        if not isinstance(entry, dict) or entry.get("role") != "enrichment":
            continue
        artifact, proto = entry.get("artifact"), entry.get("proto")
        if (not isinstance(artifact, str) or proto not in {"tcp", "udp"}
                or not artifact.startswith(f"stage3-{proto}-b")):
            continue
        if not entry.get("finished"):
            # 실패한 묶음이다. 이 자리에서 빼면 그 파일이 어느 기대 집합에도 안 들어가고,
            # 기대 밖 산출물을 훑는 마지막 단계가 그것을 손상으로 다시 센다 - 호스트별
            # 대체 실행이 **전부** 성공해 증거를 되찾았어도 nse_degraded 와 호스트 없는
            # artifact_broken 이 남는다. 대체된 산출물이라는 사실만 기록하고 넘어간다.
            superseded.add(artifact)
            continue
        units.append(([out / artifact], []))
        hosts = entry.get("hosts")
        port_text = entry.get("ports")
        try:
            ports = {int(port) for port in str(port_text).split(":")[-1].split(",")}
        except ValueError:
            ports = set()
        if isinstance(hosts, list):
            covered.update((host, proto, port) for host in hosts if isinstance(host, str)
                           for port in ports)
    for ip, protos in sorted((open_map or {}).items()):
        if not isinstance(protos, dict):
            continue
        for proto in ("tcp", "udp"):
            raw = protos.get(proto)
            if not raw:
                continue
            ports = sorted({int(p) for p in raw if (ip, proto, int(p)) not in covered})
            if not ports:
                continue
            grouped = _stage3_expected(out, ip, proto, confirm)
            split: list[Path] = []
            if proto == "udp" and 1 < len(ports) <= _MAX_SPLIT_UNITS:
                for port in ports:
                    split += _stage3_expected(out, ip, f"{proto}{port}", confirm)
            units.append((grouped, split))
    return units


def _complete(paths: list[Path]) -> bool:
    return bool(paths) and all(p.exists() and _xml_run_finished(p) for p in paths)


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


def absence_times(out_dir, spec: dict, force_scanned_hosts: bool = False) -> dict:
    """``(host, proto) -> 그 호스트의 부재를 확인한 시각``.

    '이 포트가 없다' 는 **그 호스트를 실제로 훑은 산출물**만 할 수 있는 말이다. 실행 전체의
    max(finished) 하나로 뭉치면 00:00 에 끝난 배치의 부재가 02:00 권한을 얻어, 그 사이
    01:00 에 다른 스캔이 새로 관측한 열린 포트를 닫는다.

    커버 범위를 산출물의 host 목록에서 읽을 수는 없다 - sweep 은 ``--open`` 으로 돌기
    때문에 열린 포트가 없는 호스트는 XML 에 아예 나타나지 않는다(그런데 닫힘 판정이
    필요한 것이 정확히 그 호스트들이다). 그래서 엔진이 배치를 나눈 규칙(pipeline._batches:
    live 를 순서대로 batch_size 씩)을 그대로 되짚어 배치 i 가 맡은 호스트를 세운다.
    """
    out = Path(out_dir)
    times: dict[tuple[str, str], object] = {}
    if force_scanned_hosts:
        confirm = bool(((spec.get("stages") or {}).get("service") or {}).get("confirm", False))

        def completed_for(ip: str, paths: list[Path]) -> list[Path]:
            """이 authority 단위가 실제로 끝까지 관측한 산출물만 돌려준다.

            선택 재스캔은 같은 host/proto라도 포트마다 별도 XML을 만든다. 따라서 timeout을
            host 하나의 verdict로 합치면 뒤 포트가 앞 포트의 판정을 덮어쓴다. base/confirm을
            포함한 바로 그 단위의 산출물만 판정해야 한다.
            """
            if not paths or any(not path.exists() or not _xml_run_finished(path) for path in paths):
                return []
            try:
                if any(ip in nmap_parse.timed_out_hosts(path.read_bytes()) for path in paths):
                    return []
            except (OSError, ET.ParseError):
                return []
            return paths

        for unit in spec.get("rescan_units") or []:
            try:
                ip = str(unit["ip"])
                port, proto = int(unit["port"]), str(unit.get("proto") or "tcp").lower()
            except (KeyError, TypeError, ValueError):
                continue
            # 선택 재스캔은 포트마다 별도 산출물을 만든다. 22 를 훑은 XML 은 443 의 부재를
            # 증명하지 못하므로 포트까지 키에 넣는다 - (ip, proto) 로 뭉치면 늦게 끝난
            # 포트의 시각을 다른 포트가 빌려 쓴다.
            paths = completed_for(ip, _stage3_expected(out, ip, f"{proto}{port}", confirm))
            if not paths:
                continue
            stamps = [s for s in (observed_at(path.read_bytes()) for path in paths)
                      if s is not None]
            times[(ip, port, proto)] = max(stamps) if stamps else None
        # targets_ports 는 한 XML 이 그 호스트의 여러 포트를 실제로 함께 훑으므로 산출물
        # 범위가 곧 (ip, tcp) 다. 여기서까지 포트로 쪼개면 있지도 않은 구분을 만든다.
        for ip in (spec.get("targets_ports") or {}):
            paths = completed_for(str(ip), _stage3_expected(out, str(ip), "tcp", confirm))
            if not paths:
                continue
            stamps = [s for s in (observed_at(path.read_bytes()) for path in paths)
                      if s is not None]
            times[(str(ip), "tcp")] = max(stamps) if stamps else None
        return times

    live = [h for h in (_read_state(out).get("live") or []) if isinstance(h, str)]
    stages = spec.get("stages") or {}
    batch = max(1, int(spec.get("batch_size") or 256))

    def _recorded():
        """생산자가 적어 둔 커버리지 — 산출물마다 명령줄에 올린 호스트가 그대로 남아 있다."""
        for entry in coverage_entries(out):
            if entry.get("role") != "authority":
                continue
            proto = str(entry.get("proto") or "")
            if proto not in ("tcp", "udp"):
                continue
            hosts = [h for h in (entry.get("hosts") or []) if isinstance(h, str)]
            yield proto, out / str(entry.get("artifact") or ""), hosts

    def _slices():
        """구형 out_dir 폴백 — 엔진의 배치 규칙(live 를 순서대로 batch_size 씩)을 되짚는다.

        되짚기는 규칙이 바뀌면 조용히 어긋나고 재시도처럼 부분집합을 훑은 실행을 표현하지
        못한다. 그래서 새 실행은 위의 기록을 쓰고, 이 경로는 기록이 없는 옛 실행 전용이다.
        """
        for proto in ("tcp", "udp"):
            if not (stages.get(proto) or {}).get("enabled", True):
                continue
            for index in range(-(-len(live) // batch)):
                yield (proto, out / f"stage-{proto}-b{index}.xml",
                       live[index * batch:(index + 1) * batch])

    covers = list(_recorded()) if coverage_entries(out) else (list(_slices()) if live else [])
    # 포기 판정도 프로토콜별이다. 한 집합으로 뭉치면 UDP 타임아웃이 TCP 의 시각까지 지운다.
    gave_up = {proto: timed_out_hosts(out, proto) for proto in ("tcp", "udp")}
    for proto, path, hosts in covers:
        if not path.exists():
            continue
        try:
            when = observed_at(path.read_bytes())
        except OSError:
            continue
        for host in hosts:
            if host in gave_up[proto]:
                continue
            key = (host, proto)
            current = times.get(key)
            # 시각이 없는 산출물도 '훑었다' 는 사실은 남긴다(값 None = 시각 미상).
            if key not in times or (when is not None and (current is None or when > current)):
                times[key] = when
    return times


def swept_batches(out_dir, spec: dict) -> int:
    """모든 활성 프로토콜에 대해 sweep 이 끝난 배치 수.

    엔진도 대역을 배치로 나눠 돈다(stage-tcp-b0.xml …). 청킹 스캔은 sidecar 에 cursor 가
    있지만 엔진에는 없어서, 진행 화면이 배치 진행을 아예 말하지 못했다. 파일이 곧 진행
    기록이므로 그것을 센다 - TCP 는 끝나고 UDP 가 도는 중이면 그 배치는 아직 '끝난' 것이
    아니므로 프로토콜별 완료 수의 **최솟값**을 쓴다.
    """
    out = Path(out_dir)
    stages = spec.get("stages") or {}
    counts = []
    for proto in ("tcp", "udp"):
        if not (stages.get(proto) or {}).get("enabled", True):
            continue
        counts.append(sum(
            1 for path in out.glob(f"stage-{proto}-b*.xml") if _xml_run_finished(path)
        ))
    return min(counts) if counts else 0


def gave_up_hosts(out_dir) -> list[str]:
    """``--host-timeout`` 으로 포기당해 **아직 제대로 못 훑은** 호스트.

    엔진이 배치를 끝낼 때마다 run-state 에 모아 둔다(재시도로 끝까지 훑으면 목록에서 빠진다).
    이 실행에서는 부재를 말할 자격이 없는 호스트이자, 나중에 그 호스트들만 골라 다시
    스캔할 대상 목록이다 - 안 남겨 두면 '왜 이 대역만 결과가 비지?' 를 알아낼 방법이 없다.
    """
    return [h for h in (_read_state(Path(out_dir)).get("gave_up") or []) if isinstance(h, str)]


def _retry_ip_key(value: str):
    try:
        return (0, int(ipaddress.ip_address(value)))
    except ValueError:
        return (1, value)


def gave_up_detail(out_dir) -> dict:
    """Persistent retry queue from timeout and retransmission-cap evidence."""
    state = _read_state(Path(out_dir))
    by_stage = {}
    reasons_by_stage = {}

    def merge(raw, reason):
        if not isinstance(raw, dict):
            return
        for stage, hosts in raw.items():
            if not isinstance(stage, str) or not isinstance(hosts, list):
                continue
            clean = sorted({host for host in hosts if isinstance(host, str)}, key=_retry_ip_key)
            if not clean:
                continue
            by_stage[stage] = sorted(set(by_stage.get(stage, [])) | set(clean), key=_retry_ip_key)
            stage_reasons = reasons_by_stage.setdefault(stage, {})
            for host in clean:
                host_reasons = stage_reasons.setdefault(host, [])
                if reason not in host_reasons:
                    host_reasons.append(reason)

    merge(state.get("gave_up_by_stage") or {}, "host_timeout")
    merge(state.get("retransmission_cap_by_stage") or {}, "retransmission_cap")
    targets = sorted({host for hosts in by_stage.values() for host in hosts}, key=_retry_ip_key)
    if not targets:
        targets = sorted(set(gave_up_hosts(out_dir)), key=_retry_ip_key)
    return {"required": bool(targets), "count": len(targets),
            "targets": targets, "by_stage": by_stage,
            "reasons_by_stage": reasons_by_stage}


def coverage_entries(out_dir) -> list[dict]:
    """엔진이 nmap 을 돌리며 적어 둔 커버리지 기록(run-state 의 ``coverage``).

    각 항목은 nmap 프로세스 **하나**를 뜻한다 — ``{artifact, proto, role, hosts, ports,
    finished}``. ``hosts`` 는 그 실행의 **명령줄에 실제로 올린** 목록이라, 되짚기(배치
    슬라이스·glob)와 달리 규칙이 바뀌어도 어긋나지 않는다.

    구형 out_dir(이 기록이 생기기 전에 돈 실행)은 빈 목록이며, 호출자는 되짚기 폴백을 쓴다.
    """
    return [e for e in (_read_state(Path(out_dir)).get("coverage") or []) if isinstance(e, dict)]


def _authority_entries(out_dir, proto: str | None, force_scanned_hosts: bool) -> list[dict]:
    """부재를 말할 자격이 있는 산출물만. **역할**이 판단 기준이고 파일 이름이 아니다.

    전체 스캔에서 개폐를 확정하는 것은 sweep 이고 stage3 는 enrichment 다. 포트 재스캔에서는
    stage3 가 유일한 관측이라 그것이 authority 다. 이 구분을 안 하면 완결된 TCP sweep 의
    권한을 stage3 타임아웃 하나가 빼앗는다(그리고 그 반대 방향도 똑같이 틀린다).
    """
    entries = [e for e in coverage_entries(out_dir) if e.get("role") == "authority"]
    if not force_scanned_hosts and proto:
        entries = [e for e in entries if e.get("proto") == proto]
    return entries


def _legacy_timed_out_hosts(out_dir) -> set[str]:
    """커버리지 기록이 없는 구형 out_dir 용 되짚기.

    역할·프로토콜을 구분하지 못하므로 **보수적으로 합집합**이다. 새 실행은 여기 오지 않는다.
    """
    out = Path(out_dir)
    hosts: set[str] = set()
    for pattern in ("stage-tcp-b*.xml", "stage-udp-b*.xml", "stage3-*.xml", "stage0-discovery.xml"):
        for path in sorted(out.glob(pattern)):
            try:
                hosts |= nmap_parse.timed_out_hosts(path.read_bytes())
            except (OSError, ET.ParseError):
                continue
    return hosts


def timed_out_hosts(out_dir, proto: str | None = None,
                    force_scanned_hosts: bool = False) -> set[str]:
    """``--host-timeout`` 으로 포기당해 **부재를 말할 자격이 없는** 호스트.

    판정은 산출물 하나 단위다. 같은 호스트를 여러 authority 산출물이 덮으면 **마지막 것이
    이긴다** — 한 번 포기됐다는 이유로 영구히 자격을 잃으면, 재시도가 성공해도 그 관측을
    쓰지 못한다. 읽을 수 없는 산출물은 그 실행이 아무것도 관측하지 못한 것으로 본다(fail-closed).
    """
    out = Path(out_dir)
    if not coverage_entries(out):
        # 기록 자체가 없는 구형 out_dir 일 때만 되짚는다. '해당 역할의 항목이 없다' 를 폴백
        # 조건으로 쓰면, 기록은 있는데 그 역할이 없는 정상 실행이 조용히 옛 합집합으로
        # 되돌아간다 - 고치려던 바로 그 오류다.
        return _legacy_timed_out_hosts(out)
    verdict: dict[str, bool] = {}
    entries = _authority_entries(out, proto, force_scanned_hosts)
    for entry in entries:
        path = out / str(entry.get("artifact") or "")
        covered = [h for h in (entry.get("hosts") or []) if isinstance(h, str)]
        try:
            gave_up = nmap_parse.timed_out_hosts(path.read_bytes())
        except (OSError, ET.ParseError):
            gave_up = set(covered)
        for host in covered:
            verdict[host] = host in gave_up
    return {host for host, gone in verdict.items() if gone}


def swept_total(out_dir, spec: dict) -> int:
    """sweep 이 실제로 만들 배치 수 - **swept_batches 와 같은 모집단**에서 센다.

    실행 전에 세어 둔 배치 수(ScanRun.batch_total)는 discovery **이전**의 전체 대상 수로
    나눈 값이다. 반면 엔진이 실제로 도는 배치는 discovery 를 통과한 live 를 나눈 것이라,
    둘을 분자·분모로 같이 쓰면 존재하지 않는 배치를 진행 중이라고 말하게 된다
    (/24 256대 중 1대만 live 면 실제 배치는 b0 하나인데 분모는 4가 된다).

    live 를 아직 모르면 0 - 그때는 호출자가 실행 전 추정치를 그대로 쓴다.
    """
    live = [h for h in (_read_state(Path(out_dir)).get("live") or []) if isinstance(h, str)]
    size = int(spec.get("batch_size") or 0)
    if not live or size <= 0:
        return 0
    return -(-len(live) // size)


def observed_hosts(out_dir, spec: dict, force_scanned_hosts: bool = False,
                   proto: str | None = None) -> set[str]:
    """이 실행이 **실제로 포트를 관측한** 호스트.

    산출물이 모두 완결됐다는 것과 '이 호스트의 포트를 봤다'는 것은 다른 사실이다.
    sn discovery 에서 호스트가 응답하지 않으면 live 가 비고, sweep 은 아예 실행되지 않는다
    (pipeline.run 이 live 를 sweep 입력으로 쓴다). 그때 기대 산출물은 discovery 하나뿐이라
    완결성 검사는 **공허하게 통과**한다 - 그 상태로 scope_keys 를 그대로 닫으면 그 호스트의
    포트에 패킷을 한 번도 보내지 않고 전부 '닫힘 + 정상처리'가 된다.

    nmap 문서도 host discovery 가 엄격한 방화벽 뒤의 호스트를 놓칠 수 있고, 기본 포트 스캔은
    up 으로 판정된 호스트에만 수행된다고 명시한다. 그러므로 discovery 미응답은 '포트가 닫혔다'가
    아니라 '아무것도 관측하지 못했다'이다.

    -Pn 은 pipeline._discovery 가 targets 를 그대로 live 로 넣으므로 같은 규칙으로 덮인다.
    """
    out = Path(out_dir)
    if force_scanned_hosts:
        # 재스캔 authority는 포트 단위일 수 있다. 한 포트가 timeout이어도 같은 호스트의 다른
        # 포트는 정상 완료할 수 있으므로, 실제 권한 단위가 하나라도 남은 호스트만 돌려준다.
        return {str(key[0]) for key in absence_times(out, spec, True)}
    # live 는 discovery 가 살아 있다고 본 목록일 뿐이다. 그중 sweep 이 타임아웃으로 포기한
    # 호스트는 포트를 끝까지 보지 못했으므로 부재를 말할 자격이 없다.
    live = {h for h in (_read_state(out).get("live") or []) if isinstance(h, str)}
    return live - timed_out_hosts(out, proto)


def observed_scope(scope_keys: set | None, out_dir, spec: dict,
                   force_scanned_hosts: bool = False) -> set | None:
    """닫힘 후보 중 이 실행이 실제로 관측한 호스트의 것만 남긴다.

    ``None`` 은 '후보 없음'이 아니라 **닫힘 후보 목록이 없는 구형 spec** 이라는 뜻이므로
    빈 집합으로 바꾸지 않고 그대로 돌려준다. 운영 경로에서는 워커가 그 전에 stages 의
    포트/프로토콜 경계로 후보를 세워 명시적 집합으로 만들어 넘기므로 여기 None 이 오지
    않는다 - 이 분기는 그 순서가 깨졌을 때 실행 결과를 통째로 잃지 않기 위한 방어다.
    None 과 set() 을 같은 것으로 다루면 안 된다.
    """
    if scope_keys is None:
        return None
    if force_scanned_hosts:
        authority = absence_times(out_dir, spec, True)
        kept = set()
        for key in scope_keys:
            parts = str(key).split("|")
            if len(parts) < 3:
                continue
            host, proto = parts[0], parts[2]
            try:
                exact = (host, int(parts[1]), proto)
            except ValueError:
                continue
            if exact in authority or (host, proto) in authority:
                kept.add(key)
        return kept
    # 전체 스캔에서는 프로토콜마다 authority 산출물이 다르다. 한 집합으로 뭉치면 UDP sweep
    # 타임아웃 하나가 완결된 TCP sweep 의 권한까지 빼앗는다 - 그러면 사라진 TCP 포트가
    # 영원히 열린 채로 남는다(닫지 못하는 쪽의 오류).
    by_proto = {proto: observed_hosts(out_dir, spec, False, proto)
                for proto in ("tcp", "udp")}
    kept = set()
    for key in scope_keys:
        parts = str(key).split("|")
        host = parts[0]
        proto = parts[2] if len(parts) > 2 else "tcp"
        if host in by_proto.get(proto, by_proto["tcp"]):
            kept.add(key)
    return kept


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
        superseded: set[str] = set()
        units = _enrichment_units(out, spec, superseded)
        seen: set[str] = superseded
        for grouped, split in units:
            seen |= {p.name for p in grouped} | {p.name for p in split}
            # 묶음이 온전하면 그것으로 끝. 아니면 쪼갠 집합이 **전부** 완결됐는지 본다 —
            # 그때 얻은 증거는 묶음과 같으므로 저하가 아니다.
            if _complete(grouped) or _complete(split):
                continue
            enrichment_missing += [p.name for p in grouped if not p.exists()]
            enrichment_broken += [p.name for p in grouped
                                  if p.exists() and not _xml_run_finished(p)]
            # 쪼갠 것 중 일부만 살아났으면 그 부분 손실도 남긴다.
            enrichment_broken += [p.name for p in split
                                  if p.exists() and not _xml_run_finished(p)]
        # 기대 집합 밖의 산출물(확인 패스 등)도 깨졌으면 증거 저하로 센다.
        enrichment_broken = sorted(set(enrichment_broken) | {
            p.name for p in out.glob("stage3-*.xml")
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


def canonical_stage(stage: str, proto: str = "") -> str:
    """One stage vocabulary for events, durable issues, retries, and the UI."""
    if stage in {"service:tcp", "tcp_service"} or stage == "service" and proto == "tcp":
        return "tcp_service"
    if stage in {"service:udp", "udp_service"} or stage == "service" and proto == "udp":
        return "udp_service"
    return stage if stage in {"discovery", "tcp", "udp"} else stage or ""

def parse_events(out_dir) -> dict:
    """events.ndjson 을 단계 요약으로 접는다(라이브 진행·이력 공용). 파일 없으면 빈 결과."""
    path = Path(out_dir) / "events.ndjson"
    stages: dict[str, dict] = {}
    order: list[str] = []
    executions: dict[str, dict] = {}
    execution_order: list[str] = []
    recoveries: list[dict] = []
    quality_issues: list[dict] = []
    # events.ndjson 은 append-only 라 재개하면 이전 시도의 이벤트가 그대로 남는다. 어느
    # 시도에서 난 오류인지 알아야 '재개해서 성공한 단계' 와 '이번에도 실패한 단계' 를
    # 가를 수 있다. job_start 마다 회차가 올라간다.
    attempt = 0
    superseded: set[tuple] = set()
    current: dict = {}
    overall = {"status": "running", "percent": None, "seconds": None, "counts": {}}
    if not path.exists():
        return {"stages": [], "overall": overall, "current": current, "executions": [],
                "recoveries": [], "quality_issues": []}

    def slot(name):
        if name and name not in stages:
            stages[name] = {
                "stage": name, "status": "pending", "percent": 0,
                "counts": {}, "issues": [],
            }
            order.append(name)
        return stages.get(name, {})

    def mapped_stage(name, event):
        proto = event.get("proto")
        mapped = canonical_stage(name, proto if proto in {"tcp", "udp"} else "")
        if mapped != "service":
            return mapped
        if current.get("stage") in {"tcp_service", "udp_service"}:
            return current["stage"]
        return name

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
            e in {"stage_start", "stage_progress", "stage_activity", "stage_done", "error",
                  "hosts_gave_up", "retransmission_cap_hit", "command_start", "command_done"}
            and (not isinstance(st, str) or not st)
        ):
            continue
        if e == "stage_plan":
            plan = ev.get("stages")
            if isinstance(plan, list):
                for name in plan:
                    if isinstance(name, str) and name:
                        slot(name)
        elif e == "stage_start":
            # 재개해서 같은 단계를 다시 도는 경우, 이전 시도의 실패는 이번 시도가 대신한다.
            # 안 걷어내면 stage_done 이 그 error 를 그대로 보존하고 옛 command_error 가
            # 미해결 품질 이슈로 남아, 스캔은 done 인데 타임라인·품질은 실패로 보고한다.
            #
            # **원시 이름만 보면 안 된다.** 실패 이벤트는 proto 에 따라 정규화되므로
            # (`service` + proto=tcp -> `tcp_service`), 재스캔 생산자가 내는
            # `stage_start(stage="service")` 는 오류가 든 슬롯과 이름이 다르다. 이미 있는
            # 정규화 슬롯까지 함께 본다 - 없는 슬롯을 새로 만들지는 않는다.
            for name in (st, *(("tcp_service", "udp_service") if st == "service" else ())):
                if name != st and name not in stages:
                    continue
                target = slot(name)
                # **같은 시도 안의 재시작은 건드리지 않는다.** 배치마다 stage_start 가 다시
                # 나오므로(_scan_batches), 회차를 안 보고 지우면 배치 0 의 실패가 배치 1
                # 시작에 조용히 사라진다.
                if (target.get("status") == "error"
                        and target.get("_error_attempt", attempt) < attempt):
                    superseded.add((name, target.get("_error_attempt")))
                    target["issues"] = [issue for issue in target.get("issues", [])
                                        if issue.get("type") != "command_error"]
                    # 정규화로 생긴 슬롯은 이번 시도의 `stage_done` 을 받지 못한다 - 그쪽은
                    # 원시 이름(`service`)으로 오기 때문이다. `running` 으로 두면 끝난
                    # 스캔에 영원히 도는 단계가 남으므로, 같은 일을 다시 해서 끝난 것으로
                    # 닫는다. 원시 슬롯은 뒤따르는 stage_done 이 제 상태를 채운다.
                    if name != st:
                        target["status"] = "done"
                        target["percent"] = 100
                    else:
                        target["status"] = "running"
                        target["percent"] = target.get("percent") or 0
                    target.pop("error", None)
                    target.pop("_error_attempt", None)
                elif (name == st
                      and target.get("status") not in {"done", "stopped", "error"}):
                    target["status"] = "running"
                    target["percent"] = target.get("percent") or 0
        elif e == "stage_activity":
            s = slot(st)
            progress = ev.get("percent")
            if isinstance(progress, (int, float)) and not isinstance(progress, bool) and math.isfinite(progress):
                s["percent"] = max(0, min(100, progress))
            s["status"] = "running"
            focus = {"stage": st}
            hosts = ev.get("current_hosts")
            if isinstance(hosts, list):
                focus["hosts"] = [h for h in hosts[:8] if isinstance(h, str)]
            for key in ("batch", "batch_total", "current_host_count",
                        "completed_hosts", "total_hosts"):
                value = ev.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    focus[key] = value
            if ev.get("progress_mode") == "batch":
                focus["progress_mode"] = "batch"
            current = focus
        elif e == "stage_progress":
            progress = ev.get("percent")
            mapped = st
            if st == "service" and current.get("stage") in {"tcp_service", "udp_service"}:
                mapped = current["stage"]
            if isinstance(progress, (int, float)) and not isinstance(progress, bool) and math.isfinite(progress):
                # 포트 스윕 Nmap 퍼센트는 현재 배치 안의 값이다. 배치 위치를 더해 단계 전체
                # 퍼센트로 바꾼다. 호스트별 서비스 프로브는 여러 Nmap이 동시에 떠 있으므로
                # 개별 프로세스 퍼센트로 전체를 덮지 않고 stage_activity의 완료 호스트 수를 쓴다.
                batch_progress = (
                    current.get("stage") == mapped and current.get("batch_total")
                    and (mapped == st or current.get("progress_mode") == "batch")
                )
                if batch_progress:
                    progress = ((current.get("batch", 1) - 1) + progress / 100) \
                               / current["batch_total"] * 100
                if st != "service" or mapped == st or current.get("progress_mode") == "batch":
                    slot(mapped)["percent"] = max(0, min(100, progress))
            else:
                slot(mapped)
            if stages[mapped].get("status") not in {"warning", "error"}:
                stages[mapped]["status"] = "running"
            if not current:
                current = {"stage": mapped}
        elif e == "hosts_up":
            slot("discovery")["counts"]["live"] = ev.get("count")
        elif e == "hosts_gave_up":
            mapped = mapped_stage(st, ev)
            s = slot(mapped)
            hosts = ev.get("hosts")
            hosts = [host for host in hosts if isinstance(host, str)] \
                if isinstance(hosts, list) else []
            count = ev.get("count")
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                count = len(hosts)
            s["issues"].append({
                "type": "host_timeout", "count": count, "hosts": hosts,
                "message": f"호스트 {count}대가 제한 시간 안에 이 단계를 끝내지 못했습니다.",
            })
            s["status"] = "warning"
            s["timeout_count"] = s.get("timeout_count", 0) + count
        elif e == "retransmission_cap_hit":
            mapped = mapped_stage(st, ev)
            s = slot(mapped)
            hosts = ev.get("hosts")
            hosts = [host for host in hosts if isinstance(host, str)] \
                if isinstance(hosts, list) else []
            count = ev.get("count")
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                count = len(hosts)
            retries = ev.get("max_retries")
            retries = retries if isinstance(retries, int) and not isinstance(retries, bool) else "?"
            s["issues"].append({
                "type": "retransmission_cap", "count": count, "hosts": hosts,
                "message": f"호스트 {count}대에서 포트 재전송 한도({retries}회)에 도달했습니다.",
            })
            s["status"] = "warning"
        elif e in {"service_retry", "service_split"}:
            mapped = mapped_stage(st, ev)
            hosts = ev.get("hosts")
            hosts = [host for host in hosts if isinstance(host, str)] \
                if isinstance(hosts, list) else []
            if not hosts and isinstance(ev.get("ip"), str):
                hosts = [ev["ip"]]
            ports = ev.get("ports")
            ports = [port for port in ports if isinstance(port, int) and not isinstance(port, bool)] \
                if isinstance(ports, list) else []
            recovery = {
                "type": "retry" if e == "service_retry" else "split",
                "stage": mapped, "proto": ev.get("proto") if ev.get("proto") in {"tcp", "udp"} else "",
                "hosts": hosts, "ports": ports,
                "port_spec": ev.get("port_spec") if isinstance(ev.get("port_spec"), str) else "",
                "reason": ev.get("reason") if isinstance(ev.get("reason"), str) else "",
                "outcome": ev.get("outcome") if ev.get("outcome") in {"recovered", "degraded", "failed", "stopped"}
                else "",
                "recovered": ev.get("recovered") is True,
            }
            for key in ("engine", "units", "recovered_units", "failed_units", "seconds", "rc"):
                value = ev.get(key)
                if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                    recovery[key] = value
            for key in ("recovery_of_execution_id", "execution_id"):
                value = ev.get(key)
                if isinstance(value, str) and value:
                    recovery[key] = value
            recoveries.append(recovery)
        elif e == "service_degraded":
            mapped = mapped_stage(st, ev)
            s = slot(mapped)
            hosts = ev.get("hosts")
            hosts = [host for host in hosts if isinstance(host, str)] \
                if isinstance(hosts, list) else []
            if not hosts and isinstance(ev.get("ip"), str):
                hosts = [ev["ip"]]
            ports = ev.get("failed_ports") or ev.get("ports")
            ports = [port for port in ports if isinstance(port, int) and not isinstance(port, bool)] \
                if isinstance(ports, list) else []
            proto = ev.get("proto") if ev.get("proto") in {"tcp", "udp"} else ""
            message = ev.get("message") if isinstance(ev.get("message"), str) \
                else "서비스 프로브가 일부 또는 전부 완료되지 않았습니다."
            issue = {
                "type": "service_degraded", "count": len(hosts) or 1,
                "hosts": hosts, "proto": proto, "ports": ports,
                "port_spec": ev.get("port_spec") if isinstance(ev.get("port_spec"), str) else "",
                "message": message,
            }
            s["issues"].append(issue)
            s["status"] = "warning"
            for host in hosts or [""]:
                quality_issues.append({
                    "kind": "service_degraded", "stage": mapped, "host_ip": host,
                    "proto": proto, "port_spec": issue["port_spec"], "message": message,
                })
        elif e == "stage_done":
            s = slot(st)
            cnts = ev.get("counts", {})
            if not isinstance(cnts, dict):
                cnts = {}
            if cnts.get("stopped"):
                status = "stopped"
            elif s.get("status") == "error":
                status = "error"
            elif s.get("issues"):
                status = "warning"
            else:
                status = "done"
            # warning 은 호스트 일부를 재시도 큐에 보존한 채 해당 단계 자체는 끝난 것이다.
            # 반대로 error/stopped 를 100%로 칠하면 "전체 절차 완료율"이 실패 직후 100%가
            # 되어 버린다. 마지막으로 실제 관측한 진행률을 그대로 둔다.
            percent = 100 if status in {"done", "warning"} else (s.get("percent") or 0)
            s.update({"status": status, "percent": percent,
                      "seconds": ev.get("seconds"), "counts": cnts})
            if current.get("stage") == st:
                current = {}
        elif e == "error":
            st = mapped_stage(st, ev)
            s = slot(st)
            label = {"discovery": "호스트 발견", "tcp": "TCP 포트 발견",
                     "tcp_service": "TCP 서비스 프로브", "udp": "UDP 포트 발견",
                     "udp_service": "UDP 서비스 프로브", "service": "서비스 식별"}.get(st, "스캔")
            # 원시 이벤트의 cmd/path/rc는 서버 로그에만 남기고 API에는 안정적 메시지만 노출한다.
            s["error"] = f"{label} 단계 실행에 실패했습니다."
            fatal = ev.get("fatal") is not False
            s["issues"].append({
                "type": "command_error", "count": 1, "message": s["error"],
                "fatal": fatal,
                "execution_key": ev.get("execution_id")
                if isinstance(ev.get("execution_id"), str) else "",
            })
            s["status"] = "error" if fatal else "warning"
            s["_error_attempt"] = attempt
            if fatal:
                quality_issues.append({
                    "_attempt": attempt,
                    "kind": "command_error", "stage": st, "host_ip": "",
                    "proto": ev.get("proto") if ev.get("proto") in {"tcp", "udp"} else "",
                    "port_spec": "", "message": s["error"],
                    "execution_key": ev.get("execution_id")
                    if isinstance(ev.get("execution_id"), str) else "",
                })
        elif e == "command_start":
            execution_id = ev.get("execution_id")
            argv = ev.get("argv")
            if not isinstance(execution_id, str) or not isinstance(argv, list):
                continue
            argv = [arg for arg in argv if isinstance(arg, str)]
            execution = {
                "id": execution_id, "stage": st,
                "group": ev.get("group") if ev.get("group") in {"common", "individual"}
                else "common",
                "reason": ev.get("reason") if isinstance(ev.get("reason"), str) else "",
                "artifact": ev.get("artifact") if isinstance(ev.get("artifact"), str) else "",
                "argv": argv, "status": "running", "started_at": ev.get("ts"),
                "watchdog_seconds": 0,
                "seconds": None, "timeout_count": 0, "timed_out": [],
                "retransmission_cap_count": 0, "retransmission_cap_hosts": [],
            }
            if ev.get("role") in {"authority", "enrichment"}:
                execution["role"] = ev["role"]
            executions[execution_id] = execution
            execution_order.append(execution_id)
        elif e == "command_done":
            execution_id = ev.get("execution_id")
            execution = executions.get(execution_id)
            if execution is None:
                continue
            outcome = ev.get("outcome")
            execution.update({
                # watchdog = 우리가 프로세스 상한으로 끊은 실행. rc 만 보면 nmap 이 죽은
                # 것과 구분되지 않는데 사용자가 할 일이 다르다(전자는 원인 조사, 후자는
                # 상한을 늘릴지 대상을 줄일지 결정).
                "status": outcome
                if outcome in {"done", "timeout", "error", "stopped", "watchdog"}
                else "done",
                "watchdog_seconds": ev.get("watchdog_seconds")
                if isinstance(ev.get("watchdog_seconds"), int)
                and not isinstance(ev.get("watchdog_seconds"), bool) else 0,
                "seconds": ev.get("seconds") if isinstance(ev.get("seconds"), (int, float))
                and not isinstance(ev.get("seconds"), bool) else None,
                "rc": ev.get("rc") if isinstance(ev.get("rc"), int) else None,
                "timeout_count": ev.get("timeout_count")
                if isinstance(ev.get("timeout_count"), int) else 0,
                "timed_out": [host for host in (ev.get("timed_out") or [])
                              if isinstance(host, str)],
                "retransmission_cap_count": ev.get("retransmission_cap_count")
                if isinstance(ev.get("retransmission_cap_count"), int) else 0,
                "retransmission_cap_hosts": [
                    host for host in (ev.get("retransmission_cap_hosts") or [])
                    if isinstance(host, str)
                ],
                "finished_at": ev.get("ts"),
            })
            for kind, hosts in (
                ("host_timeout", execution["timed_out"]),
                ("retransmission_cap", execution["retransmission_cap_hosts"]),
            ):
                for host in hosts:
                    quality_issues.append({
                        "kind": kind, "stage": execution["stage"], "host_ip": host,
                        "proto": "udp" if execution["stage"].startswith("udp") else "tcp"
                        if execution["stage"].startswith("tcp") else "",
                        "port_spec": "", "message": "",
                        "execution_key": execution_id,
                    })
        elif e == "job_start":
            overall["status"] = "running"
            attempt += 1
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
    if overall["status"] == "done":
        overall["percent"] = 100
    elif stage_list:
        # 시간 경과나 프로세스 상태가 아니라, 계획된 단계 중 실제로 끝난 비율이다.
        total = sum(100 if s["status"] in ("done", "warning") else (s.get("percent") or 0)
                    for s in stage_list)
        overall["percent"] = round(min(total / len(stage_list), 100), 1)
    now = time.time()
    for execution in executions.values():
        if execution["status"] != "running":
            continue
        started_at = execution.get("started_at")
        if (
            isinstance(started_at, (int, float))
            and not isinstance(started_at, bool)
            and math.isfinite(started_at)
        ):
            execution["seconds"] = round(max(now - started_at, 0), 1)
    recovered_execution_keys = {
        recovery.get("recovery_of_execution_id") for recovery in recoveries
        if recovery.get("recovered") is True
    }
    quality_issues = [
        issue for issue in quality_issues
        if not (
            issue.get("kind") == "command_error"
            and issue.get("execution_key") in recovered_execution_keys
        )
        # 재개가 대신한 시도의 실패는 남기지 않는다 - 남기면 성공한 스캔이 영영
        # '확인 필요' 로 보이고 재시도 안내가 사라지지 않는다.
        and (issue.get("kind"), issue.get("stage"), issue.get("_attempt")) not in {
            ("command_error", stage, att) for stage, att in superseded
        }
    ]
    for issue in quality_issues:
        issue.pop("_attempt", None)
    for stage in stage_list:
        stage.pop("_error_attempt", None)
    if recovered_execution_keys:
        for stage in stage_list:
            stage["issues"] = [
                issue for issue in stage.get("issues", [])
                if not (
                    issue.get("type") == "command_error"
                    and issue.get("execution_key") in recovered_execution_keys
                )
            ]
            if stage.get("status") == "warning" and not stage["issues"]:
                stage["status"] = "done" if stage.get("percent") == 100 else "running"
    return {
        "stages": stage_list, "overall": overall, "current": current,
        "executions": [executions[key] for key in execution_order if key in executions],
        "recoveries": recoveries, "quality_issues": quality_issues,
    }


_HOST_STAGE_FIELD = {
    "discovery": "discovery_status",
    "tcp": "tcp_sweep_status",
    "tcp_service": "tcp_service_status",
    "udp": "udp_sweep_status",
    "udp_service": "udp_service_status",
}


def terminal_observability(out_dir, spec: dict | None = None) -> dict:
    """Build deterministic terminal DB inputs from the authoritative sidecars.

    This does not write the database. Running scans continue to read the sidecars directly;
    the API calls this only while committing a terminal scan.  Keeping the conversion here
    makes reconciliation and the normal worker use the exact same projection.
    """
    out = Path(out_dir)
    parsed = parse_events(out)
    state = _read_state(out)
    saved = spec if isinstance(spec, dict) else {}
    plan = {
        stage.get("stage") for stage in parsed.get("stages", [])
        if isinstance(stage, dict) and isinstance(stage.get("stage"), str)
    }
    host_rows: dict[str, dict] = {}

    def host_row(host) -> dict | None:
        if not isinstance(host, str) or not host:
            return None
        row = host_rows.setdefault(host, {"host_ip": host})
        for stage, field in _HOST_STAGE_FIELD.items():
            row.setdefault(field, "unknown" if stage in plan else "not_planned")
        return row

    # 저장된 spec 의 targets 는 **주소 표현**이다. 기본 단계 스캔은 `-sn` 발견을 쓰므로
    # `10.0.0.0/24` 같은 문자열이 그대로 들어 있다. 그걸 호스트로 넣으면 그 토큰 자체가
    # 가짜 관측 행이 되어 `not_responding` 으로 찍히고, 정작 응답하지 않은 실제 주소들은
    # 행이 없다 - 없는 호스트를 하나 만들고 있는 호스트들을 빠뜨리는 셈이다.
    #
    # 구체적인 IP 만 받는다. `--discovery pn` 경로는 실제 호스트 목록이 그대로 들어오므로
    # 그쪽의 미응답 기록은 지금처럼 남는다. 범위를 펼치지는 않는다 - /16 하나가 65,536 개
    # 행이 되고, 응답하지 않은 주소는 어차피 지금도 행이 없다.
    for host in saved.get("targets", []) if isinstance(saved.get("targets"), list) else []:
        if isinstance(host, str) and _is_ip(host):
            host_row(host)
    live = {host for host in (state.get("live") or []) if isinstance(host, str)}
    for host in live:
        row = host_row(host)
        if row is not None:
            row["discovery_status"] = "done"
    discovery = next(
        (stage for stage in parsed.get("stages", []) if stage.get("stage") == "discovery"),
        None,
    )
    if discovery and discovery.get("status") in {"done", "warning"}:
        for host, row in host_rows.items():
            if host not in live and row["discovery_status"] == "unknown":
                row["discovery_status"] = "not_responding"

    coverage = state.get("coverage") or []
    if isinstance(coverage, list):
        for entry in coverage:
            if not isinstance(entry, dict):
                continue
            proto = entry.get("proto")
            if proto not in {"tcp", "udp"}:
                continue
            artifact = entry.get("artifact") if isinstance(entry.get("artifact"), str) else ""
            field = f"{proto}_service_status" if artifact.startswith("stage3-") \
                else f"{proto}_sweep_status"
            status = "done" if entry.get("finished") is True else "error"
            for host in entry.get("hosts", []) if isinstance(entry.get("hosts"), list) else []:
                row = host_row(host)
                if row is not None:
                    row[field] = status

    issue_inputs = []
    for raw in parsed.get("quality_issues", []):
        if not isinstance(raw, dict) or not isinstance(raw.get("kind"), str):
            continue
        issue = dict(raw)
        issue["detail"] = raw.get("message") if isinstance(raw.get("message"), str) else ""
        issue_inputs.append(issue)
        row = host_row(issue.get("host_ip"))
        field = _HOST_STAGE_FIELD.get(issue.get("stage"))
        if row is not None and field:
            row[field] = {
                "host_timeout": "timeout",
                "retransmission_cap": "warning",
                "service_degraded": "degraded",
                "command_error": "error",
            }.get(issue["kind"], "warning")

    return {
        "executions": parsed.get("executions") or [],
        "issues": issue_inputs,
        "hosts": list(host_rows.values()),
        "recoveries": parsed.get("recoveries") or [],
        "stages": parsed.get("stages") or [],
        "overall": parsed.get("overall") or {},
    }


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
    # 파일마다 관측 시각이 다르다. 배치가 여러 개면 b0 과 b7 사이에 몇 시간이 벌어지기도
    # 하므로, 스캔 하나의 시각으로 뭉뚱그리면 실제 순서와 어긋난다.
    if not force_scanned_hosts:
        # Service probing is enrichment, not authority over a successful open-port sweep.
        # In particular, a flaky mixed/Windows probe must not close a port just proven open.
        for pattern in ("stage-tcp-b*.xml", "stage-udp-b*.xml"):
            for x in sorted(out.glob(pattern)):
                try:
                    raw = x.read_bytes()
                    fallback = parse_xml(raw)
                except Exception:
                    continue
                seen_at = observed_at(raw)
                for f in fallback:
                    f["observed_at"] = seen_at
                    # Sweep proves openness only. It has not run the service/NSE probes and
                    # therefore must not erase an existing identity when stage3 misses a key.
                    f["identity_observed"] = False
                    by_key.setdefault((f["host_ip"], f["port"], f["proto"]), f)
    for x in sorted(out.glob("stage3-*.xml")):
        try:
            raw = x.read_bytes()
            fnd = parse_xml(raw)
        except Exception:
            continue
        seen_at = observed_at(raw)
        for f in fnd:
            f["observed_at"] = seen_at
            by_key[(f["host_ip"], f["port"], f["proto"])] = f   # confirm/base 중복 제거(존재값 우선)
    return list(by_key.values()), scanned


def authority_observed_at(out_dir, spec: dict, force_scanned_hosts: bool = False):
    """부재(닫힘)를 주장할 수 있는 시점 — authority 산출물이 **모두** 끝난 시각.

    '이 포트가 없다'는 마지막 authority sweep 이 끝나야 할 수 있는 말이다. 시작 시각을 쓰면
    실행 중에 다른 스캔이 새로 연 포트를 과거의 부재로 닫고, 반대로 이 스캔이 나중에 확인한
    열림을 오래된 것으로 버린다. 읽을 수 있는 시각이 하나도 없으면 None 을 돌려주어
    호출자가 스캔 시각으로 되돌아가게 한다.
    """
    times = []
    for path in expected_authority_xml(out_dir, spec, force_scanned_hosts):
        try:
            when = observed_at(path.read_bytes())
        except OSError:
            continue
        if when is not None:
            times.append(when)
    return max(times) if times else None


def ingest_results(db, scan, out_dir, scope_keys: set | None = None,
                   force_scanned_hosts: bool = False, scan_date=None, spec: dict | None = None,
                   closed_keys: set | None = None, applied_keys: set | None = None,
                   *, commit: bool = True) -> dict:
    """단계별 XML → finding 인입. 명시적 scope_keys는 완료 스캔의 closure 권한.

    ``spec`` 은 어느 산출물이 어떤 호스트를 훑었는지 되짚는 데 쓴다(absence_times). 없으면
    키별 부재 시각을 세우지 않고 실행 시각 하나로 판단한다 - 예전 동작이다.

    ``scan_date`` 는 이 결과가 **언제 관측된 것인가**다. 며칠 전 끝난 실행을 지금 마감하는
    경로(finalize/resume)에서 이걸 넘기지 않으면 인입 시각이 '지금'이 되어, ingest() 의
    out-of-order 방어(_is_older)가 한 번도 발동하지 않는다. 그러면 그 스캔이 끝난 뒤에
    새로 관측된 포트가 과거의 부재를 근거로 닫힌다 - 시간이 거꾸로 흐른다.
    """
    findings, scanned = collect_results(
        out_dir, scope_keys=scope_keys, force_scanned_hosts=force_scanned_hosts,
    )

    enriched = taxonomy.enrich_all(db, findings)
    counts = ingest(
        db, scan.id, enriched, scanned, scope_keys=scope_keys,
        scan_date=scan_date,
        # spec 이 없으면 어느 산출물이 무엇을 커버했는지 계산할 근거가 없다. 그때는 빈 맵을
        # 넘겨 '아무것도 커버하지 않았다' 로 읽히게 하는 대신, 키별 정보 없음(None)으로 둔다.
        absence_at=(absence_times(out_dir, spec, force_scanned_hosts)
                    if spec is not None else None),
        closed_keys=closed_keys,
        applied_keys=applied_keys,
        commit=False,
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
