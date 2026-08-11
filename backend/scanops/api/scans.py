"""스캔 라우터 — nmap 실행(백그라운드) / 오프라인 XML 가져오기 → finding 인입.

스캔은 HTTP 요청을 막지 않도록 백그라운드 스레드에서 돈다. 요청은 즉시 ScanRun 을
돌려주고, 프론트는 GET /{id}/progress 로 진행률을, POST /{id}/stop 으로 중지를,
POST /{id}/resume 로 이어가기를 호출한다. (status: running/done/failed/canceling/canceled)
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import SessionLocal, get_db
from ..models import ACTIVE_FINDING_STATES, Finding, ScanRun, User
from ..schemas import IngestSummary, RawCommandIn, ScanOut, ScanRunIn
from ..uploads import read_limited
from ..scanning import chunker, engine_runner, nmap_runner, scan_options, scope, taxonomy
from ..scanning.presets import PRESETS
from ..scanning.ingest import ingest
from ..scanning.nmap_parse import parse_xml, scan_start, up_hosts
from .audit import record
from .deps import current_user, require_role

router = APIRouter()
_settings = get_settings()
logger = logging.getLogger(__name__)

_FAILURE_MESSAGES = {
    "scan_state_missing": "저장된 스캔 실행 상태를 불러오지 못했습니다.",
    "invalid_scan_state": "저장된 스캔 설정을 해석하지 못했습니다.",
    "nmap_unavailable": "서버에서 스캔 도구를 찾을 수 없습니다.",
    "nmap_launch_failed": "스캔 도구를 시작하지 못했습니다.",
    "nmap_failed": "스캔 도구가 비정상 종료되었습니다.",
    "result_missing": "스캔 결과 파일이 생성되지 않았습니다.",
    "result_ingest_failed": "스캔 결과를 처리하지 못했습니다.",
    "engine_spec_missing": "단계 스캔 설정을 불러오지 못했습니다.",
    "engine_spec_invalid": "저장된 단계 스캔 설정을 해석하지 못했습니다.",
    "engine_launch_failed": "단계 스캔 엔진을 시작하지 못했습니다.",
    "engine_wait_failed": "단계 스캔 엔진의 종료 상태를 확인하지 못했습니다.",
    "engine_cleanup_failed": "단계 스캔 엔진을 안전하게 종료하지 못했습니다.",
    "engine_timeline_failed": "단계 스캔 진행 기록을 처리하지 못했습니다.",
    "engine_failed": "단계 스캔 중 오류가 발생했습니다.",
    "engine_incomplete": "단계 스캔이 완료 결과 없이 종료되었습니다.",
    "engine_ingest_failed": "단계 스캔 결과를 처리하지 못했습니다.",
    "import_failed": "XML 가져오기에 실패했습니다.",
    "launch_setup_failed": "스캔 실행 준비에 실패했습니다.",
    "server_restarted": "서버 재시작으로 실행이 중단되었습니다.",
}
_RECOVERABLE_COMPLETED_ENGINE_FAILURES = {
    "engine_wait_failed",
    "engine_cleanup_failed",
    "engine_timeline_failed",
    "engine_ingest_failed",
    "server_restarted",
}

# 실행 중인(현재 배치) nmap 프로세스 레지스트리(scan_id -> Popen). 중지 버튼이 여기서 찾아 종료.
# 서버 메모리에만 존재 — 재시작 시 비지만, 배치 진행상태는 사이드카 JSON 에 영속되므로
# 이어가기는 가능(다음 배치부터). 청킹이 native --resume(Windows 깨짐)을 대체한다.
_PROCS: dict = {}
_LOCK = threading.Lock()
AUTO_STAGE_LABELS = {
    "tcp_discovery": "TCP 전체 포트 발견",
    "tcp_identify": "발견된 TCP 포트 용도/서비스 식별",
    "udp_identify": "주요 UDP 서비스 식별",
}
STAGE_FILE_RE = re.compile(r"^(?P<base>.+)\.(?P<stage>tcp_discovery|tcp_identify|udp_identify)\.xml$", re.I)
IMPORT_CONTRACT_SCHEMA = 1
IMPORT_CONTRACT_MAX_HOSTS = 65536


def _basename(scan_id: int) -> Path:
    return _settings.scans_dir / f"scan_{scan_id}"


def _profile(options: list[str], ports: str, preset: str) -> tuple:
    """예상시간용 '동일 설정' 키 — 옵션(또는 프리셋) + 포트. 옵션·망이 시간을 좌우하므로
    이게 같은 과거 스캔만 기준으로 삼는다."""
    pn = (ports or "").replace(" ", "")
    return ("opt", tuple(sorted(options)), pn) if options else ("preset", preset or "quick", pn)


def _estimate_profile(body: ScanRunIn) -> tuple:
    if body.workflow == "auto":
        return ("auto", (body.ports or "").replace(" ", ""))
    return _profile(body.options, body.ports, body.preset)


def _validate_structured_scan(
    body: ScanRunIn, *, uses_manual_preset: bool,
) -> tuple[list[str], list[str]]:
    """Validate request fields shared by run, staged run, and estimate.

    Scope and executable availability are intentionally endpoint-specific.  The estimate
    endpoint skips those two checks, but must reject the same malformed structured input
    instead of presenting an estimate for a request that cannot be run.
    """
    nmap_runner.validate_targets(body.targets)
    scan_options.validate_keys(body.options)
    scan_options.validate_nse(body.nse)
    scan_options.validate_ports(body.ports)
    if body.workflow not in ("auto", "manual"):
        raise ValueError("workflow 는 auto 또는 manual 이어야 합니다.")
    if body.discovery not in ("sn", "pn"):
        raise ValueError("discovery 는 sn 또는 pn 이어야 합니다.")
    if not 1 <= body.batch_size <= 1024:
        raise ValueError("batch_size 는 1-1024 범위여야 합니다.")

    # Overlapping CIDRs/hosts must not inflate batches, estimates, or closure scope.
    hosts = list(dict.fromkeys(chunker.expand_targets(body.targets)))
    if not hosts:
        raise ValueError("유효한 타겟이 없습니다.")
    # Keep Nmap's target-injection/IPv6 contract aligned with saved engine specs, then
    # require the narrower IPv4 address/CIDR grammar used by exclusions.
    nmap_runner.validate_targets(body.exclude)
    excludes = scope.parse_excludes(body.exclude)
    if body.workflow == "auto":
        tcp_spec = nmap_runner.auto_tcp_port_spec(body.ports)
        udp_spec = nmap_runner.auto_udp_port_spec(body.ports)
        if not tcp_spec and not udp_spec:
            raise ValueError("자동 스캔에 사용할 TCP 또는 UDP 포트가 없습니다.")
    elif uses_manual_preset and not body.options and body.preset not in PRESETS:
        raise ValueError(f"알 수 없는 프리셋: {body.preset}")
    return hosts, excludes


def _effective_hosts(hosts: list[str], excludes: list[str]) -> list[str]:
    effective = scope.apply_excludes(hosts, excludes)
    if not effective:
        raise ValueError("제외 대상을 적용하니 스캔할 호스트가 남지 않았습니다.")
    return effective


def _with_nmap_excludes(argv: list[str], excludes: list[str] | None,
                        exclude_ports: str = "") -> list[str]:
    """Apply canonical exclusions as one Nmap option (repeated --exclude keeps only the last).

    포트 제외는 -p 를 건드리지 않는 전역 필터라, 같은 자리에서 한 번만 얹으면 모든 단계에 적용된다."""
    canonical = scope.parse_excludes(excludes)
    port_spec = scan_options.validate_ports(exclude_ports or "")
    injected: list[str] = []
    if canonical:
        injected += ["--exclude", ",".join(canonical)]
    if port_spec:
        injected += ["--exclude-ports", port_spec]
    if not injected:
        return argv
    return [argv[0], *injected, *argv[1:]]


def _merge_raw_excludes(argv: list[str], excludes: list[str] | None) -> list[str]:
    """직접 입력 명령에 구조화된 제외 대상을 합친다.

    Nmap 은 --exclude 를 반복하면 마지막 값만 쓰므로, 명령에 이미 있는 인라인 --exclude 를 그냥 두고
    하나 더 붙이면 둘 중 하나가 조용히 사라진다. 인라인 값을 걷어내 구조화 값과 함께 검증·중복제거한
    뒤 정확히 하나의 --exclude 로 되돌린다(다른 실행 경로와 같은 계약)."""
    inline: list[str] = []
    cleaned: list[str] = []
    take_value = False
    for token in argv:
        if take_value:
            take_value = False
            inline.extend(token.replace(",", " ").split())
            continue
        if token == "--exclude":
            take_value = True
            continue
        if token.startswith("--exclude="):
            inline.extend(token.split("=", 1)[1].replace(",", " ").split())
            continue
        cleaned.append(token)
    merged = [*inline, *(excludes or [])]
    if not merged:
        return argv
    return _with_nmap_excludes(cleaned, merged)


def _validate_staged_protocol_selection(body: ScanRunIn) -> None:
    """Reject an explicit UDP port request when the staged UDP phase is disabled."""
    selected = set(body.options or [])
    if "connect" in selected and "syn" in selected:
        raise ValueError("단계 스캔에서는 TCP SYN과 Connect 방식을 동시에 선택할 수 없습니다.")
    if "connect" in selected and "udp" in selected:
        raise ValueError("TCP Connect 단계 스캔은 UDP 스캔과 함께 실행할 수 없습니다.")
    if body.ports and nmap_runner.auto_udp_port_spec(body.ports) and "udp" not in body.options:
        raise ValueError("UDP 포트를 지정하려면 udp 스캔 옵션을 활성화해야 합니다.")


def reconcile_orphans() -> int:
    """서버 부팅 시 호출 — 워커가 사라져 고아가 된 실행(running/canceling)을 interrupted 로 정직하게
    표기한다. 자동 복구는 하지 않는다(이어하기는 사용자가 수동으로). 좀비 '실행 중' 박제를 막는 게 목적.
    반환: 정리된 건수."""
    db = SessionLocal()
    try:
        orphans = db.query(ScanRun).filter(ScanRun.status.in_(("running", "canceling"))).all()
        for scan in orphans:
            out_dir = _settings.scans_dir / f"scan_{scan.id}"
            if engine_runner.is_engine_scan(out_dir):
                try:
                    stages = engine_runner.parse_events(out_dir)["stages"]
                except (OSError, UnicodeError):
                    logger.warning(
                        "failed to preserve staged scan timeline for scan %s", scan.id,
                        exc_info=True,
                    )
                else:
                    if stages:
                        scan.stages_json = stages
            scan.status = "interrupted"
            scan.failure_code = "server_restarted"
            scan.failure_message = _FAILURE_MESSAGES["server_restarted"]
            if scan.finished_at is None:
                scan.finished_at = datetime.now(timezone.utc)
        if orphans:
            db.commit()
        return len(orphans)
    finally:
        db.close()


def _mark(scan_id: int, status: str, failure_code: str = "") -> None:
    """종료 상태 확정(done/failed/canceled) — finished_at 기록."""
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        if scan is not None:
            scan.status = status
            scan.finished_at = datetime.now(timezone.utc)
            scan.failure_code = failure_code if status == "failed" else ""
            scan.failure_message = _FAILURE_MESSAGES.get(failure_code, "") if status == "failed" else ""
            db.commit()
    finally:
        db.close()


def _fail(scan_id: int, failure_code: str) -> None:
    _mark(scan_id, "failed", failure_code)


def _fail_launch_setup(
    db: Session,
    scan_id: int,
    user: User,
    target: str,
    artifact_paths: list[Path],
    artifact_dirs: list[Path] | None = None,
    audit_action: str = "SCAN_RUN",
    failure_code: str = "launch_setup_failed",
) -> None:
    """Persist one safe terminal failure and remove exact pre-worker artifacts."""
    logger.exception("failed to prepare scan %s for launch", scan_id)
    try:
        db.rollback()
        scan = db.get(ScanRun, scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.finished_at = datetime.now(timezone.utc)
            scan.failure_code = failure_code
            scan.failure_message = _FAILURE_MESSAGES[failure_code]
            db.commit()
    except Exception:
        db.rollback()
        logger.exception("failed to persist launch setup failure for scan %s", scan_id)

    for path in dict.fromkeys(artifact_paths):
        candidates = [path, *path.parent.glob(f"{path.name}.*.tmp")]
        for candidate in candidates:
            try:
                candidate.unlink(missing_ok=True)
            except OSError:
                logger.warning(
                    "failed to remove launch artifact for scan %s",
                    scan_id,
                    exc_info=True,
                )
    for directory in dict.fromkeys(artifact_dirs or []):
        try:
            directory.rmdir()
        except FileNotFoundError:
            pass
        except OSError:
            # Only remove an empty, exact per-scan directory. Unknown diagnostic files stay.
            logger.warning("launch artifact directory is not empty for scan %s", scan_id)
    record(
        db, user, audit_action, target=target,
        detail=f"#{scan_id} 시작 준비 실패", ok=False,
    )
    raise HTTPException(status_code=500, detail=_FAILURE_MESSAGES["launch_setup_failed"])


def _set_current_log(scan_id: int, log_path: Path) -> None:
    """진행률 표시가 읽을 현재 배치 로그 경로를 기록."""
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        if scan is not None:
            scan.log_path = str(log_path)
            db.commit()
    finally:
        db.close()


def _port_tokens(port_spec: str, proto: str) -> list[str]:
    current = ""
    out: list[str] = []
    for raw in (port_spec or "").replace(" ", "").split(","):
        item = raw.strip()
        if not item:
            continue
        if ":" in item:
            prefix, value = item.split(":", 1)
            if prefix.upper() in {"T", "U"}:
                current = prefix.upper()
                item = value
        if not item:
            continue
        if not current:
            if proto.upper() == "T":
                out.append(item)
        elif current == proto.upper():
            out.append(item)
    return out


def _port_scope(port_spec: str, proto: str) -> set[int] | None:
    """None means all ports for the protocol were scanned."""
    tokens = _port_tokens(port_spec, proto)
    if not tokens:
        return set()
    ports: set[int] = set()
    for token in tokens:
        if "-" in token:
            lo, hi = token.split("-", 1)
            try:
                start = int(lo) if lo else 1
                end = int(hi) if hi else 65535
            except ValueError:
                continue
            if start <= 1 and end >= 65535:
                return None
            ports.update(range(max(1, start), min(65535, end) + 1))
        else:
            try:
                ports.add(int(token))
            except ValueError:
                continue
    return ports


def _stage_file_info(filename: str | None) -> tuple[str, str] | None:
    normalized = (filename or "").replace("\\", "/")
    m = STAGE_FILE_RE.match(normalized)
    if not m:
        return None
    return m.group("base"), m.group("stage").lower()


def _scaninfo_scope(xml_bytes: bytes, proto: str) -> set[int] | None | set:
    """Read the nmap <scaninfo services=...> range for scoped close decisions."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return set()
    proto = proto.lower()
    prefix = "T" if proto == "tcp" else "U"
    scopes: list[set[int] | None] = []
    for info in root.findall("scaninfo"):
        if (info.get("protocol") or "").lower() != proto:
            continue
        services = (info.get("services") or "").strip()
        if not services:
            continue
        scopes.append(_port_scope(f"{prefix}:{services}", prefix))
    if not scopes:
        return set()
    if any(s is None for s in scopes):
        return None
    merged: set[int] = set()
    for s in scopes:
        merged.update(s)
    return merged


def _scope_from_stage_xml(stage: str, xml_bytes: bytes) -> tuple[set[int] | None | set, set[int] | None | set]:
    if stage.startswith("tcp_"):
        return _scaninfo_scope(xml_bytes, "tcp"), set()
    if stage == "udp_identify":
        return set(), _scaninfo_scope(xml_bytes, "udp")
    return set(), set()


def _finding_key(f: dict) -> str:
    return f"{f['host_ip']}|{f['port']}|{f['proto']}"


def _auto_scope_keys(db: Session, scanned_hosts: set[str], findings: list[dict],
                     tcp_scope: set[int] | None | set, udp_scope: set[int] | None | set) -> set[str]:
    keys = {_finding_key(f) for f in findings}
    if not scanned_hosts:
        return keys
    hosts = sorted(scanned_hosts)
    rows = []
    for start in range(0, len(hosts), 500):
        rows.extend(db.query(Finding).filter(
            Finding.state.in_(ACTIVE_FINDING_STATES), Finding.host_ip.in_(hosts[start:start + 500])
        ).all())
    for row in rows:
        proto = (row.proto or "").lower()
        if proto == "tcp" and (tcp_scope is None or row.port in tcp_scope):
            keys.add(row.finding_key)
        if proto == "udp" and (udp_scope is None or row.port in udp_scope):
            keys.add(row.finding_key)
    return keys


def _prefer_identified(primary: list[dict], fallback: list[dict]) -> list[dict]:
    """Keep service-identification rows, but preserve discovery-only open ports."""
    by_key = {_finding_key(f): f for f in primary}
    for f in fallback:
        key = _finding_key(f)
        if key not in by_key:
            # Discovery proves the port open but does not authoritatively observe identity.
            # Copy so callers retaining the parsed discovery list do not see a hidden mutation.
            by_key[key] = {**f, "identity_observed": False}
    return list(by_key.values())


def _key_parts(key: str) -> tuple[str, int, str]:
    host, port, proto = key.split("|", 2)
    return host, int(port), proto


def _port_el(finding: dict) -> ET.Element:
    port = ET.Element("port", protocol=finding.get("proto") or "tcp", portid=str(finding.get("port") or "0"))
    ET.SubElement(port, "state", state=finding.get("state") or "open")
    svc_attrs = {
        k: str(v)
        for k, v in {
            "name": finding.get("service") or "",
            "product": finding.get("product") or "",
            "version": finding.get("version") or "",
        }.items()
        if v
    }
    if svc_attrs:
        svc_attrs.setdefault("method", "probed" if finding.get("identification") == "확인" else "table")
        svc = ET.SubElement(port, "service", **svc_attrs)
        for cpe in str(finding.get("cpe") or "").split(";"):
            if cpe:
                ET.SubElement(svc, "cpe").text = cpe
    for script in finding.get("nse_json") or []:
        ET.SubElement(
            port,
            "script",
            id=str(script.get("id") or ""),
            output=str(script.get("output") or ""),
        )
    return port


def _closed_port_el(port_num: int, proto: str, service: str = "") -> ET.Element:
    port = ET.Element("port", protocol=proto, portid=str(port_num))
    ET.SubElement(port, "state", state="closed", reason="scanops-scope")
    if service:
        ET.SubElement(port, "service", name=service, method="table")
    return port


def _write_merged_xml(db: Session, xml_path: Path, findings: list[dict], scanned_hosts: set[str],
                      scope_keys: set[str], scan_date: datetime | None = None) -> None:
    """Write one XML snapshot that heatmap can read consistently with Finding ingest."""
    when = scan_date or datetime.now(timezone.utc)
    root = ET.Element(
        "nmaprun",
        scanner="scanops",
        args="scanops bundled import",
        start=str(int(when.timestamp())),
        startstr=when.isoformat(),
        version="scanops",
        xmloutputversion="1.05",
    )
    fallback_keys = [
        _finding_key(f) for f in findings if f.get("identity_observed") is False
    ]
    prior_identity = {
        row.finding_key: row
        for row in db.query(Finding).filter(Finding.finding_key.in_(fallback_keys)).all()
    } if fallback_keys else {}
    by_host: dict[str, dict[str, list]] = {}
    seen = {_finding_key(f) for f in findings}
    for f in findings:
        snapshot = f
        if f.get("identity_observed") is False and (row := prior_identity.get(_finding_key(f))):
            # The discovery sweep proves openness only. Keep the merged heatmap snapshot in
            # sync with ingest(), which retains the last authoritative identity/evidence.
            snapshot = {**f}
            for field in (
                "hostname", "service", "product", "version", "server", "banner", "cpe",
                "identification", "nse_json", "remarks",
            ):
                snapshot[field] = getattr(row, field)
        by_host.setdefault(f["host_ip"], {"open": [], "closed": []})["open"].append(snapshot)

    missing = sorted(scope_keys - seen, key=lambda k: (_key_parts(k)[0], _key_parts(k)[2], _key_parts(k)[1]))
    existing = {
        row.finding_key: row
        for row in db.query(Finding).filter(Finding.finding_key.in_(missing)).all()
    } if missing else {}
    for key in missing:
        host, port_num, proto = _key_parts(key)
        row = existing.get(key)
        by_host.setdefault(host, {"open": [], "closed": []})["closed"].append((port_num, proto, row.service if row else ""))

    hosts = sorted(set(scanned_hosts) | set(by_host))
    for host_ip in hosts:
        host_el = ET.SubElement(root, "host")
        ET.SubElement(host_el, "status", state="up")
        ET.SubElement(host_el, "address", addr=host_ip, addrtype="ipv4")
        ports_el = ET.SubElement(host_el, "ports")
        items = by_host.get(host_ip, {"open": [], "closed": []})
        for f in sorted(items["open"], key=lambda x: (x.get("proto") or "", int(x.get("port") or 0))):
            ports_el.append(_port_el(f))
        for port_num, proto, service in items["closed"]:
            ports_el.append(_closed_port_el(port_num, proto, service))
    runstats = ET.SubElement(root, "runstats")
    ET.SubElement(runstats, "finished", time=str(int(when.timestamp())), exit="success")
    ET.SubElement(runstats, "hosts", up=str(len(hosts)), down="0", total=str(len(hosts)))
    xml_path.write_bytes(ET.tostring(root, encoding="utf-8", xml_declaration=True))


def _commit_ingest(db: Session, scan: ScanRun, findings: list[dict], scanned_hosts: set[str],
                   tcp_scope: set[int] | None | set, udp_scope: set[int] | None | set,
                   scan_date: datetime | None = None, raw_xml_path: Path | None = None,
                   closure_hosts: set[str] | None = None,
                   closure_scope_keys: set[str] | None = None) -> dict:
    enriched = taxonomy.enrich_all(db, findings)
    scope_keys = (
        closure_scope_keys
        if closure_scope_keys is not None
        else _auto_scope_keys(
            db,
            scanned_hosts if closure_hosts is None else closure_hosts,
            enriched,
            tcp_scope,
            udp_scope,
        )
    )
    if raw_xml_path is not None:
        _write_merged_xml(db, raw_xml_path, enriched, scanned_hosts, scope_keys, scan_date)
        scan.raw_xml_path = str(raw_xml_path)
    counts = ingest(
        db, scan.id, enriched, scanned_hosts, scope_keys=scope_keys,
        scan_date=scan_date, commit=False,
    )
    from .assets import match_assets
    match_assets(db, commit=False)
    scan.host_count = len({f["host_ip"] for f in enriched})
    scan.port_count = len(enriched)
    scan.status = "done"
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()
    return counts


def _ingest_batch(
    scan_id: int,
    xml_bytes: bytes,
    no_close: bool = False,
    closure_hosts: set[str] | None = None,
) -> None:
    """배치 XML 1개 인입 — job scan_id 에 귀속, host/port 카운트 누적(상태는 안 바꿈).
    완료된 structured 배치는 closure_hosts 범위에 권한을 가지므로 다른 배치에는 영향이 없다.
    no_close=True 면 닫힘 판정을 끈다(직접 명령처럼 스캔한 포트 범위를 알 수 없을 때 — 가산만)."""
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        findings = taxonomy.enrich_all(db, parse_xml(xml_bytes))
        scanned_hosts = up_hosts(xml_bytes)
        if no_close:
            scope_keys = set()
        else:
            scope_keys = _auto_scope_keys(
                db,
                scanned_hosts if closure_hosts is None else closure_hosts,
                findings,
                _scaninfo_scope(xml_bytes, "tcp"),
                _scaninfo_scope(xml_bytes, "udp"),
            )
        ingest(db, scan_id, findings, scanned_hosts, scope_keys=scope_keys, commit=False)
        from .assets import match_assets
        match_assets(db, commit=False)
        scan.host_count = (scan.host_count or 0) + len({f["host_ip"] for f in findings})
        scan.port_count = (scan.port_count or 0) + len(findings)
        db.commit()
    finally:
        db.close()


def _ingest_auto_findings(
    scan_id: int,
    findings: list[dict],
    scanned_hosts: set[str],
    tcp_scope: set[int] | None | set,
    udp_scope: set[int] | None | set,
    closure_hosts: set[str] | None = None,
) -> None:
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        if scan is None:
            return
        enriched = taxonomy.enrich_all(db, findings)
        scope_keys = _auto_scope_keys(
            db,
            scanned_hosts if closure_hosts is None else closure_hosts,
            enriched,
            tcp_scope,
            udp_scope,
        )
        ingest(db, scan_id, enriched, scanned_hosts, scope_keys=scope_keys, commit=False)
        from .assets import match_assets
        match_assets(db, commit=False)
        scan.host_count = (scan.host_count or 0) + len({f["host_ip"] for f in enriched})
        scan.port_count = (scan.port_count or 0) + len(enriched)
        db.commit()
    finally:
        db.close()


def _wait_scan_process(scan_id: int, proc) -> int:
    """Register, honor a stop that raced with spawn, then release tree ownership."""
    with _LOCK:
        _PROCS[scan_id] = proc
    if chunker.stop_requested(_basename(scan_id)) and proc.poll() is None:
        proc.terminate()
    try:
        return nmap_runner.wait_owned(proc)
    finally:
        with _LOCK:
            if _PROCS.get(scan_id) is proc:
                _PROCS.pop(scan_id, None)


def _run_stage(scan_id: int, argv: list[str], log_path: Path) -> int:
    _set_current_log(scan_id, log_path)
    try:
        proc = nmap_runner.popen(argv, log_path)
    except OSError:
        return -1
    return _wait_scan_process(scan_id, proc)


class _WorkerFailure(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _checked_stage(scan_id: int, argv: list[str], log_path: Path) -> None:
    rc = _run_stage(scan_id, argv, log_path)
    if rc == -1:
        raise _WorkerFailure("nmap_launch_failed")
    if rc != 0:
        raise _WorkerFailure("nmap_failed")


def _run_auto_batch(scan_id: int, nmap: str, batch: list[str], b_base: Path, state: dict) -> bool:
    """Run discovery -> identify -> UDP for one batch, then ingest the final observations once."""
    ports = state.get("ports", "")
    nse = state.get("nse") if state.get("nse") is not None else scan_options.NSE_DEFAULT_KEYS
    udp_all_targets = bool(state.get("udp_all_targets"))
    tcp_port_spec = nmap_runner.auto_tcp_port_spec(ports)
    udp_port_spec = nmap_runner.auto_udp_port_spec(ports)
    tcp_scope = _port_scope(tcp_port_spec, "T") if tcp_port_spec else set()
    udp_scope = _port_scope(udp_port_spec, "U") if udp_port_spec else set()
    findings: list[dict] = []
    scanned_hosts: set[str] = set()
    tcp_discovery_findings: list[dict] = []
    # identify 단계는 discovery 에서 살아난 호스트로만 좁힌다(죽은 IP 재스캔·PTR 폭증 방지).
    # discovery 를 안 돌린 UDP-only 경우엔 비어 있어 배치 전체로 폴백.
    discovery_live: list[str] = []

    if tcp_port_spec:
        if chunker.stop_requested(_basename(scan_id)):
            return False
        discovery_base = Path(str(b_base) + ".tcp_discovery")
        discovery_log = Path(str(discovery_base) + ".log")
        argv = _with_nmap_excludes(
            nmap_runner.build_auto_command(
                nmap, "tcp_discovery", batch, discovery_base, ports=ports, nse=nse,
            ),
            state.get("exclude"), state.get("exclude_ports", ""),
        )
        _checked_stage(scan_id, argv, discovery_log)
        discovery_xml = nmap_runner.xml_of(discovery_base)
        if not discovery_xml.exists():
            raise _WorkerFailure("result_missing")
        discovery_live = sorted(up_hosts(discovery_xml))
        scanned_hosts |= set(discovery_live)
        tcp_discovery_findings = parse_xml(discovery_xml)
        tcp_ports = nmap_runner.open_ports_from_xml(discovery_xml, "tcp")
        if tcp_ports:
            if chunker.stop_requested(_basename(scan_id)):
                return False
            identify_base = Path(str(b_base) + ".tcp_identify")
            identify_log = Path(str(identify_base) + ".log")
            argv = _with_nmap_excludes(
                nmap_runner.build_auto_command(
                    nmap, "tcp_identify", discovery_live or batch, identify_base,
                    ports=ports, tcp_ports=tcp_ports, nse=nse,
                ),
                state.get("exclude"), state.get("exclude_ports", ""),
            )
            _checked_stage(scan_id, argv, identify_log)
            identify_xml = nmap_runner.xml_of(identify_base)
            if not identify_xml.exists():
                raise _WorkerFailure("result_missing")
            scanned_hosts |= up_hosts(identify_xml)
            findings.extend(_prefer_identified(parse_xml(identify_xml), tcp_discovery_findings))
        else:
            findings.extend(tcp_discovery_findings)

    # discovery 를 돌렸는데 생존 호스트가 0이면 UDP 도 스킵(죽은 대역에 -Pn UDP 낭비 방지).
    # udp_all_targets(opt-in)면 discovery 결과 무관하게 원본 배치 전체로 UDP(죽은 IP 비용 감수,
    # TCP/ICMP/ACK 다 침묵하지만 UDP만 여는 호스트·부분 누락까지 보장). 아니면 생존 호스트로 제한,
    # discovery 를 돌렸는데 생존 0이면 skip(죽은 대역 UDP 낭비 방지).
    if udp_port_spec and (udp_all_targets or not tcp_port_spec or discovery_live):
        if chunker.stop_requested(_basename(scan_id)):
            return False
        udp_base = Path(str(b_base) + ".udp_identify")
        udp_log = Path(str(udp_base) + ".log")
        udp_targets = batch if udp_all_targets else (discovery_live or batch)
        argv = _with_nmap_excludes(
            nmap_runner.build_auto_command(
                nmap, "udp_identify", udp_targets, udp_base, ports=ports, nse=nse,
            ),
            state.get("exclude"), state.get("exclude_ports", ""),
        )
        _checked_stage(scan_id, argv, udp_log)
        udp_xml = nmap_runner.xml_of(udp_base)
        if not udp_xml.exists():
            raise _WorkerFailure("result_missing")
        scanned_hosts |= up_hosts(udp_xml)
        findings.extend(parse_xml(udp_xml))

    if not tcp_port_spec and not udp_port_spec:
        raise _WorkerFailure("invalid_scan_state")
    try:
        _ingest_auto_findings(
            scan_id, findings, scanned_hosts, tcp_scope, udp_scope,
            closure_hosts=set(batch),
        )
    except Exception as exc:
        raise _WorkerFailure("result_ingest_failed") from exc
    return True


def _chunk_worker(scan_id: int) -> None:
    """배치를 순차 실행. 각 배치: nmap → XML → 인입 → 사이드카 커서 전진.
    중지(stop) 플래그가 보이면 현재 배치를 버리고(커서 유지) canceled 로 멈춘다 →
    이어가기 시 그 배치부터 다시 실행한다."""
    base = _basename(scan_id)
    nmap = nmap_runner.find_nmap(_settings.nmap_path)
    state = chunker.read_state(base)
    if not nmap:
        _fail(scan_id, "nmap_unavailable")
        return
    if state is None:
        _fail(scan_id, "scan_state_missing")
        return
    batches = state["batches"]
    while True:
        st = chunker.read_state(base) or state
        if chunker.stop_requested(base):
            _mark(scan_id, "canceled")
            return
        cursor = st.get("cursor", 0)
        if cursor >= len(batches):
            _mark(scan_id, "done")
            return
        batch = batches[cursor]
        b_base = Path(str(base) + f".b{cursor}")
        b_log = Path(str(b_base) + ".log")
        t0 = datetime.now(timezone.utc)
        if st.get("workflow") == "auto":
            try:
                ok = _run_auto_batch(scan_id, nmap, batch, b_base, st)
            except _WorkerFailure as exc:
                # /stop 이 현재 Nmap을 terminate하면 nonzero rc가 나오나, 이는 실패가
                # 아니라 사용자 취소다. sidecar 요청을 실행 오류보다 우선한다.
                if chunker.stop_requested(base):
                    _mark(scan_id, "canceled")
                    return
                logger.exception("auto scan %s failed", scan_id)
                _fail(scan_id, exc.code)
                return
            except ValueError:
                logger.exception("invalid stored auto-scan settings for scan %s", scan_id)
                _fail(scan_id, "invalid_scan_state")
                return
            if chunker.stop_requested(base):
                _mark(scan_id, "canceled")
                return
            if not ok:
                _fail(scan_id, "nmap_failed")
                return
            dt = (datetime.now(timezone.utc) - t0).total_seconds()
            st["cursor"] = cursor + 1
            st["active_seconds"] = round(st.get("active_seconds", 0) + dt, 1)
            chunker.write_state(base, st)
            continue
        try:
            if st.get("options"):
                argv = nmap_runner.build_command_opts(nmap, st.get("options") or [], st.get("ports", ""), batch, b_base, nse=st.get("nse"))
            else:
                argv = nmap_runner.build_command(
                    nmap, st.get("preset", "quick"), batch, b_base,
                    ports=st.get("ports", ""), nse=st.get("nse"),
                )
            argv = _with_nmap_excludes(argv, st.get("exclude"), st.get("exclude_ports", ""))
        except ValueError:
            logger.exception("invalid stored scan settings for scan %s", scan_id)
            _fail(scan_id, "invalid_scan_state")
            return
        _set_current_log(scan_id, b_log)
        try:
            proc = nmap_runner.popen(argv, b_log)
        except OSError:
            logger.exception("failed to launch nmap for scan %s", scan_id)
            _fail(scan_id, "nmap_launch_failed")
            return
        rc = _wait_scan_process(scan_id, proc)

        # 중지로 종료됐으면 이 배치는 미완 → 커서 유지하고 canceled.
        if chunker.stop_requested(base):
            _mark(scan_id, "canceled")
            return
        xml_path = nmap_runner.xml_of(b_base)
        if rc != 0:
            _fail(scan_id, "nmap_failed")
            return
        if not xml_path.exists():
            _fail(scan_id, "result_missing")
            return
        try:
            _ingest_batch(scan_id, xml_path.read_bytes(), closure_hosts=set(batch))
        except Exception:
            logger.exception("failed to ingest scan %s result", scan_id)
            _fail(scan_id, "result_ingest_failed")
            return
        # 배치 완료 → 커서 전진 + 실제 스캔 시간 누적(영속). 누적은 멈춤시간 제외 → ETA 정확.
        dt = (datetime.now(timezone.utc) - t0).total_seconds()
        st["cursor"] = cursor + 1
        st["active_seconds"] = round(st.get("active_seconds", 0) + dt, 1)
        chunker.write_state(base, st)


def _command_worker(scan_id: int) -> None:
    """직접 입력 명령 스캔 — 단발 실행(청킹/이어가기 없음). nmap → XML → 인입.
    중지(stop)면 프로세스 종료 후 canceled."""
    base = _basename(scan_id)
    state = chunker.read_state(base) or {}
    argv = state.get("raw_argv")
    if not argv:
        _fail(scan_id, "scan_state_missing")
        return
    log = Path(str(base) + ".log")
    _set_current_log(scan_id, log)
    if chunker.stop_requested(base):
        _mark(scan_id, "canceled")
        return
    try:
        proc = nmap_runner.popen(argv, log)
    except OSError:
        logger.exception("failed to launch raw nmap scan %s", scan_id)
        _fail(scan_id, "nmap_launch_failed")
        return
    rc = _wait_scan_process(scan_id, proc)
    if chunker.stop_requested(base):
        _mark(scan_id, "canceled")
        return
    xml_path = nmap_runner.xml_of(base)
    if rc != 0:
        _fail(scan_id, "nmap_failed")
        return
    if not xml_path.exists():
        _fail(scan_id, "result_missing")
        return
    try:
        # 직접 명령은 -p 범위가 불투명 → 닫힘 판정을 끄고 가산만(미스캔 포트 오closure 방지).
        _ingest_batch(scan_id, xml_path.read_bytes(), no_close=True)
    except Exception:
        logger.exception("failed to ingest raw scan %s result", scan_id)
        _fail(scan_id, "result_ingest_failed")
        return
    _mark(scan_id, "done")


def _persist_stages(scan_id: int, out_dir: Path) -> None:
    """엔진 이벤트를 단계 요약으로 접어 ScanRun.stages_json 에 영속(완료·중지·실패 공통)."""
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        if scan is not None:
            scan.stages_json = engine_runner.parse_events(out_dir)["stages"]
            db.commit()
    finally:
        db.close()


def _load_engine_spec(spec_path: Path) -> dict:
    data = json.loads(spec_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("engine spec must be an object")
    scanops_spec = data.get("scanops") or {}
    if not isinstance(scanops_spec, dict):
        raise ValueError("scanops spec must be an object")
    if "scope_keys" in scanops_spec:
        keys = scanops_spec["scope_keys"]
        if not isinstance(keys, list) or not all(isinstance(key, str) for key in keys):
            raise ValueError("scope_keys must be a string list")
    return data


def _parse_engine_scope_key(key: str) -> tuple[str, int, str]:
    parts = key.split("|")
    if len(parts) != 3:
        raise ValueError("저장된 단계 스캔 닫힘 범위(scope_keys) 형식이 잘못되었습니다.")
    host, port_text, proto = parts
    try:
        address = ipaddress.ip_address(host)
        port = int(port_text)
    except ValueError:
        raise ValueError(
            "저장된 단계 스캔 닫힘 범위(scope_keys) 형식이 잘못되었습니다."
        ) from None
    if (address.version != 4 or str(address) != host
            or str(port) != port_text or not 1 <= port <= 65535
            or proto not in {"tcp", "udp"}):
        raise ValueError("저장된 단계 스캔 닫힘 범위(scope_keys) 형식이 잘못되었습니다.")
    return host, port, proto


def _engine_stage_port_scope(saved_spec: dict, proto: str) -> set[int] | None:
    stages = saved_spec.get("stages") or {}
    if not isinstance(stages, dict):
        raise ValueError("저장된 단계 스캔 닫힘 범위(scope_keys) 설정이 잘못되었습니다.")
    stage = stages.get(proto) or {}
    if not isinstance(stage, dict):
        raise ValueError("저장된 단계 스캔 닫힘 범위(scope_keys) 설정이 잘못되었습니다.")
    default_enabled = proto == "tcp"
    default_ports = "1-65535" if proto == "tcp" else scan_options.UDP_DEFAULT_PORTS
    enabled = stage.get("enabled", default_enabled)
    ports = stage.get("ports", default_ports)
    if not isinstance(enabled, bool) or not isinstance(ports, str):
        raise ValueError("저장된 단계 스캔 닫힘 범위(scope_keys) 설정이 잘못되었습니다.")
    scan_options.validate_ports(ports)
    if not enabled:
        return set()
    if not ports.strip():
        raise ValueError("저장된 단계 스캔 닫힘 범위(scope_keys) 설정이 잘못되었습니다.")
    prefix = "T" if proto == "tcp" else "U"
    scoped_ports = ports if ":" in ports else f"{prefix}:{ports}"
    return _port_scope(scoped_ports, prefix)


def _validate_engine_scope_keys(saved_spec: dict) -> None:
    """Keep explicit closure authority inside the immutable saved scan contract."""
    scanops_spec = saved_spec.get("scanops") or {}
    if "scope_keys" not in scanops_spec:
        return
    parsed_keys = {_parse_engine_scope_key(key) for key in scanops_spec["scope_keys"]}
    excludes = scope.parse_excludes(saved_spec.get("exclude") or [])

    rescan_units = saved_spec.get("rescan_units")
    targets_ports = saved_spec.get("targets_ports")
    expected: set[tuple[str, int, str]] | None = None
    if rescan_units:
        if not isinstance(rescan_units, list) or not all(
            isinstance(unit, dict) for unit in rescan_units
        ):
            raise ValueError("저장된 단계 스캔 닫힘 범위(scope_keys) 설정이 잘못되었습니다.")
        expected = {
            _parse_engine_scope_key(
                f"{unit.get('ip', '')}|{unit.get('port', '')}|{unit.get('proto', 'tcp')}"
            )
            for unit in rescan_units
        }
    elif targets_ports:
        if not isinstance(targets_ports, dict):
            raise ValueError("저장된 단계 스캔 닫힘 범위(scope_keys) 설정이 잘못되었습니다.")
        expected = set()
        for host, ports in targets_ports.items():
            if not isinstance(ports, list):
                raise ValueError(
                    "저장된 단계 스캔 닫힘 범위(scope_keys) 설정이 잘못되었습니다."
                )
            expected.update(
                _parse_engine_scope_key(f"{host}|{port}|tcp") for port in ports
            )

    if expected is not None:
        selected_hosts = [host for host, _port, _proto in expected]
        if scope.apply_excludes(selected_hosts, excludes) != selected_hosts:
            raise ValueError(
                "저장된 단계 스캔 닫힘 범위(scope_keys)에 제외 대상이 포함되어 있습니다."
            )
        if parsed_keys != expected:
            raise ValueError(
                "저장된 단계 스캔 닫힘 범위(scope_keys)가 재스캔 선택 범위와 다릅니다."
            )
        return

    targets = saved_spec.get("targets") or []
    if not isinstance(targets, list) or not all(isinstance(target, str) for target in targets):
        raise ValueError("저장된 단계 스캔 닫힘 범위(scope_keys) 설정이 잘못되었습니다.")
    nmap_runner.validate_targets(targets)
    effective_hosts = set(scope.apply_excludes(chunker.expand_targets(targets), excludes))
    tcp_ports = _engine_stage_port_scope(saved_spec, "tcp")
    udp_ports = _engine_stage_port_scope(saved_spec, "udp")
    for host, port, proto in parsed_keys:
        port_scope = tcp_ports if proto == "tcp" else udp_ports
        if host not in effective_hosts or (port_scope is not None and port not in port_scope):
            raise ValueError(
                "저장된 단계 스캔 닫힘 범위(scope_keys)가 유효 스캔 범위를 벗어났습니다."
            )


def _commit_engine_ingest(db: Session, scan: ScanRun, out_dir: Path,
                          scope_keys: set[str] | None,
                          force_scanned_hosts: bool) -> dict:
    """Persist staged findings and the equivalent authoritative heatmap snapshot."""
    findings, scanned_hosts = engine_runner.collect_results(
        out_dir, scope_keys=scope_keys, force_scanned_hosts=force_scanned_hosts,
    )
    if scope_keys is None:
        # Backward-compatible old specs used host-wide closure. Capture those same active keys
        # before ingest mutates them so the synthetic XML records every resulting close.
        snapshot_scope = _auto_scope_keys(db, scanned_hosts, findings, None, None)
    else:
        # Explicit scope_keys are the completed scan's authority, independent of discovery.
        # They were built from effective targets, so excluded hosts are absent by construction.
        snapshot_scope = set(scope_keys)
    merged_path = _settings.scans_dir / f"scan_{scan.id}.xml"
    snapshot_date = scan.started_at
    if snapshot_date is not None and snapshot_date.tzinfo is None:
        # SQLite reloads UTC DateTime values without tzinfo; timestamp() would otherwise apply
        # the Windows local offset and move this phase backwards in the heatmap chronology.
        snapshot_date = snapshot_date.replace(tzinfo=timezone.utc)
    _write_merged_xml(
        db, merged_path, findings, scanned_hosts, snapshot_scope, scan_date=snapshot_date,
    )
    scan.raw_xml_path = str(merged_path)
    return engine_runner.ingest_results(
        db, scan, out_dir, scope_keys=scope_keys,
        force_scanned_hosts=force_scanned_hosts, commit=False,
    )


def _engine_worker(scan_id: int, *, finalize_completed: bool = False) -> None:
    """단계분리 엔진 실행 — spec.json 으로 엔진 spawn → 대기 → 단계요약 영속 + 결과 인입.

    중지는 run-state.json 의 stop 플래그로(graceful, 단계/호스트 경계). 엔진 프로세스는
    자기 nmap 자식을 관리하므로 ScanOps 가 강제 종료하지 않는다(고아 nmap 방지).
    """
    out_dir = _settings.scans_dir / f"scan_{scan_id}"
    spec_path = out_dir / "spec.json"
    if not spec_path.exists():
        _fail(scan_id, "engine_spec_missing")
        return
    # 타겟 재스캔이면 spec 에 scope_keys 가 들어있음 → 닫힘 판정을 그 발견으로만 한정.
    scope_keys = None
    force_scanned_hosts = False
    try:
        saved_spec = _load_engine_spec(spec_path)
        _validate_engine_scope_keys(saved_spec)
        scanops_spec = saved_spec.get("scanops") or {}
        if "scope_keys" in scanops_spec:
            scope_keys = set(scanops_spec.get("scope_keys") or [])
        force_scanned_hosts = bool(saved_spec.get("rescan_units") or saved_spec.get("targets_ports"))
    except (OSError, ValueError, json.JSONDecodeError):
        logger.exception("failed to read staged engine spec for scan %s", scan_id)
        _fail(scan_id, "engine_spec_invalid")
        return
    rc = None
    if not finalize_completed:
        try:
            proc = engine_runner.spawn(spec_path, out_dir, out_dir / "engine.log")
        except (OSError, RuntimeError):
            logger.exception("failed to launch staged engine for scan %s", scan_id)
            _fail(scan_id, "engine_launch_failed")
            return
        wait_failed = False
        cleanup_failed = False
        try:
            rc = proc.wait()
        except Exception:
            logger.exception("failed while waiting for staged engine scan %s", scan_id)
            wait_failed = True
        finally:
            # 정상 완료뿐 아니라 wait 예외에도 backend ownership을 닫아 engine/Nmap 잔존을 막는다.
            try:
                engine_runner.close_owned(proc)
            except Exception:
                logger.exception("failed to close staged engine scan %s process tree", scan_id)
                cleanup_failed = True
        if cleanup_failed:
            _fail(scan_id, "engine_cleanup_failed")
            return
        if wait_failed:
            _fail(scan_id, "engine_wait_failed")
            return
    try:
        _persist_stages(scan_id, out_dir)
    except Exception:
        logger.exception("failed to persist staged scan %s timeline", scan_id)
        _fail(scan_id, "engine_timeline_failed")
        return
    if engine_runner.stopped(out_dir):
        _mark(scan_id, "canceled")
        return
    if not finalize_completed and rc != 0:
        _fail(scan_id, "engine_failed")
        return
    if not engine_runner.is_done(out_dir):
        _fail(scan_id, "engine_incomplete")
        return
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        if scan is not None:
            _commit_engine_ingest(db, scan, out_dir, scope_keys, force_scanned_hosts)
            scan.status = "done"
            scan.finished_at = datetime.now(timezone.utc)
            scan.failure_code = ""
            scan.failure_message = ""
            db.commit()
    except Exception:
        logger.exception("failed to ingest staged scan %s result", scan_id)
        db.rollback()
        try:
            (_settings.scans_dir / f"scan_{scan_id}.xml").unlink(missing_ok=True)
        except OSError:
            logger.warning(
                "failed to remove staged scan snapshot for scan %s",
                scan_id,
                exc_info=True,
            )
        _fail(scan_id, "engine_ingest_failed")
    finally:
        db.close()


def _finalize_completed_engine_worker(scan_id: int) -> None:
    """Ingest an already-complete engine run without spawning the engine or Nmap again."""
    _engine_worker(scan_id, finalize_completed=True)


class _InvalidImportXML(ValueError):
    pass


def _targets_fingerprint(hosts: list[str]) -> str:
    digest = hashlib.sha256()
    for host in hosts:
        encoded = host.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _contract_int(obj: dict, key: str, minimum: int = 0, maximum: int | None = None) -> int:
    value = obj.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise _InvalidImportXML(f"manifest import_contract.{key} 값이 올바르지 않습니다.")
    if maximum is not None and value > maximum:
        raise _InvalidImportXML(f"manifest import_contract.{key} 값이 너무 큽니다.")
    return value


def _strict_services(value: str) -> set[int]:
    ports: set[int] = set()
    if not isinstance(value, str) or not value.strip():
        raise _InvalidImportXML("manifest에 연결된 XML scaninfo services가 비어 있습니다.")
    for raw in value.split(","):
        token = raw.strip()
        if not token:
            raise _InvalidImportXML("manifest에 연결된 XML scaninfo services가 올바르지 않습니다.")
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2 or not all(part.isdigit() for part in parts):
                raise _InvalidImportXML("manifest에 연결된 XML 포트 범위가 올바르지 않습니다.")
            start, end = (int(part) for part in parts)
            if not (1 <= start <= end <= 65535):
                raise _InvalidImportXML("manifest에 연결된 XML 포트 범위가 올바르지 않습니다.")
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit() or not 1 <= int(token) <= 65535:
                raise _InvalidImportXML("manifest에 연결된 XML 포트가 올바르지 않습니다.")
            ports.add(int(token))
    return ports


def _validate_contract_xml(xml_bytes: bytes, stage_id: str, target_count: int) -> None:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        raise _InvalidImportXML("manifest에 연결된 XML 형식이 올바르지 않습니다.") from None
    if root.tag != "nmaprun":
        raise _InvalidImportXML("manifest에 연결된 파일은 Nmap XML이 아닙니다.")
    finished = root.findall("./runstats/finished")
    hosts = root.findall("./runstats/hosts")
    if len(finished) != 1 or len(hosts) != 1 or finished[0].get("exit") != "success":
        raise _InvalidImportXML("manifest의 닫힘 권한에는 성공한 Nmap runstats가 필요합니다.")
    try:
        up = int(hosts[0].get("up", ""))
        down = int(hosts[0].get("down", ""))
        total = int(hosts[0].get("total", ""))
    except (TypeError, ValueError):
        raise _InvalidImportXML("manifest에 연결된 Nmap host 집계가 올바르지 않습니다.") from None
    if up < 0 or down < 0 or up + down != total or total != target_count:
        raise _InvalidImportXML("manifest target 수와 Nmap host 집계가 일치하지 않습니다.")

    protocols: set[str] = set()
    for info in root.findall("./scaninfo"):
        proto = (info.get("protocol") or "").lower()
        if proto not in {"tcp", "udp"}:
            raise _InvalidImportXML("manifest에 연결된 XML protocol이 올바르지 않습니다.")
        ports = _strict_services(info.get("services") or "")
        try:
            numservices = int(info.get("numservices", ""))
        except (TypeError, ValueError):
            raise _InvalidImportXML("manifest에 연결된 XML numservices가 올바르지 않습니다.") from None
        if numservices != len(ports):
            raise _InvalidImportXML("manifest에 연결된 XML 포트 수가 일치하지 않습니다.")
        protocols.add(proto)
    if not protocols:
        raise _InvalidImportXML("manifest의 닫힘 권한에는 scaninfo 포트 범위가 필요합니다.")
    if stage_id == "tcp_discovery" and protocols != {"tcp"}:
        raise _InvalidImportXML("TCP 발견 manifest와 XML protocol이 일치하지 않습니다.")
    if stage_id == "udp_identify" and protocols != {"udp"}:
        raise _InvalidImportXML("UDP 식별 manifest와 XML protocol이 일치하지 않습니다.")


def _canonical_contract_targets(value, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(host, str) for host in value):
        raise _InvalidImportXML(f"manifest {field}가 IPv4 목록이 아닙니다.")
    result: list[str] = []
    seen: set[str] = set()
    for host in value:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise _InvalidImportXML(f"manifest {field}에는 canonical IPv4만 사용할 수 있습니다.") from None
        if not isinstance(address, ipaddress.IPv4Address) or str(address) != host or host in seen:
            raise _InvalidImportXML(f"manifest {field}에는 중복 없는 canonical IPv4만 사용할 수 있습니다.")
        seen.add(host)
        result.append(host)
    return result


def _safe_contract_basename(value) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or ":" in value
        or Path(value).name != value
    ):
        raise _InvalidImportXML("manifest XML 파일명은 안전한 basename이어야 합니다.")
    return value


def _validate_import_observation_hosts(
    observed_hosts: set,
    allowed_targets: list[str],
) -> None:
    """Bind every imported observation to the unit that claims to have produced it."""
    observed = set(observed_hosts)
    observed.discard(None)

    canonical: set[str] = set()
    for host in observed:
        if not isinstance(host, str):
            raise _InvalidImportXML("manifest XML 관측 host가 올바른 IPv4가 아닙니다.")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise _InvalidImportXML("manifest XML 관측 host가 올바른 IPv4가 아닙니다.") from None
        if not isinstance(address, ipaddress.IPv4Address) or str(address) != host:
            raise _InvalidImportXML("manifest XML 관측 host가 canonical IPv4가 아닙니다.")
        canonical.add(host)

    unexpected = sorted(canonical.difference(allowed_targets))
    if unexpected:
        shown = ", ".join(unexpected[:5])
        if len(unexpected) > 5:
            shown += f" 외 {len(unexpected) - 5}건"
        raise _InvalidImportXML(f"manifest XML 관측 host가 unit target 밖입니다: {shown}")
    try:
        scope.check_scope(sorted(canonical))
    except ValueError as exc:
        raise _InvalidImportXML(f"manifest XML 관측 host가 서버 scope 밖입니다: {exc}") from None


def _validate_import_manifest(manifest_bytes: bytes, payloads: list[dict]) -> dict[str, set[str]] | None:
    """Validate a standalone sidecar fully before the first DB or artifact side effect."""
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _InvalidImportXML("manifest JSON 형식이 올바르지 않습니다.") from None
    if not isinstance(manifest, dict):
        raise _InvalidImportXML("manifest JSON 객체가 필요합니다.")
    contract = manifest.get("import_contract")
    if contract is None:
        return None  # old standalone manifests retain observed-host import semantics
    if manifest.get("tool") != "scanops_scanner" or not isinstance(contract, dict):
        raise _InvalidImportXML("인식된 manifest import_contract 형식이 올바르지 않습니다.")
    if contract.get("schema") != IMPORT_CONTRACT_SCHEMA:
        raise _InvalidImportXML("지원하지 않는 manifest import_contract schema입니다.")

    raw_targets = contract.get("raw_targets")
    if not isinstance(raw_targets, list) or not raw_targets or not all(isinstance(t, str) for t in raw_targets):
        raise _InvalidImportXML("manifest raw_targets가 올바르지 않습니다.")
    try:
        nmap_runner.validate_targets(raw_targets)
        max_hosts = _contract_int(contract, "max_hosts", 1, IMPORT_CONTRACT_MAX_HOSTS)
        expanded = list(dict.fromkeys(chunker.expand_targets(raw_targets, max_hosts)))
        # Authorization is evaluated against the original requested expansion, before excludes.
        scope.check_scope(expanded)
        excludes = scope.parse_excludes(contract.get("exclude"))
    except ValueError as exc:
        raise _InvalidImportXML(f"manifest target/exclude 검증 실패: {exc}") from None
    if excludes != contract.get("exclude"):
        raise _InvalidImportXML("manifest exclude가 canonical 목록이 아닙니다.")
    effective = scope.apply_excludes(expanded, excludes)
    if not effective:
        raise _InvalidImportXML("manifest exclude 적용 후 대상이 남지 않습니다.")
    if _contract_int(contract, "requested_host_count") != len(expanded):
        raise _InvalidImportXML("manifest 요청 host 수가 target과 일치하지 않습니다.")
    if _contract_int(contract, "effective_host_count") != len(effective):
        raise _InvalidImportXML("manifest 유효 host 수가 target/exclude와 일치하지 않습니다.")
    if contract.get("effective_targets_sha256") != _targets_fingerprint(effective):
        raise _InvalidImportXML("manifest 유효 target 지문이 일치하지 않습니다.")
    batch_size = _contract_int(contract, "batch_size", 0, IMPORT_CONTRACT_MAX_HOSTS)
    batches = chunker.make_batches(effective, batch_size) if batch_size > 0 else [effective]
    host_timeout = contract.get("host_timeout")
    if not isinstance(host_timeout, str):
        raise _InvalidImportXML("manifest host_timeout 형식이 올바르지 않습니다.")

    by_basename: dict[str, dict] = {}
    observed_by_basename: dict[str, set] = {}
    for item in payloads:
        basename = Path(item["name"].replace("\\", "/")).name
        if basename in by_basename:
            raise _InvalidImportXML("manifest import에 중복 XML basename이 있습니다.")
        _, findings, scanned_hosts, _, _ = _prepare_import_xml(item["bytes"], item["name"])
        observed = set(scanned_hosts)
        observed.update(finding.get("host_ip") for finding in findings)
        observed_by_basename[basename] = observed
        by_basename[basename] = item

    units = contract.get("units")
    if not isinstance(units, list):
        raise _InvalidImportXML("manifest units 목록이 올바르지 않습니다.")
    authorities: dict[str, set[str]] = {}
    for unit in units:
        if not isinstance(unit, dict):
            raise _InvalidImportXML("manifest unit 형식이 올바르지 않습니다.")
        basename = _safe_contract_basename(unit.get("xml_basename"))
        if basename in authorities:
            raise _InvalidImportXML("manifest에 중복 XML unit이 있습니다.")
        item = by_basename.get(basename)
        if item is None:
            raise _InvalidImportXML("manifest가 참조하는 XML 파일이 업로드되지 않았습니다.")
        if _contract_int(unit, "xml_size") != len(item["bytes"]):
            raise _InvalidImportXML("manifest XML 크기가 업로드와 일치하지 않습니다.")
        digest = unit.get("xml_sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise _InvalidImportXML("manifest XML SHA-256 형식이 올바르지 않습니다.")
        if hashlib.sha256(item["bytes"]).hexdigest() != digest:
            raise _InvalidImportXML("manifest XML SHA-256이 업로드와 일치하지 않습니다.")
        try:
            root = ET.fromstring(item["bytes"])
        except ET.ParseError:
            raise _InvalidImportXML("manifest에 연결된 XML 형식이 올바르지 않습니다.") from None
        if root.tag != "nmaprun":
            raise _InvalidImportXML("manifest에 연결된 파일은 Nmap XML이 아닙니다.")

        batch_index = _contract_int(unit, "batch_index", 0)
        if batch_index >= len(batches):
            raise _InvalidImportXML("manifest unit batch_index가 범위를 벗어났습니다.")
        stage_id = unit.get("stage_id")
        if stage_id not in {"single", "tcp_discovery", "tcp_identify", "udp_identify"}:
            raise _InvalidImportXML("manifest unit stage_id가 올바르지 않습니다.")
        file_stage = (_stage_file_info(basename) or ("", "single"))[1]
        if file_stage != stage_id:
            raise _InvalidImportXML("manifest unit stage와 XML 파일명이 일치하지 않습니다.")
        authoritative = unit.get("authoritative")
        if not isinstance(authoritative, bool):
            raise _InvalidImportXML("manifest unit authoritative 값이 올바르지 않습니다.")
        closure_targets = _canonical_contract_targets(unit.get("closure_targets"), "closure_targets")
        if not authoritative:
            if closure_targets:
                raise _InvalidImportXML("관측 전용 manifest unit은 closure_targets를 가질 수 없습니다.")
            _validate_import_observation_hosts(observed_by_basename[basename], batches[batch_index])
            authorities[basename] = set()
            continue
        if host_timeout:
            raise _InvalidImportXML("host-timeout 실행은 미관측 닫힘 권한을 가질 수 없습니다.")
        if stage_id not in {"single", "tcp_discovery", "udp_identify"}:
            raise _InvalidImportXML("TCP 식별 unit은 미관측 닫힘 권한을 가질 수 없습니다.")
        batch = batches[batch_index]
        if stage_id in {"single", "tcp_discovery"}:
            if closure_targets != batch:
                raise _InvalidImportXML("manifest unit target이 유효 batch와 일치하지 않습니다.")
        elif not closure_targets or not set(closure_targets).issubset(set(batch)):
            raise _InvalidImportXML("UDP manifest unit target이 유효 batch의 subset이 아닙니다.")
        try:
            scope.check_scope(closure_targets)
        except ValueError as exc:
            raise _InvalidImportXML(f"manifest 닫힘 target이 서버 scope 밖입니다: {exc}") from None
        _validate_import_observation_hosts(observed_by_basename[basename], closure_targets)
        _validate_contract_xml(item["bytes"], stage_id, len(closure_targets))
        authorities[basename] = set(closure_targets)

    if set(authorities) != set(by_basename):
        raise _InvalidImportXML("업로드 XML 목록과 manifest unit 목록이 일치하지 않습니다.")
    return authorities


def _prepare_import_xml(xml_bytes: bytes, filename: str | None = None) -> tuple:
    """Parse every XML-derived value before creating a ScanRun or writing a file."""
    try:
        scan_date = scan_start(xml_bytes)
        stage = (_stage_file_info(filename) or ("", ""))[1]
        findings = parse_xml(xml_bytes)
        if stage == "tcp_discovery":
            findings = [{**finding, "identity_observed": False} for finding in findings]
        scanned_hosts = up_hosts(xml_bytes)
        if stage:
            tcp_scope, udp_scope = _scope_from_stage_xml(stage, xml_bytes)
        else:
            tcp_scope = _scaninfo_scope(xml_bytes, "tcp")
            udp_scope = _scaninfo_scope(xml_bytes, "udp")
    except Exception:
        # ElementTree text, local paths, and parser internals must not be reflected to clients.
        raise _InvalidImportXML("XML 형식이 올바르지 않습니다.") from None
    return scan_date, findings, scanned_hosts, tcp_scope, udp_scope


def _zero_counts() -> dict:
    return {"new": 0, "reopened": 0, "service_changed": 0, "version_changed": 0,
            "server_changed": 0, "unchanged": 0, "closed": 0}


def _add_counts(total: dict, counts: dict) -> None:
    for key, value in counts.items():
        total[key] = total.get(key, 0) + int(value or 0)


def _fail_import(db: Session, scan_id: int, artifact_paths: list[Path]) -> None:
    """Best-effort terminal state and exact artifact cleanup for a failed import unit."""
    try:
        db.rollback()
        scan = db.get(ScanRun, scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.finished_at = datetime.now(timezone.utc)
            scan.raw_xml_path = ""
            scan.failure_code = "import_failed"
            scan.failure_message = _FAILURE_MESSAGES["import_failed"]
            db.commit()
    except Exception:
        db.rollback()
        logger.exception("failed to persist XML import failure for scan %s", scan_id)
    for artifact_path in dict.fromkeys(artifact_paths):
        try:
            artifact_path.unlink(missing_ok=True)
        except OSError:
            logger.warning(
                "failed to remove partial XML import artifact for scan %s",
                scan_id,
                exc_info=True,
            )


def _import_single_xml(
    db: Session,
    user: User,
    name: str,
    xml_bytes: bytes,
    closure_hosts: set[str] | None = None,
) -> dict:
    # Full parsing precedes every persistent side effect. A malformed upload therefore
    # cannot leave a ScanRun row, raw XML file, finding mutation, or success audit record.
    sdate, findings, scanned_hosts, tcp_scope, udp_scope = _prepare_import_xml(xml_bytes, name)
    scan = ScanRun(name=f"가져오기: {name}", status="running", created_by=user.id)
    db.add(scan)
    db.commit()
    if sdate is not None:
        scan.started_at = sdate
    stage = (_stage_file_info(name) or ("", ""))[1]
    xml_path = _settings.scans_dir / f"scan_{scan.id}.xml"
    artifact_paths = [xml_path]
    try:
        if stage == "tcp_discovery":
            # Keep the exact partial-stage artifact while exposing a merged snapshot whose
            # identity agrees with the Finding row retained by the discovery-only contract.
            stage_path = _settings.scans_dir / f"scan_{scan.id}.{stage}.xml"
            artifact_paths.append(stage_path)
            stage_path.write_bytes(xml_bytes)
        else:
            xml_path.write_bytes(xml_bytes)
            scan.raw_xml_path = str(xml_path)
        counts = _commit_ingest(
            db,
            scan,
            findings,
            scanned_hosts,
            tcp_scope,
            udp_scope,
            scan_date=sdate,
            raw_xml_path=xml_path if stage == "tcp_discovery" else None,
            closure_hosts=closure_hosts,
        )
    except Exception:
        _fail_import(db, scan.id, artifact_paths)
        raise
    record(db, user, "SCAN_IMPORT", target=name, detail=f"#{scan.id}")
    return {"scan_id": scan.id, "name": scan.name, "counts": counts, "files": [name]}


def _import_stage_bundle(db: Session, user: User, base: str, stages: dict[str, dict]) -> dict:
    # Validate and derive every stage before the first DB/file side effect. One malformed
    # member invalidates the unit atomically instead of leaving a failed row and partial files.
    prepared = {
        stage: _prepare_import_xml(item["bytes"], item["name"])
        for stage, item in stages.items()
    }
    dates = [values[0] for values in prepared.values() if values[0] is not None]
    sdate = min(dates) if dates else None
    display = Path(base.replace("\\", "/")).name
    scan = ScanRun(name=f"가져오기: {display} 자동 스캔 묶음", status="running", created_by=user.id)
    scan.command = "자동 스캔 XML 묶음 · TCP 발견 → TCP 식별 → UDP 식별"
    db.add(scan)
    db.commit()
    if sdate is not None:
        scan.started_at = sdate

    merged_path = _settings.scans_dir / f"scan_{scan.id}.xml"
    artifact_paths = [
        merged_path,
        *(
            _settings.scans_dir / f"scan_{scan.id}.{stage}.xml"
            for stage in stages
        ),
    ]
    try:
        scanned_hosts: set[str] = set()
        closure_scope_keys: set[str] = set()
        tcp_scope: set[int] | None | set = set()
        udp_scope: set[int] | None | set = set()
        tcp_discovery_findings: list[dict] = []
        tcp_identified_findings: list[dict] = []
        udp_findings: list[dict] = []

        for stage, item in stages.items():
            (_settings.scans_dir / f"scan_{scan.id}.{stage}.xml").write_bytes(item["bytes"])

        if values := prepared.get("tcp_discovery"):
            _date, findings, hosts, stage_tcp_scope, _stage_udp_scope = values
            scanned_hosts |= hosts
            tcp_scope = stage_tcp_scope
            tcp_discovery_findings = findings
            item = stages["tcp_discovery"]
            closure_scope_keys |= _auto_scope_keys(
                db,
                hosts if item.get("closure_hosts") is None else item["closure_hosts"],
                findings,
                stage_tcp_scope,
                set(),
            )
        if values := prepared.get("tcp_identify"):
            _date, findings, hosts, stage_tcp_scope, _stage_udp_scope = values
            scanned_hosts |= hosts
            if tcp_scope == set():
                tcp_scope = stage_tcp_scope
            tcp_identified_findings = findings
            item = stages["tcp_identify"]
            closure_scope_keys |= _auto_scope_keys(
                db,
                hosts if item.get("closure_hosts") is None else item["closure_hosts"],
                findings,
                stage_tcp_scope,
                set(),
            )
        if values := prepared.get("udp_identify"):
            _date, findings, hosts, _stage_tcp_scope, stage_udp_scope = values
            scanned_hosts |= hosts
            udp_scope = stage_udp_scope
            udp_findings = findings
            item = stages["udp_identify"]
            closure_scope_keys |= _auto_scope_keys(
                db,
                hosts if item.get("closure_hosts") is None else item["closure_hosts"],
                findings,
                set(),
                stage_udp_scope,
            )

        tcp_findings = _prefer_identified(tcp_identified_findings, tcp_discovery_findings)
        findings = [*tcp_findings, *udp_findings]
        if not scanned_hosts:
            scanned_hosts = {f["host_ip"] for f in findings if f.get("host_ip")}

        counts = _commit_ingest(
            db,
            scan,
            findings,
            scanned_hosts,
            tcp_scope,
            udp_scope,
            scan_date=sdate,
            raw_xml_path=merged_path,
            closure_scope_keys=closure_scope_keys,
        )
    except Exception:
        _fail_import(db, scan.id, artifact_paths)
        raise
    files = [stages[k]["name"] for k in sorted(stages)]
    record(db, user, "SCAN_IMPORT_BUNDLE", target=display, detail=f"#{scan.id} · {len(files)} files")
    return {"scan_id": scan.id, "name": scan.name, "counts": counts, "files": files}


@router.get("", response_model=list[ScanOut])
def list_scans(_: User = Depends(current_user), db: Session = Depends(get_db)):
    return db.query(ScanRun).order_by(ScanRun.id.desc()).all()


@router.get("/options")
def list_scan_options(_: User = Depends(current_user)):
    """스캔 옵션 화이트리스트 — UI 가 토글을 그리고 명령을 실시간 조립. NSE 스크립트 목록 포함."""
    return {
        "options": scan_options.SCAN_OPTIONS,
        "default": scan_options.DEFAULT_KEYS,
        "nse": scan_options.NSE_SCRIPTS,
        "nse_default": scan_options.NSE_DEFAULT_KEYS,
        "udp_default_ports": scan_options.UDP_DEFAULT_PORTS,
        "default_ports": scan_options.DEFAULT_PORTS,
    }


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, _: User = Depends(current_user), db: Session = Depends(get_db)):
    scan = db.get(ScanRun, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="스캔을 찾을 수 없습니다.")
    return scan


@router.post("/import", response_model=IngestSummary)
async def import_xml(
    file: UploadFile = File(...),
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    xml_bytes = await read_limited(file, _settings.upload_max_bytes)
    try:
        result = _import_single_xml(db, user, file.filename or "scan.xml", xml_bytes)
    except _InvalidImportXML as e:
        record(db, user, "SCAN_IMPORT", target=file.filename or "", detail="실패", ok=False)
        raise HTTPException(status_code=400, detail=f"XML 파싱 실패: {e}")
    except Exception:
        logger.exception("failed to import XML")
        record(db, user, "SCAN_IMPORT", target=file.filename or "", detail="실패", ok=False)
        raise HTTPException(status_code=500, detail=_FAILURE_MESSAGES["import_failed"])
    return IngestSummary(scan_id=result["scan_id"], counts=result["counts"])


@router.post("/import-bundle")
async def import_xml_bundle(
    files: list[UploadFile] = File(...),
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    payloads = []
    manifests = []
    total_bytes = 0
    for f in files:
        name = f.filename or "scan.xml"
        lower_name = name.lower()
        if not (lower_name.endswith(".xml") or lower_name.endswith(".manifest.json")):
            continue
        data = await read_limited(f, _settings.upload_max_bytes)
        total_bytes += len(data)
        if total_bytes > _settings.upload_bundle_max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"업로드 묶음이 허용 크기({_settings.upload_bundle_max_bytes} bytes)를 초과했습니다.",
            )
        if lower_name.endswith(".manifest.json"):
            manifests.append({"name": name, "bytes": data})
        else:
            payloads.append({"name": name, "bytes": data})
    if not payloads:
        raise HTTPException(status_code=400, detail="가져올 XML 파일이 없습니다.")
    if len(manifests) > 1:
        raise HTTPException(status_code=400, detail="standalone manifest는 한 번에 하나만 가져올 수 있습니다.")

    authorities = None
    if manifests:
        try:
            authorities = _validate_import_manifest(manifests[0]["bytes"], payloads)
        except _InvalidImportXML as exc:
            record(db, user, "SCAN_IMPORT", target=manifests[0]["name"], detail="실패", ok=False)
            raise HTTPException(status_code=400, detail=f"가져오기 계약 오류: {exc}")
    if authorities is not None:
        for item in payloads:
            basename = Path(item["name"].replace("\\", "/")).name
            item["closure_hosts"] = authorities[basename]

    grouped: dict[str, dict[str, dict]] = {}
    units: list[dict] = []
    for item in payloads:
        info = _stage_file_info(item["name"])
        if not info:
            units.append({"kind": "single", "sort": item["name"], "item": item})
            continue
        base, stage = info
        grouped.setdefault(base, {})[stage] = item
    for base, stages in grouped.items():
        if len(stages) >= 2:
            units.append({"kind": "bundle", "sort": base, "base": base, "stages": stages})
        else:
            only = next(iter(stages.values()))
            units.append({"kind": "single", "sort": only["name"], "item": only})

    total = _zero_counts()
    imported = []
    failed = []
    for unit in sorted(units, key=lambda u: str(u["sort"]).lower()):
        try:
            if unit["kind"] == "bundle":
                result = _import_stage_bundle(db, user, unit["base"], unit["stages"])
            else:
                item = unit["item"]
                if "closure_hosts" in item:
                    result = _import_single_xml(
                        db, user, item["name"], item["bytes"], item["closure_hosts"],
                    )
                else:
                    result = _import_single_xml(db, user, item["name"], item["bytes"])
            imported.append(result)
            _add_counts(total, result["counts"])
        except _InvalidImportXML as e:
            failed.append({"name": str(unit["sort"]), "error": str(e)})
            record(db, user, "SCAN_IMPORT", target=str(unit["sort"]), detail="실패", ok=False)
        except Exception:
            logger.exception("failed to import XML bundle unit")
            failed.append({"name": str(unit["sort"]), "error": "XML 가져오기에 실패했습니다."})
            record(db, user, "SCAN_IMPORT", target=str(unit["sort"]), detail="실패", ok=False)
    if not imported and failed:
        raise HTTPException(status_code=400, detail=f"XML 파싱 실패: {failed[0]['error']}")
    return {
        "imported": len(imported),
        "failed": len(failed),
        "file_count": len(payloads),
        "counts": total,
        "scans": imported,
        "errors": failed,
        "closure_mode": "manifest" if authorities is not None else "observed-host",
    }


@router.post("/run", response_model=ScanOut)
def run_scan(
    body: ScanRunIn,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    """백그라운드 청킹 스캔 시작 — 대역을 배치로 쪼개 순차 실행. 즉시 ScanRun(running) 반환.

    배치 단위라 진행 중 [중지]→다음날 [이어하기]가 native --resume 없이 견고하게 동작한다.
    """
    try:
        requested_hosts, excludes = _validate_structured_scan(body, uses_manual_preset=True)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        # Authorization applies to the original requested expansion. Exclusions must not turn
        # an out-of-scope request into an allowed one.
        scope.check_scope(requested_hosts)
        hosts = _effective_hosts(requested_hosts, excludes)
        batches = chunker.make_batches(hosts, body.batch_size)
        exclude_ports = scan_options.validate_ports(body.exclude_ports or "")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    nmap = nmap_runner.find_nmap(_settings.nmap_path)
    if not nmap:
        raise HTTPException(status_code=400, detail="서버에서 nmap 을 찾을 수 없습니다.")
    try:
        # 옵션/프리셋·포트·NSE 사전 검증(첫 배치로) — 잘못된 입력은 시작 전에 거절.
        if body.workflow == "auto":
            tcp_spec = nmap_runner.auto_tcp_port_spec(body.ports)
            udp_spec = nmap_runner.auto_udp_port_spec(body.ports)
            if not tcp_spec and not udp_spec:
                raise ValueError("자동 스캔에 사용할 TCP 또는 UDP 포트가 없습니다.")
            if tcp_spec:
                argv0 = nmap_runner.build_auto_command(nmap, "tcp_discovery", batches[0], _basename(0), ports=body.ports, nse=body.nse)
            else:
                argv0 = nmap_runner.build_auto_command(nmap, "udp_identify", batches[0], _basename(0), ports=body.ports, nse=body.nse)
        elif body.options:
            argv0 = nmap_runner.build_command_opts(nmap, body.options, body.ports, batches[0], _basename(0), nse=body.nse)
        else:
            argv0 = nmap_runner.build_command(
                nmap, body.preset, batches[0], _basename(0), ports=body.ports, nse=body.nse,
            )
        argv0 = _with_nmap_excludes(argv0, excludes, exclude_ports)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan = ScanRun(name=body.name or "스캔", targets=" ".join(body.targets),
                   status="running", created_by=user.id)
    db.add(scan)
    db.commit()
    base = _basename(scan.id)
    launch_paths = [chunker.sidecar_path(base), chunker.stop_path(base)]
    try:
        chunker.clear_stop(base)
        chunker.write_state(base, {
            "batches": batches, "cursor": 0, "stop": False, "active_seconds": 0,
            "workflow": body.workflow, "options": body.options, "ports": body.ports,
            "preset": body.preset, "nse": body.nse,
            "exclude": excludes,
            "exclude_ports": exclude_ports,
            "udp_all_targets": body.udp_all_targets,
        })
        # 명령 표기는 대표(타겟·-oA 제외) — 호스트 수/배치 수를 덧붙여 가독.
        if body.workflow == "auto":
            stages = []
            if nmap_runner.auto_tcp_port_spec(body.ports):
                stages.extend([AUTO_STAGE_LABELS["tcp_discovery"], AUTO_STAGE_LABELS["tcp_identify"]])
            if nmap_runner.auto_udp_port_spec(body.ports):
                label = AUTO_STAGE_LABELS["udp_identify"]
                if body.udp_all_targets:
                    label += "(전체 타깃)"
                stages.append(label)
            scan.command = f"자동 스캔 · {' → '.join(stages)}  ·  {len(hosts)}호스트 / {len(batches)}배치"
        else:
            parts, skip = [], False
            for t in argv0:
                if skip:
                    skip = False
                    continue
                if t == "-oA":
                    skip = True
                    continue
                if t in batches[0]:
                    continue
                parts.append(t)
            scan.command = f"{' '.join(parts)}  ·  {len(hosts)}호스트 / {len(batches)}배치"
        if excludes:
            scan.command += f"  ·  제외 {', '.join(excludes)}"
        db.commit()
        db.refresh(scan)
        threading.Thread(target=_chunk_worker, args=(scan.id,), daemon=True).start()
    except Exception:
        _fail_launch_setup(db, scan.id, user, scan.targets, launch_paths)
    record(db, user, "SCAN_RUN", target=scan.targets,
           detail=f"#{scan.id} · {len(hosts)}호스트 / {len(batches)}배치")
    return scan


@router.post("/run-command", response_model=ScanOut)
def run_command(
    body: RawCommandIn,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    """직접 입력한 nmap 명령으로 스캔(고급) — 단발 실행. 출력 플래그는 서버가 -oA 로 강제 교체,
    셸 메타문자 차단, IP 타겟은 scope 검사. 청킹/이어가기는 미지원(중지만 가능)."""
    nmap = nmap_runner.find_nmap(_settings.nmap_path)
    if not nmap:
        raise HTTPException(status_code=400, detail="서버에서 nmap 을 찾을 수 없습니다.")
    try:
        toks = nmap_runner.parse_raw_command(body.command)   # 셸메타 차단 + 토큰화
        # scope 설정 시: 파일/랜덤 타겟(-iL/-iR) 차단, IP/CIDR 타겟 필수·전부 in-scope.
        # (호스트명만 있는 명령은 검증 불가라 거절 — /run 과 동일한 엄격성)
        scope.check_raw_scope(toks)
        argv, ip_tokens = nmap_runner.build_command_raw(nmap, body.command, _basename(0))
        # 구조화 제외 대상도 직접 명령에 적용한다. 예전에는 이 경로만 제외를 버려서, 폼에 제외를
        # 입력한 뒤 '명령 직접 입력'으로 바꾸면 제외가 조용히 사라졌다.
        argv = _merge_raw_excludes(argv, body.exclude)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan = ScanRun(name=body.name or "직접 명령 스캔", targets=" ".join(ip_tokens) or body.command.strip()[:64],
                   command=body.command.strip(), status="running", created_by=user.id)
    db.add(scan)
    db.commit()
    base = _basename(scan.id)
    argv[-1] = str(base)  # build_command_raw appends the managed -oA basename last.
    launch_paths = [chunker.sidecar_path(base), chunker.stop_path(base)]
    try:
        chunker.clear_stop(base)
        chunker.write_state(base, {"raw_argv": argv, "stop": False})
        db.refresh(scan)
        threading.Thread(target=_command_worker, args=(scan.id,), daemon=True).start()
    except Exception:
        _fail_launch_setup(db, scan.id, user, scan.targets, launch_paths)
    record(db, user, "SCAN_RUN", target=scan.targets,
           detail=f"#{scan.id} 직접명령: {body.command.strip()[:160]}")
    return scan


@router.post("/run-staged", response_model=ScanOut)
def run_staged(
    body: ScanRunIn,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    """단계분리 엔진 스캔 시작 — 발견→TCP→UDP→서비스 probe 를 별도 엔진이 단계로 실행.

    즉시 ScanRun(running) 반환. 진행은 GET /{id}/stages(이벤트 기반 단계 타임라인),
    중지/이어가기는 기존 /stop·/resume 이 run-state 플래그로 처리한다.
    """
    try:
        requested_hosts, excludes = _validate_structured_scan(body, uses_manual_preset=False)
        _validate_staged_protocol_selection(body)
        scope.check_scope(requested_hosts)
        hosts = _effective_hosts(requested_hosts, excludes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        engine_runner.ensure_available()
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    if not nmap_runner.find_nmap(_settings.nmap_path):
        raise HTTPException(status_code=400, detail="서버에서 nmap 을 찾을 수 없습니다.")

    scan = ScanRun(name=body.name or "단계 스캔", targets=" ".join(body.targets),
                   status="running", created_by=user.id)
    db.add(scan)
    db.commit()
    out_dir = _settings.scans_dir / f"scan_{scan.id}"
    launch_paths = [
        out_dir / "spec.json", out_dir / "run-state.json", out_dir / "stop-requested",
    ]
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        spec = engine_runner.build_job_spec(
            scan.id, hosts if body.discovery == "pn" else body.targets,
            excludes, body.options, body.ports,
            body.nse, out_dir, body.batch_size, discovery=body.discovery,
        )
        tcp_scope = _port_scope(nmap_runner.auto_tcp_port_spec(body.ports), "T")
        udp_scope = (_port_scope(nmap_runner.auto_udp_port_spec(body.ports), "U")
                     if "udp" in body.options else set())
        spec["scanops"] = {
            # Empty is meaningful: this scan must not close any pre-existing finding.
            "scope_keys": sorted(_auto_scope_keys(db, set(hosts), [], tcp_scope, udp_scope)),
        }
        (out_dir / "spec.json").write_text(json.dumps(spec, ensure_ascii=False), encoding="utf-8")
        scan.command = f"{engine_runner.describe(spec)}  ·  {len(hosts)}호스트"
        if excludes:
            scan.command += f"  ·  제외 {', '.join(excludes)}"
        db.commit()
        db.refresh(scan)
        threading.Thread(target=_engine_worker, args=(scan.id,), daemon=True).start()
    except Exception:
        _fail_launch_setup(
            db, scan.id, user, scan.targets, launch_paths, artifact_dirs=[out_dir],
        )
    record(db, user, "SCAN_RUN", target=scan.targets, detail=f"#{scan.id} 단계스캔 · {len(hosts)}호스트")
    return scan


@router.post("/{scan_id}/stop", response_model=ScanOut)
def stop_scan(
    scan_id: int,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    """스캔 중지 — 다음 배치를 안 띄우고, 진행 중 배치는 종료(미완 배치는 이어가기 때 재실행)."""
    scan = db.get(ScanRun, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="스캔을 찾을 수 없습니다.")
    if scan.status not in ("running", "canceling"):
        raise HTTPException(status_code=400, detail="실행 중인 스캔이 아닙니다.")
    base = _basename(scan_id)
    state = chunker.read_state(base)
    if state is not None:
        chunker.request_stop(base)
        state["stop"] = True
        chunker.write_state(base, state)
    # 엔진 스캔이면 run-state 에 graceful stop 플래그(엔진이 단계/호스트 경계에서 감지). 무해.
    engine_runner.signal_stop(_settings.scans_dir / f"scan_{scan_id}")
    scan.status = "canceling"   # 워커가 배치 종료를 감지하면 canceled 로 확정
    db.commit()
    with _LOCK:
        proc = _PROCS.get(scan_id)
    if proc is not None:
        proc.terminate()        # 현재 배치 즉시 중단(그 배치는 버려지고 커서 유지)
    db.refresh(scan)
    record(db, user, "SCAN_STOP", target=scan.targets, detail=f"#{scan.id}")
    return scan


@router.post("/{scan_id}/resume", response_model=ScanOut)
def resume_scan(
    scan_id: int,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    """중단된 스캔 재개 — 청킹 스캔은 다음 미완 배치부터, 직접 명령 스캔은 전체 재실행(단발)."""
    scan = db.get(ScanRun, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="스캔을 찾을 수 없습니다.")
    with _LOCK:
        already = scan_id in _PROCS
    if already or scan.status in ("running", "canceling"):
        raise HTTPException(status_code=400, detail="이미 실행 중인 스캔입니다.")
    # 엔진 스캔 이어가기 — run-state 의 완료 단계·호스트를 건너뛰고 재실행(엔진이 알아서 재개).
    out_dir = _settings.scans_dir / f"scan_{scan_id}"
    if engine_runner.is_engine_scan(out_dir):
        completed_output = engine_runner.is_done(out_dir)
        finalize_completed = (
            completed_output
            and scan.status in {"failed", "interrupted"}
            and scan.failure_code in _RECOVERABLE_COMPLETED_ENGINE_FAILURES
        )
        if completed_output and not finalize_completed:
            raise HTTPException(status_code=400, detail="이미 모든 단계가 완료되었습니다.")
        recovery_failure_code = scan.failure_code if finalize_completed else "launch_setup_failed"
        try:
            saved_spec = _load_engine_spec(out_dir / "spec.json")
            saved_targets = list(saved_spec.get("targets") or [])
            saved_excludes = saved_spec.get("exclude") or []
            saved_targets.extend((saved_spec.get("targets_ports") or {}).keys())
            saved_targets.extend(str(unit.get("ip") or "")
                                 for unit in (saved_spec.get("rescan_units") or []))
        except (OSError, ValueError, json.JSONDecodeError):
            raise HTTPException(
                status_code=400,
                detail=_FAILURE_MESSAGES["engine_spec_invalid"],
            )
        try:
            saved_targets = [target for target in saved_targets if target]
            nmap_runner.validate_targets(saved_targets)
            scope.check_scope(saved_targets)
            nmap_runner.validate_targets(saved_excludes)
            scope.parse_excludes(saved_excludes)
            stages = saved_spec.get("stages") or {}
            if not isinstance(stages, dict):
                raise ValueError("저장된 단계 스캔 설정이 잘못되었습니다.")
            for stage_name in ("tcp", "udp"):
                stage = stages.get(stage_name) or {}
                if not isinstance(stage, dict):
                    raise ValueError("저장된 단계 스캔 설정이 잘못되었습니다.")
                scan_options.validate_ports(str(stage.get("ports") or ""))
            _validate_engine_scope_keys(saved_spec)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        if not finalize_completed:
            if not nmap_runner.find_nmap(_settings.nmap_path):
                raise HTTPException(status_code=400, detail="서버에서 nmap 을 찾을 수 없습니다.")
            try:
                engine_runner.ensure_available()
            except RuntimeError as e:
                raise HTTPException(status_code=503, detail=str(e))
        try:
            engine_runner.clear_stop(out_dir)
            scan.status = "running"
            scan.finished_at = None
            scan.failure_code = ""
            scan.failure_message = ""
            db.commit()
            db.refresh(scan)
            worker = _finalize_completed_engine_worker if finalize_completed else _engine_worker
            threading.Thread(target=worker, args=(scan_id,), daemon=True).start()
        except Exception:
            _fail_launch_setup(
                db, scan.id, user, scan.targets, [], audit_action="SCAN_RESUME",
                failure_code=recovery_failure_code,
            )
        record(db, user, "SCAN_RESUME", target=scan.targets, detail=f"#{scan.id} 엔진 이어가기")
        return scan
    base = _basename(scan_id)
    state = chunker.read_state(base)
    if state is None:
        raise HTTPException(status_code=400, detail="이어갈 스캔 상태가 없습니다(이전 버전 스캔).")
    try:
        if "batches" in state:
            saved_targets = [host for batch in state.get("batches", []) for host in batch]
            nmap_runner.validate_targets(saved_targets)
            scope.check_scope(saved_targets)
            saved_excludes = state.get("exclude") or []
            nmap_runner.validate_targets(saved_excludes)
            saved_excludes = scope.parse_excludes(saved_excludes)
            if scope.apply_excludes(saved_targets, saved_excludes) != saved_targets:
                raise ValueError(
                    "저장된 스캔 상태에 제외 대상이 배치로 다시 포함되어 있습니다."
                )
            scan_options.validate_keys(state.get("options") or [])
            scan_options.validate_nse(state.get("nse"))
            scan_options.validate_ports(state.get("ports") or "")
        elif "raw_argv" in state:
            scope.check_raw_scope(list(state.get("raw_argv") or [])[1:])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not nmap_runner.find_nmap(_settings.nmap_path):
        raise HTTPException(status_code=400, detail="서버에서 nmap 을 찾을 수 없습니다.")

    # 직접 명령 스캔(raw_argv): 청킹/커서가 없으므로 전체를 다시 실행한다(단발).
    if "batches" not in state:
        if "raw_argv" not in state:
            raise HTTPException(status_code=400, detail="이어가기를 지원하지 않는 스캔입니다.")
        try:
            state["stop"] = False
            chunker.clear_stop(base)
            chunker.write_state(base, state)
            scan.status = "running"
            scan.finished_at = None
            scan.failure_code = ""
            scan.failure_message = ""
            db.commit()
            db.refresh(scan)
            threading.Thread(target=_command_worker, args=(scan_id,), daemon=True).start()
        except Exception:
            _fail_launch_setup(
                db, scan.id, user, scan.targets, [], audit_action="SCAN_RESUME",
            )
        record(db, user, "SCAN_RESUME", target=scan.targets, detail=f"#{scan.id} 직접명령 재실행")
        return scan

    if state.get("cursor", 0) >= len(state["batches"]):
        raise HTTPException(status_code=400, detail="이미 모든 배치가 완료되었습니다.")
    try:
        state["stop"] = False
        chunker.clear_stop(base)
        chunker.write_state(base, state)
        scan.status = "running"
        scan.finished_at = None
        scan.failure_code = ""
        scan.failure_message = ""
        db.commit()
        db.refresh(scan)
        threading.Thread(target=_chunk_worker, args=(scan_id,), daemon=True).start()
    except Exception:
        _fail_launch_setup(
            db, scan.id, user, scan.targets, [], audit_action="SCAN_RESUME",
        )
    record(db, user, "SCAN_RESUME", target=scan.targets,
           detail=f"#{scan.id} · 배치 {state.get('cursor', 0)}부터")
    return scan


@router.get("/{scan_id}/progress")
def scan_progress(scan_id: int, _: User = Depends(current_user), db: Session = Depends(get_db)):
    """실시간 진행률 — 배치 진행(완료/전체) + 현재 배치 nmap percent/ETC/경과 → 전체 percent."""
    scan = db.get(ScanRun, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="스캔을 찾을 수 없습니다.")
    log_path = Path(scan.log_path) if scan.log_path else _basename(scan_id)
    prog = nmap_runner.parse_progress(log_path)   # 현재 배치의 percent/ETC/경과
    state = chunker.read_state(_basename(scan_id))
    has_batches = bool(state) and "batches" in state
    total = len(state["batches"]) if has_batches else 1
    done = state.get("cursor", 0) if has_batches else (1 if scan.status == "done" else 0)
    in_batch = (prog["percent"] or 0) / 100.0
    if scan.status == "done":
        overall = 100.0
    elif total:
        overall = round(min(done + in_batch, total) / total * 100, 1)
    else:
        overall = None
    # 라이브 ETA — 끝난 배치들의 실제 누적시간으로 남은 배치 외삽(같은 옵션·망이라 정확).
    eta = None
    active = state.get("active_seconds", 0) if state else 0
    if scan.status == "running" and done >= 1 and active > 0 and total:
        avg = active / done
        eta = max(0, round(avg * (total - done - in_batch)))
    prog.update({
        "scan_id": scan.id,
        "status": scan.status,
        "host_count": scan.host_count,
        "port_count": scan.port_count,
        "finished_at": scan.finished_at,
        "batches_total": total,
        "batches_done": done,
        "overall_percent": overall,
        "eta_seconds": eta,
    })
    return prog


@router.get("/{scan_id}/stages")
def scan_stages(scan_id: int, _: User = Depends(current_user), db: Session = Depends(get_db)):
    """단계분리 엔진 스캔의 단계 타임라인 — events.ndjson 에서 라이브 derive(없으면 영속 stages_json)."""
    scan = db.get(ScanRun, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="스캔을 찾을 수 없습니다.")
    out_dir = _settings.scans_dir / f"scan_{scan_id}"
    derived = engine_runner.parse_events(out_dir)
    stages = derived["stages"] or (scan.stages_json or [])
    overall = dict(derived["overall"])
    # The database lifecycle is authoritative. An empty/truncated event stream must not make a
    # terminal scan look like it is still running after a restart or worker failure.
    overall["status"] = scan.status
    return {
        "scan_id": scan_id,
        "status": scan.status,
        "kind": "staged" if engine_runner.is_engine_scan(out_dir) else "legacy_or_import",
        "timeline_available": bool(stages),
        "stages": stages,
        "overall": overall,
        "failure_code": scan.failure_code,
        "failure_message": scan.failure_message,
        "host_count": scan.host_count,
        "port_count": scan.port_count,
        "finished_at": scan.finished_at,
    }


@router.post("/estimate")
def estimate_scan(body: ScanRunIn, _: User = Depends(current_user), db: Session = Depends(get_db)):
    """실행 전 예상 — 타겟을 호스트/배치 수로, 그리고 '동일 설정' 과거 스캔이 있으면
    호스트당 평균시간(중앙값)으로 대략적 소요시간을 낸다. 없으면 basis='none'."""
    # 예상치는 정보 제공용(실제 nmap 미실행)이라 scope 를 강제하지 않는다 — 입력 중 호스트명에
    # 매 키 입력마다 400 이 뜨던 회귀 방지. scope 차단은 실제 실행(run/run-command)에서만.
    try:
        requested_hosts, excludes = _validate_structured_scan(body, uses_manual_preset=True)
        if body.staged:
            _validate_staged_protocol_selection(body)
        hosts = _effective_hosts(requested_hosts, excludes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    host_count = len(hosts)
    size = body.batch_size
    batch_count = (host_count + size - 1) // size if host_count else 0

    want = _estimate_profile(body)
    rates: list[float] = []
    for s in db.query(ScanRun).filter(ScanRun.status == "done").order_by(ScanRun.id.desc()).limit(50):
        st = chunker.read_state(_basename(s.id))
        if not st:
            continue
        if (("auto", (st.get("ports", "") or "").replace(" ", "")) if st.get("workflow") == "auto"
                else _profile(st.get("options") or [], st.get("ports", ""), st.get("preset", "quick"))) != want:
            continue
        nh = sum(len(b) for b in st.get("batches", []))
        sec = st.get("active_seconds", 0)
        if nh > 0 and sec > 0:
            rates.append(sec / nh)
    rates.sort()
    sec_per_host = round(rates[len(rates) // 2], 3) if rates else None   # 중앙값
    est = round(sec_per_host * host_count) if (sec_per_host and host_count) else None
    return {
        "host_count": host_count,
        "batch_count": batch_count,
        "exclude": excludes,
        "basis": "history" if rates else "none",
        "sample_count": len(rates),
        "sec_per_host": sec_per_host,
        "est_seconds": est,
    }
