"""스캔 라우터 — nmap 실행(백그라운드) / 오프라인 XML 가져오기 → finding 인입.

스캔은 HTTP 요청을 막지 않도록 백그라운드 스레드에서 돈다. 요청은 즉시 ScanRun 을
돌려주고, 프론트는 GET /{id}/progress 로 진행률을, POST /{id}/stop 으로 중지를,
POST /{id}/resume 로 이어가기를 호출한다. (status: running/done/failed/canceling/canceled)
"""
from __future__ import annotations

import json
import re
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import SessionLocal, get_db
from ..models import Finding, ScanRun, User
from ..schemas import IngestSummary, RawCommandIn, ScanOut, ScanRunIn
from ..scanning import chunker, engine_runner, nmap_runner, scan_options, scope, taxonomy
from ..scanning.ingest import ingest
from ..scanning.nmap_parse import parse_xml, scan_start, up_hosts
from .audit import record
from .deps import current_user, require_role

router = APIRouter()
_settings = get_settings()

# 실행 중인(현재 배치) nmap 프로세스 레지스트리(scan_id -> Popen). 중지 버튼이 여기서 찾아 종료.
# 서버 메모리에만 존재 — 재시작 시 비지만, 배치 진행상태는 사이드카 JSON 에 영속되므로
# 이어가기는 가능(다음 배치부터). 청킹이 native --resume(Windows 깨짐)을 대체한다.
_PROCS: dict = {}
_LOCK = threading.Lock()
# 사이드카 상태(state.json)의 read-modify-write 직렬화 — 워커의 커서 전진과 stop_scan 의 stop 쓰기가
# 겹치면, 워커가 stale in-memory state 로 전체를 덮어써 stop 플래그를 지워버린다(중지 유실). 이 락으로
# 두 경로의 RMW 를 직렬화해 lost-update 를 막는다.
_STATE_LOCK = threading.Lock()
AUTO_STAGE_LABELS = {
    "tcp_discovery": "TCP 전체 포트 발견",
    "tcp_identify": "발견된 TCP 포트 용도/서비스 식별",
    "udp_identify": "주요 UDP 서비스 식별",
}
STAGE_FILE_RE = re.compile(r"^(?P<base>.+)\.(?P<stage>tcp_discovery|tcp_identify|udp_identify)\.xml$", re.I)


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


def reconcile_orphans() -> int:
    """서버 부팅 시 호출 — 워커가 사라져 고아가 된 실행(running/canceling)을 interrupted 로 정직하게
    표기한다. 자동 복구는 하지 않는다(이어하기는 사용자가 수동으로). 좀비 '실행 중' 박제를 막는 게 목적.
    반환: 정리된 건수."""
    db = SessionLocal()
    try:
        orphans = db.query(ScanRun).filter(ScanRun.status.in_(("running", "canceling"))).all()
        for scan in orphans:
            scan.status = "interrupted"
            scan.error = "서버 재시작으로 워커가 사라져 중단됨 — [이어하기]로 재개하세요."
            if scan.finished_at is None:
                scan.finished_at = datetime.now(timezone.utc)
        if orphans:
            db.commit()
        return len(orphans)
    finally:
        db.close()


class ScanFailed(Exception):
    """스캔 실패 + 사람이 읽을 원인. 워커가 잡아 ScanRun.error 에 남긴다(추적성)."""
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# nmap 오류/경고 신호어 — 로그 꼬리에서 이 줄들을 우선 뽑아 원인으로 삼는다.
_NMAP_ERR_HINTS = (
    "QUITTING", "ERROR", "Error", "error", "WARNING", "Warning", "Failed", "failed",
    "cannot", "Cannot", "denied", "Permission", "permission", "requires", "privileg",
    "not permitted", "No route", "unreachable", "Unable", "Invalid", "invalid",
)


def _log_tail(path: Path, max_chars: int = 4000) -> str:
    """로그 파일 꼬리에서 원인 후보 줄을 뽑는다 — nmap stderr(오류/경고) 우선, 없으면 마지막 줄들."""
    try:
        data = path.read_bytes()[-max_chars:].decode("utf-8", "replace")
    except OSError:
        return ""
    lines = [ln.strip() for ln in data.splitlines() if ln.strip()]
    if not lines:
        return ""
    hits = [ln for ln in lines if any(h in ln for h in _NMAP_ERR_HINTS)]
    picked = hits[-4:] if hits else lines[-3:]
    return " / ".join(picked)[:800]


def _stage_reason(stage: str, rc: int, log_path: Path) -> str:
    """단계 실패 원인 문자열 — 단계명 + nmap 종료코드 + 로그 꼬리(있으면)."""
    tail = _log_tail(log_path)
    head = f"{stage} 단계 실패 — nmap 종료코드 {rc}"
    return f"{head}. {tail}" if tail else f"{head} (로그 출력 없음 — nmap 실행 경로/권한 확인)"


def _mark(scan_id: int, status: str, error: str = "") -> None:
    """종료 상태 확정(done/failed/canceled) — finished_at + 실패 원인(error) 기록.
    성공/취소 등 error 미전달 시 기존 원인을 비운다(재시도·이어가기 후 잔재 방지)."""
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        if scan is not None:
            scan.status = status
            scan.error = (error or "")[:2000]
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


def _advance_cursor(base: Path, st: dict, cursor: int, dt: float) -> bool:
    """배치 완료 후 커서 전진. 사이드카를 fresh 로 다시 읽어(stale 덮어쓰기 방지) 그 사이 stop 이
    들어왔으면 전진하지 않고 False 반환(→ 호출자가 canceled 처리). _STATE_LOCK 으로 stop_scan 의
    stop 쓰기와 직렬화 → 중지 유실(lost-update) 방지. read 실패 시에만 워커의 st 로 폴백."""
    with _STATE_LOCK:
        fresh = chunker.read_state(base) or st
        if fresh.get("stop"):
            return False
        fresh["cursor"] = cursor + 1
        fresh["active_seconds"] = round(fresh.get("active_seconds", 0) + dt, 1)
        chunker.write_state(base, fresh)
        return True


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
    if any(t == "1-65535" for t in tokens):
        return None
    ports: set[int] = set()
    for token in tokens:
        if "-" in token:
            lo, hi = token.split("-", 1)
            try:
                start, end = int(lo), int(hi)
            except ValueError:
                continue
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
    rows = db.query(Finding).filter(Finding.state == "open", Finding.host_ip.in_(scanned_hosts)).all()
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
        by_key.setdefault(_finding_key(f), f)
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
    by_host: dict[str, dict[str, list]] = {}
    seen = {_finding_key(f) for f in findings}
    for f in findings:
        by_host.setdefault(f["host_ip"], {"open": [], "closed": []})["open"].append(f)

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
                   scan_date: datetime | None = None, raw_xml_path: Path | None = None) -> dict:
    enriched = taxonomy.enrich_all(db, findings)
    scope_keys = _auto_scope_keys(db, scanned_hosts, enriched, tcp_scope, udp_scope)
    if raw_xml_path is not None:
        _write_merged_xml(db, raw_xml_path, enriched, scanned_hosts, scope_keys, scan_date)
        scan.raw_xml_path = str(raw_xml_path)
    counts = ingest(db, scan.id, enriched, scanned_hosts, scope_keys=scope_keys, scan_date=scan_date)
    from .assets import match_assets
    match_assets(db)
    scan.host_count = len({f["host_ip"] for f in enriched})
    scan.port_count = len(enriched)
    scan.status = "done"
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()
    return counts


def _ingest_batch(scan_id: int, xml_bytes: bytes, no_close: bool = False) -> None:
    """배치 XML 1개 인입 — job scan_id 에 귀속, host/port 카운트 누적(상태는 안 바꿈).
    닫힘 판정은 ingest 내부에서 '이번 배치가 스캔한 호스트'로만 한정되므로 다른 배치 안전.
    no_close=True 면 닫힘 판정을 끈다(직접 명령처럼 스캔한 포트 범위를 알 수 없을 때 — 가산만)."""
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        findings = taxonomy.enrich_all(db, parse_xml(xml_bytes))
        # no_close: scope_keys=set() → 닫힘 패스가 어떤 포트도 닫지 않음(미스캔 포트 오closure 방지).
        ingest(db, scan_id, findings, up_hosts(xml_bytes), scope_keys=set() if no_close else None)
        from .assets import match_assets
        match_assets(db)
        scan.host_count = (scan.host_count or 0) + len({f["host_ip"] for f in findings})
        scan.port_count = (scan.port_count or 0) + len(findings)
        db.commit()
    finally:
        db.close()


def _ingest_auto_findings(scan_id: int, findings: list[dict], scanned_hosts: set[str],
                          tcp_scope: set[int] | None | set, udp_scope: set[int] | None | set) -> None:
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        if scan is None:
            return
        enriched = taxonomy.enrich_all(db, findings)
        scope_keys = _auto_scope_keys(db, scanned_hosts, enriched, tcp_scope, udp_scope)
        ingest(db, scan_id, enriched, scanned_hosts, scope_keys=scope_keys)
        from .assets import match_assets
        match_assets(db)
        scan.host_count = (scan.host_count or 0) + len({f["host_ip"] for f in enriched})
        scan.port_count = (scan.port_count or 0) + len(enriched)
        db.commit()
    finally:
        db.close()


def _register_proc(scan_id: int, proc) -> None:
    """한 스캔이 동시에 여러 nmap 프로세스를 띄울 수 있다(예: tcp_identify ∥ udp_identify).
    중지 버튼이 그 스캔의 모든 프로세스를 찾아 종료하도록 set 으로 모은다."""
    with _LOCK:
        _PROCS.setdefault(scan_id, set()).add(proc)


def _unregister_proc(scan_id: int, proc) -> None:
    with _LOCK:
        procs = _PROCS.get(scan_id)
        if procs is not None:
            procs.discard(proc)
            if not procs:
                _PROCS.pop(scan_id, None)


def _run_stage(scan_id: int, argv: list[str], log_path: Path, set_current: bool = True) -> int:
    # 병렬 단계에선 set_current=False 로 두고 호출자가 대표 로그를 한 번만 지정한다
    # (동시 두 단계가 log_path 를 서로 덮어쓰는 경합 방지).
    if set_current:
        _set_current_log(scan_id, log_path)
    try:
        proc = nmap_runner.popen(argv, log_path)
    except OSError:
        return -1
    _register_proc(scan_id, proc)
    rc = proc.wait()
    _unregister_proc(scan_id, proc)
    return rc


def _run_identify_parallel(scan_id: int, tasks: list[tuple]) -> dict:
    """발견 이후의 식별 단계들을 동시에 돌린다 — tcp_identify 와 udp_identify 는 둘 다 발견 결과에만
    의존하고 서로 독립적이라 병렬 가능. UDP 는 지연(ICMP rate-limit 대기) 위주라 부하 증가는 미미하고,
    그 대기가 TCP 식별과 겹쳐 벽시계 시간이 준다.

    tasks: (label, base, log, argv) 목록. 반환: {label: (rc, base, log)}.
    단계별 산출물(base.xml)·로그(log)가 파일로 분리돼 있어 동시 실행해도 서로 안 섞인다."""
    results: dict = {}

    def _one(label: str, base: Path, log: Path, argv: list[str]) -> None:
        results[label] = (_run_stage(scan_id, argv, log, set_current=False), base, log)

    if len(tasks) == 1:
        _one(*tasks[0])
    else:
        threads = [threading.Thread(target=_one, args=t, daemon=True) for t in tasks]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
    return results


def _run_auto_batch(scan_id: int, nmap: str, batch: list[str], b_base: Path, state: dict) -> bool:
    """Run discovery, then tcp_identify ∥ udp_identify (parallel), then ingest observations once."""
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
    tcp_ports: list[int] = []
    # identify 단계는 discovery 에서 살아난 호스트로만 좁힌다(죽은 IP 재스캔·PTR 폭증 방지).
    # discovery 를 안 돌린 UDP-only 경우엔 비어 있어 배치 전체로 폴백.
    discovery_live: list[str] = []

    if tcp_port_spec:
        if (chunker.read_state(_basename(scan_id)) or state).get("stop"):
            return False
        discovery_base = Path(str(b_base) + ".tcp_discovery")
        discovery_log = Path(str(discovery_base) + ".log")
        argv = nmap_runner.build_auto_command(nmap, "tcp_discovery", batch, discovery_base, ports=ports, nse=nse)
        rc = _run_stage(scan_id, argv, discovery_log)
        if (chunker.read_state(_basename(scan_id)) or state).get("stop"):
            return False   # 중지로 종료된 nmap → 실패 아님(취소)
        if rc != 0:
            raise ScanFailed(_stage_reason("TCP 발견", rc, discovery_log))
        discovery_xml = nmap_runner.xml_of(discovery_base)
        if not discovery_xml.exists():
            raise ScanFailed("TCP 발견 단계: nmap XML 산출물이 없습니다. " + (_log_tail(discovery_log) or "(로그 없음)"))
        discovery_live = sorted(up_hosts(discovery_xml))
        scanned_hosts |= set(discovery_live)
        tcp_discovery_findings = parse_xml(discovery_xml)
        tcp_ports = nmap_runner.open_ports_from_xml(discovery_xml, "tcp")

    # ── 식별 단계 구성 ── tcp_identify(열린 TCP 서비스/버전) 와 udp_identify(주요 UDP) 는
    # 둘 다 '발견 결과'에만 의존하고 서로 독립적 → 병렬 실행(UDP 지연이 TCP 식별과 겹쳐 시간 절약).
    # UDP 스킵 규칙: discovery 를 돌렸는데 생존 0이면 죽은 대역 -Pn UDP 낭비 방지로 제외.
    # udp_all_targets(opt-in)면 discovery 무관 배치 전체로.
    tasks: list[tuple] = []
    if tcp_port_spec and tcp_ports:
        tcp_identify_base = Path(str(b_base) + ".tcp_identify")
        argv_tcp = nmap_runner.build_auto_command(nmap, "tcp_identify", discovery_live or batch, tcp_identify_base, ports=ports, tcp_ports=tcp_ports, nse=nse)
        tasks.append(("tcp_identify", tcp_identify_base, Path(str(tcp_identify_base) + ".log"), argv_tcp))
    if udp_port_spec and (udp_all_targets or not tcp_port_spec or discovery_live):
        udp_base = Path(str(b_base) + ".udp_identify")
        udp_targets = batch if udp_all_targets else (discovery_live or batch)
        argv_udp = nmap_runner.build_auto_command(nmap, "udp_identify", udp_targets, udp_base, ports=ports, nse=nse)
        tasks.append(("udp_identify", udp_base, Path(str(udp_base) + ".log"), argv_udp))

    if tasks:
        if (chunker.read_state(_basename(scan_id)) or state).get("stop"):
            return False
        _set_current_log(scan_id, tasks[-1][2])   # 대표 진행 로그: UDP 있으면 UDP(장기 단계)를 가리켜 라이브 진행 표시
        results = _run_identify_parallel(scan_id, tasks)
        if (chunker.read_state(_basename(scan_id)) or state).get("stop"):
            return False   # 중지로 종료 → 실패 아님(취소)
        # 두 단계 모두 검증(실패한 쪽의 원인을 정확히 남긴다)
        for label, (rc, base, log) in results.items():
            stage_ko = "TCP 식별" if label == "tcp_identify" else "UDP 식별"
            if rc != 0:
                raise ScanFailed(_stage_reason(stage_ko, rc, log))
            if not nmap_runner.xml_of(base).exists():
                raise ScanFailed(f"{stage_ko} 단계: nmap XML 산출물이 없습니다. " + (_log_tail(log) or "(로그 없음)"))
        # 병합: TCP 는 식별본 우선(발견 열린포트 보존), UDP 는 가산.
        if "tcp_identify" in results:
            tcp_xml = nmap_runner.xml_of(results["tcp_identify"][1])
            scanned_hosts |= up_hosts(tcp_xml)
            findings.extend(_prefer_identified(parse_xml(tcp_xml), tcp_discovery_findings))
        if "udp_identify" in results:
            udp_xml = nmap_runner.xml_of(results["udp_identify"][1])
            scanned_hosts |= up_hosts(udp_xml)
            findings.extend(parse_xml(udp_xml))

    # 발견은 돌렸지만 열린 TCP 0 → 식별 스킵. 발견이 본 개방포트(있으면)를 그대로 반영.
    if tcp_port_spec and not tcp_ports:
        findings.extend(tcp_discovery_findings)

    if not tcp_port_spec and not udp_port_spec:
        raise ScanFailed("자동 스캔에 사용할 TCP/UDP 포트가 없습니다.")
    _ingest_auto_findings(scan_id, findings, scanned_hosts, tcp_scope, udp_scope)
    return True


def _chunk_worker(scan_id: int) -> None:
    """배치를 순차 실행. 각 배치: nmap → XML → 인입 → 사이드카 커서 전진.
    중지(stop) 플래그가 보이면 현재 배치를 버리고(커서 유지) canceled 로 멈춘다 →
    이어가기 시 그 배치부터 다시 실행한다."""
    base = _basename(scan_id)
    nmap = nmap_runner.find_nmap(_settings.nmap_path)
    state = chunker.read_state(base)
    if not nmap:
        _mark(scan_id, "failed", "서버에서 nmap 실행 파일을 찾을 수 없습니다. (설치 여부·SCANOPS_NMAP_PATH 확인)")
        return
    if state is None:
        _mark(scan_id, "failed", "스캔 상태 파일을 읽을 수 없습니다 (사이드카 손실).")
        return
    batches = state["batches"]
    while True:
        st = chunker.read_state(base) or state
        if st.get("stop"):
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
            except ScanFailed as e:
                if (chunker.read_state(base) or st).get("stop"):
                    _mark(scan_id, "canceled")
                else:
                    _mark(scan_id, "failed", e.reason)
                return
            except ValueError as e:
                _mark(scan_id, "failed", f"명령 구성 오류: {e}")
                return
            except Exception as e:
                _mark(scan_id, "failed", f"자동 스캔 내부 오류: {type(e).__name__}: {e}")
                return
            if (chunker.read_state(base) or st).get("stop"):
                _mark(scan_id, "canceled")
                return
            if not ok:
                _mark(scan_id, "failed", "자동 스캔 배치가 결과를 내지 못했습니다.")
                return
            dt = (datetime.now(timezone.utc) - t0).total_seconds()
            if not _advance_cursor(base, st, cursor, dt):   # 그 사이 stop 이면 전진 안 함 → canceled
                _mark(scan_id, "canceled")
                return
            continue
        try:
            if st.get("options") or st.get("nse"):
                argv = nmap_runner.build_command_opts(nmap, st.get("options") or [], st.get("ports", ""), batch, b_base, nse=st.get("nse"))
            else:
                argv = nmap_runner.build_command(nmap, st.get("preset", "quick"), batch, b_base)
        except ValueError as e:
            _mark(scan_id, "failed", f"명령 구성 오류: {e}")
            return
        _set_current_log(scan_id, b_log)
        try:
            proc = nmap_runner.popen(argv, b_log)
        except OSError as e:
            _mark(scan_id, "failed", f"nmap 프로세스 실행 실패: {e}")
            return
        _register_proc(scan_id, proc)
        rc = proc.wait()
        _unregister_proc(scan_id, proc)

        # 중지로 종료됐으면 이 배치는 미완 → 커서 유지하고 canceled.
        if (chunker.read_state(base) or st).get("stop"):
            _mark(scan_id, "canceled")
            return
        xml_path = nmap_runner.xml_of(b_base)
        if rc != 0 or not xml_path.exists():
            _mark(scan_id, "failed", _stage_reason("스캔", rc, b_log))
            return
        try:
            _ingest_batch(scan_id, xml_path.read_bytes())
        except Exception as e:
            _mark(scan_id, "failed", f"결과 인입 오류: {type(e).__name__}: {e}")
            return
        # 배치 완료 → 커서 전진 + 실제 스캔 시간 누적(영속). 누적은 멈춤시간 제외 → ETA 정확.
        # 전진 직전 stop 이 들어왔으면(레이스) fresh 로 감지해 커서를 안 밀고 canceled 로 확정.
        dt = (datetime.now(timezone.utc) - t0).total_seconds()
        if not _advance_cursor(base, st, cursor, dt):
            _mark(scan_id, "canceled")
            return


def _command_worker(scan_id: int) -> None:
    """직접 입력 명령 스캔 — 단발 실행(청킹/이어가기 없음). nmap → XML → 인입.
    중지(stop)면 프로세스 종료 후 canceled."""
    base = _basename(scan_id)
    state = chunker.read_state(base) or {}
    argv = state.get("raw_argv")
    if not argv:
        _mark(scan_id, "failed", "직접 명령 인자를 복원할 수 없습니다 (상태 파일 손실).")
        return
    log = Path(str(base) + ".log")
    _set_current_log(scan_id, log)
    if (chunker.read_state(base) or {}).get("stop"):
        _mark(scan_id, "canceled")
        return
    try:
        proc = nmap_runner.popen(argv, log)
    except OSError as e:
        _mark(scan_id, "failed", f"nmap 프로세스 실행 실패: {e}")
        return
    _register_proc(scan_id, proc)
    rc = proc.wait()
    _unregister_proc(scan_id, proc)
    if (chunker.read_state(base) or {}).get("stop"):
        _mark(scan_id, "canceled")
        return
    xml_path = nmap_runner.xml_of(base)
    if rc != 0 or not xml_path.exists():
        _mark(scan_id, "failed", _stage_reason("직접 명령", rc, log))
        return
    try:
        # 직접 명령은 -p 범위가 불투명 → 닫힘 판정을 끄고 가산만(미스캔 포트 오closure 방지).
        _ingest_batch(scan_id, xml_path.read_bytes(), no_close=True)
    except Exception as e:
        _mark(scan_id, "failed", f"결과 인입 오류: {type(e).__name__}: {e}")
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


def _engine_worker(scan_id: int) -> None:
    """단계분리 엔진 실행 — spec.json 으로 엔진 spawn → 대기 → 단계요약 영속 + 결과 인입.

    중지는 run-state.json 의 stop 플래그로(graceful, 단계/호스트 경계). 엔진 프로세스는
    자기 nmap 자식을 관리하므로 ScanOps 가 강제 종료하지 않는다(고아 nmap 방지).
    """
    out_dir = _settings.scans_dir / f"scan_{scan_id}"
    spec_path = out_dir / "spec.json"
    if not spec_path.exists():
        _mark(scan_id, "failed", "엔진 spec.json 파일이 없습니다.")
        return
    # 타겟 재스캔이면 spec 에 scope_keys 가 들어있음 → 닫힘 판정을 그 발견으로만 한정.
    scope_keys = None
    try:
        sk = (json.loads(spec_path.read_text(encoding="utf-8")).get("scanops") or {}).get("scope_keys")
        if sk:
            scope_keys = set(sk)
    except (OSError, ValueError):
        pass
    try:
        proc = engine_runner.spawn(spec_path, out_dir, out_dir / "engine.log")
    except OSError as e:
        _mark(scan_id, "failed", f"엔진 프로세스 실행 실패: {e}")
        return
    proc.wait()
    _persist_stages(scan_id, out_dir)
    if engine_runner.stopped(out_dir):
        _mark(scan_id, "canceled")
        return
    if not engine_runner.is_done(out_dir):
        _mark(scan_id, "failed", "엔진 단계가 완료 상태에 도달하지 못했습니다. " + (_log_tail(out_dir / "engine.log") or "(엔진 로그 없음)"))
        return
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        if scan is not None:
            engine_runner.ingest_results(db, scan, out_dir, scope_keys=scope_keys)
            scan.status = "done"
            scan.error = ""   # 이전 실패/중단 후 이어하기로 완주한 경우의 잔재 원인 제거(_mark 우회 경로라 직접 비움)
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
    except Exception as e:
        db.rollback()
        _mark(scan_id, "failed", f"엔진 결과 인입 오류: {type(e).__name__}: {e}")
    finally:
        db.close()


def _ingest_xml(db: Session, scan: ScanRun, xml_bytes: bytes, scan_date=None, filename: str | None = None) -> dict:
    stage = (_stage_file_info(filename) or ("", ""))[1]
    findings = parse_xml(xml_bytes)
    scanned_hosts = up_hosts(xml_bytes)
    if stage:
        tcp_scope, udp_scope = _scope_from_stage_xml(stage, xml_bytes)
    else:
        tcp_scope = _scaninfo_scope(xml_bytes, "tcp")
        udp_scope = _scaninfo_scope(xml_bytes, "udp")
    return _commit_ingest(db, scan, findings, scanned_hosts, tcp_scope, udp_scope, scan_date=scan_date)


def _zero_counts() -> dict:
    return {"new": 0, "reopened": 0, "service_changed": 0, "version_changed": 0, "unchanged": 0, "closed": 0}


def _add_counts(total: dict, counts: dict) -> None:
    for key, value in counts.items():
        total[key] = total.get(key, 0) + int(value or 0)


def _first_scan_date(items: list[dict]) -> datetime | None:
    dates = []
    for item in items:
        try:
            if dt := scan_start(item["bytes"]):
                dates.append(dt)
        except Exception:
            continue
    return min(dates) if dates else None


def _import_single_xml(db: Session, user: User, name: str, xml_bytes: bytes) -> dict:
    sdate = scan_start(xml_bytes)
    scan = ScanRun(name=f"가져오기: {name}", status="running", created_by=user.id)
    db.add(scan)
    db.commit()
    if sdate is not None:
        scan.started_at = sdate
    xml_path = _settings.scans_dir / f"scan_{scan.id}.xml"
    xml_path.write_bytes(xml_bytes)
    scan.raw_xml_path = str(xml_path)
    try:
        counts = _ingest_xml(db, scan, xml_bytes, scan_date=sdate, filename=name)
    except Exception as e:
        scan.status = "failed"
        scan.error = f"가져오기 실패: {type(e).__name__}: {e}"[:2000]
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
        raise
    record(db, user, "SCAN_IMPORT", target=name, detail=f"#{scan.id}")
    return {"scan_id": scan.id, "name": scan.name, "counts": counts, "files": [name]}


def _import_stage_bundle(db: Session, user: User, base: str, stages: dict[str, dict]) -> dict:
    items = list(stages.values())
    sdate = _first_scan_date(items)
    display = Path(base.replace("\\", "/")).name
    scan = ScanRun(name=f"가져오기: {display} 자동 스캔 묶음", status="running", created_by=user.id)
    scan.command = "자동 스캔 XML 묶음 · TCP 발견 → TCP 식별 → UDP 식별"
    db.add(scan)
    db.commit()
    if sdate is not None:
        scan.started_at = sdate

    try:
        scanned_hosts: set[str] = set()
        tcp_scope: set[int] | None | set = set()
        udp_scope: set[int] | None | set = set()
        tcp_discovery_findings: list[dict] = []
        tcp_identified_findings: list[dict] = []
        udp_findings: list[dict] = []

        for stage, item in stages.items():
            (_settings.scans_dir / f"scan_{scan.id}.{stage}.xml").write_bytes(item["bytes"])

        if item := stages.get("tcp_discovery"):
            xml_bytes = item["bytes"]
            scanned_hosts |= up_hosts(xml_bytes)
            tcp_scope = _scaninfo_scope(xml_bytes, "tcp")
            tcp_discovery_findings = parse_xml(xml_bytes)
        if item := stages.get("tcp_identify"):
            xml_bytes = item["bytes"]
            scanned_hosts |= up_hosts(xml_bytes)
            if tcp_scope == set():
                tcp_scope = _scaninfo_scope(xml_bytes, "tcp")
            tcp_identified_findings = parse_xml(xml_bytes)
        if item := stages.get("udp_identify"):
            xml_bytes = item["bytes"]
            scanned_hosts |= up_hosts(xml_bytes)
            udp_scope = _scaninfo_scope(xml_bytes, "udp")
            udp_findings = parse_xml(xml_bytes)

        tcp_findings = _prefer_identified(tcp_identified_findings, tcp_discovery_findings)
        findings = [*tcp_findings, *udp_findings]
        if not scanned_hosts:
            scanned_hosts = {f["host_ip"] for f in findings if f.get("host_ip")}

        merged_path = _settings.scans_dir / f"scan_{scan.id}.xml"
        counts = _commit_ingest(
            db,
            scan,
            findings,
            scanned_hosts,
            tcp_scope,
            udp_scope,
            scan_date=sdate,
            raw_xml_path=merged_path,
        )
    except Exception as e:
        scan.status = "failed"
        scan.error = f"묶음 가져오기 실패: {type(e).__name__}: {e}"[:2000]
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
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
        # 관리자 권한 여부 — UI 가 '관리자 권한/비특권(-sT)' 배지를 그리고, 비특권이면
        # 자동 스캔이 막히므로 단일 실행으로 유도한다(-sS→-sT 자동 강등).
        "privileged": nmap_runner.is_admin(),
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
    xml_bytes = await file.read()
    # 가져온 XML 의 '스캔 날짜'는 파일 안의 실제 스캔 시각(없으면 현재). 인입 시각이 아님.
    sdate = scan_start(xml_bytes)
    scan = ScanRun(name=f"가져오기: {file.filename}", status="running", created_by=user.id)
    db.add(scan)
    db.commit()
    if sdate is not None:
        scan.started_at = sdate
    xml_path = _settings.scans_dir / f"scan_{scan.id}.xml"
    xml_path.write_bytes(xml_bytes)
    scan.raw_xml_path = str(xml_path)
    try:
        counts = _ingest_xml(db, scan, xml_bytes, scan_date=sdate, filename=file.filename)
    except Exception as e:
        scan.status = "failed"
        scan.error = f"가져오기 실패: {type(e).__name__}: {e}"[:2000]
        db.commit()
        record(db, user, "SCAN_IMPORT", target=file.filename or "", detail=f"#{scan.id} 실패", ok=False)
        raise HTTPException(status_code=400, detail=f"XML 파싱 실패: {e}")
    record(db, user, "SCAN_IMPORT", target=file.filename or "", detail=f"#{scan.id}")
    return IngestSummary(scan_id=scan.id, counts=counts)


@router.post("/import-bundle")
async def import_xml_bundle(
    files: list[UploadFile] = File(...),
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    payloads = []
    for f in files:
        name = f.filename or "scan.xml"
        if not name.lower().endswith(".xml"):
            continue
        payloads.append({"name": name, "bytes": await f.read()})
    if not payloads:
        raise HTTPException(status_code=400, detail="가져올 XML 파일이 없습니다.")

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
                result = _import_single_xml(db, user, item["name"], item["bytes"])
            imported.append(result)
            _add_counts(total, result["counts"])
        except Exception as e:
            failed.append({"name": str(unit["sort"]), "error": str(e)})
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
    nmap = nmap_runner.find_nmap(_settings.nmap_path)
    if not nmap:
        raise HTTPException(status_code=400, detail="서버에서 nmap 을 찾을 수 없습니다.")
    # 자동 워크플로는 -sS·raw 호스트 발견(-PE/-PA)을 전제하므로 관리자 권한이 없으면 반쪽짜리
    # 스캔이 된다 → 정직하게 차단하고 비특권 대안('단일 실행' -sT)을 안내한다. 단일 실행은
    # build_command_opts/build_command 가 -sT 로 자동 강등하므로 비특권에서도 안전하게 돈다.
    if body.workflow == "auto" and not nmap_runner.is_admin():
        raise HTTPException(status_code=400, detail=(
            "자동 스캔은 관리자 권한(-sS·raw 호스트 발견)이 필요합니다. "
            "서버를 관리자 권한으로 실행하거나, '단일 실행'(비특권 -sT)으로 스캔하세요."))
    try:
        if body.workflow not in ("auto", "manual"):
            raise ValueError("workflow 는 auto 또는 manual 이어야 합니다.")
        hosts = chunker.expand_targets(body.targets)
        if not hosts:
            raise ValueError("유효한 타겟이 없습니다.")
        scope.check_scope(hosts)   # 허용 대역(scope) 밖이면 시작 전에 거절
        batches = chunker.make_batches(hosts, body.batch_size)
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
        elif body.options or body.nse:
            argv0 = nmap_runner.build_command_opts(nmap, body.options, body.ports, batches[0], _basename(0), nse=body.nse)
        else:
            argv0 = nmap_runner.build_command(nmap, body.preset, batches[0], _basename(0))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan = ScanRun(name=body.name or "스캔", targets=" ".join(body.targets),
                   status="running", created_by=user.id)
    db.add(scan)
    db.commit()
    base = _basename(scan.id)
    chunker.write_state(base, {
        "batches": batches, "cursor": 0, "stop": False, "active_seconds": 0,
        "workflow": body.workflow, "options": body.options, "ports": body.ports, "preset": body.preset, "nse": body.nse,
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
    db.commit()
    db.refresh(scan)
    record(db, user, "SCAN_RUN", target=scan.targets,
           detail=f"#{scan.id} · {len(hosts)}호스트 / {len(batches)}배치")
    threading.Thread(target=_chunk_worker, args=(scan.id,), daemon=True).start()
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
        ip_tokens = [t for t in toks if scope.is_ip_token(t)]
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan = ScanRun(name=body.name or "직접 명령 스캔", targets=" ".join(ip_tokens) or body.command.strip()[:64],
                   command=body.command.strip(), status="running", created_by=user.id)
    db.add(scan)
    db.commit()
    base = _basename(scan.id)
    argv, _ = nmap_runner.build_command_raw(nmap, body.command, base)
    chunker.write_state(base, {"raw_argv": argv, "stop": False})
    db.refresh(scan)
    record(db, user, "SCAN_RUN", target=scan.targets,
           detail=f"#{scan.id} 직접명령: {body.command.strip()[:160]}")
    threading.Thread(target=_command_worker, args=(scan.id,), daemon=True).start()
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
    if not nmap_runner.find_nmap(_settings.nmap_path):
        raise HTTPException(status_code=400, detail="서버에서 nmap 을 찾을 수 없습니다.")
    try:
        hosts = chunker.expand_targets(body.targets)
        if not hosts:
            raise ValueError("유효한 타겟이 없습니다.")
        scope.check_scope(hosts)
        scan_options.validate_keys(body.options)
        scan_options.validate_nse(body.nse)
        scan_options.validate_ports(body.ports)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan = ScanRun(name=body.name or "단계 스캔", targets=" ".join(body.targets),
                   status="running", created_by=user.id)
    db.add(scan)
    db.commit()
    out_dir = _settings.scans_dir / f"scan_{scan.id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    spec = engine_runner.build_job_spec(scan.id, body.targets, [], body.options, body.ports,
                                        body.nse, out_dir, body.batch_size, discovery=body.discovery)
    (out_dir / "spec.json").write_text(json.dumps(spec, ensure_ascii=False), encoding="utf-8")
    scan.command = f"{engine_runner.describe(spec)}  ·  {len(hosts)}호스트"
    db.commit()
    db.refresh(scan)
    record(db, user, "SCAN_RUN", target=scan.targets, detail=f"#{scan.id} 단계스캔 · {len(hosts)}호스트")
    threading.Thread(target=_engine_worker, args=(scan.id,), daemon=True).start()
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
    with _STATE_LOCK:   # 워커의 커서 전진(_advance_cursor)과 직렬화 → stop 플래그 유실 방지
        state = chunker.read_state(base)
        if state is not None:
            state["stop"] = True
            chunker.write_state(base, state)
    # 엔진 스캔이면 run-state 에 graceful stop 플래그(엔진이 단계/호스트 경계에서 감지). 무해.
    engine_runner.signal_stop(_settings.scans_dir / f"scan_{scan_id}")
    scan.status = "canceling"   # 워커가 배치 종료를 감지하면 canceled 로 확정
    db.commit()
    with _LOCK:
        procs = list(_PROCS.get(scan_id, ()))   # 병렬 단계면 동시에 뜬 nmap 이 여럿 → 전부 종료
    for proc in procs:
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
        if engine_runner.is_done(out_dir):
            raise HTTPException(status_code=400, detail="이미 모든 단계가 완료되었습니다.")
        if not nmap_runner.find_nmap(_settings.nmap_path):
            raise HTTPException(status_code=400, detail="서버에서 nmap 을 찾을 수 없습니다.")
        engine_runner.clear_stop(out_dir)
        scan.status = "running"
        scan.finished_at = None
        db.commit()
        db.refresh(scan)
        record(db, user, "SCAN_RESUME", target=scan.targets, detail=f"#{scan.id} 엔진 이어가기")
        threading.Thread(target=_engine_worker, args=(scan_id,), daemon=True).start()
        return scan
    base = _basename(scan_id)
    state = chunker.read_state(base)
    if state is None:
        raise HTTPException(status_code=400, detail="이어갈 스캔 상태가 없습니다(이전 버전 스캔).")
    if not nmap_runner.find_nmap(_settings.nmap_path):
        raise HTTPException(status_code=400, detail="서버에서 nmap 을 찾을 수 없습니다.")

    # 직접 명령 스캔(raw_argv): 청킹/커서가 없으므로 전체를 다시 실행한다(단발).
    if "batches" not in state:
        if "raw_argv" not in state:
            raise HTTPException(status_code=400, detail="이어가기를 지원하지 않는 스캔입니다.")
        state["stop"] = False
        chunker.write_state(base, state)
        scan.status = "running"
        scan.finished_at = None
        db.commit()
        db.refresh(scan)
        record(db, user, "SCAN_RESUME", target=scan.targets, detail=f"#{scan.id} 직접명령 재실행")
        threading.Thread(target=_command_worker, args=(scan_id,), daemon=True).start()
        return scan

    if state.get("cursor", 0) >= len(state["batches"]):
        raise HTTPException(status_code=400, detail="이미 모든 배치가 완료되었습니다.")
    state["stop"] = False
    chunker.write_state(base, state)
    scan.status = "running"
    scan.finished_at = None
    db.commit()
    db.refresh(scan)
    record(db, user, "SCAN_RESUME", target=scan.targets,
           detail=f"#{scan.id} · 배치 {state.get('cursor', 0)}부터")
    threading.Thread(target=_chunk_worker, args=(scan_id,), daemon=True).start()
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
        "error": scan.error or "",   # 실패/중단 원인(추적성)
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
    return {
        "scan_id": scan_id,
        "status": scan.status,
        "stages": derived["stages"] or (scan.stages_json or []),
        "overall": derived["overall"],
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
        hosts = chunker.expand_targets(body.targets)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    host_count = len(hosts)
    size = max(1, body.batch_size)
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
        "basis": "history" if rates else "none",
        "sample_count": len(rates),
        "sec_per_host": sec_per_host,
        "est_seconds": est,
    }
