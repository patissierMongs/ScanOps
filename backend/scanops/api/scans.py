"""스캔 라우터 — nmap 실행(백그라운드) / 오프라인 XML 가져오기 → finding 인입.

스캔은 HTTP 요청을 막지 않도록 백그라운드 스레드에서 돈다. 요청은 즉시 ScanRun 을
돌려주고, 프론트는 GET /{id}/progress 로 진행률을, POST /{id}/stop 으로 중지를,
POST /{id}/resume 로 이어가기를 호출한다. (status: running/done/failed/canceling/canceled)
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import SessionLocal, get_db
from ..models import ScanRun, User
from ..schemas import IngestSummary, RawCommandIn, ScanOut, ScanRunIn
from ..scanning import chunker, nmap_runner, scan_options, scope, taxonomy
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


def _basename(scan_id: int) -> Path:
    return _settings.scans_dir / f"scan_{scan_id}"


def _profile(options: list[str], ports: str, preset: str) -> tuple:
    """예상시간용 '동일 설정' 키 — 옵션(또는 프리셋) + 포트. 옵션·망이 시간을 좌우하므로
    이게 같은 과거 스캔만 기준으로 삼는다."""
    pn = (ports or "").replace(" ", "")
    return ("opt", tuple(sorted(options)), pn) if options else ("preset", preset or "quick", pn)


def reconcile_orphans() -> int:
    """서버 부팅 시 호출 — 워커가 사라져 고아가 된 실행(running/canceling)을 interrupted 로 정직하게
    표기한다. 자동 복구는 하지 않는다(이어하기는 사용자가 수동으로). 좀비 '실행 중' 박제를 막는 게 목적.
    반환: 정리된 건수."""
    db = SessionLocal()
    try:
        orphans = db.query(ScanRun).filter(ScanRun.status.in_(("running", "canceling"))).all()
        for scan in orphans:
            scan.status = "interrupted"
            if scan.finished_at is None:
                scan.finished_at = datetime.now(timezone.utc)
        if orphans:
            db.commit()
        return len(orphans)
    finally:
        db.close()


def _mark(scan_id: int, status: str) -> None:
    """종료 상태 확정(done/failed/canceled) — finished_at 기록."""
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        if scan is not None:
            scan.status = status
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


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


def _chunk_worker(scan_id: int) -> None:
    """배치를 순차 실행. 각 배치: nmap → XML → 인입 → 사이드카 커서 전진.
    중지(stop) 플래그가 보이면 현재 배치를 버리고(커서 유지) canceled 로 멈춘다 →
    이어가기 시 그 배치부터 다시 실행한다."""
    base = _basename(scan_id)
    nmap = nmap_runner.find_nmap(_settings.nmap_path)
    state = chunker.read_state(base)
    if not nmap or state is None:
        _mark(scan_id, "failed")
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
        try:
            if st.get("options") or st.get("nse"):
                argv = nmap_runner.build_command_opts(nmap, st.get("options") or [], st.get("ports", ""), batch, b_base, nse=st.get("nse"))
            else:
                argv = nmap_runner.build_command(nmap, st.get("preset", "quick"), batch, b_base)
        except ValueError:
            _mark(scan_id, "failed")
            return
        _set_current_log(scan_id, b_log)
        t0 = datetime.now(timezone.utc)
        try:
            proc = nmap_runner.popen(argv, b_log)
        except OSError:
            _mark(scan_id, "failed")
            return
        with _LOCK:
            _PROCS[scan_id] = proc
        rc = proc.wait()
        with _LOCK:
            _PROCS.pop(scan_id, None)

        # 중지로 종료됐으면 이 배치는 미완 → 커서 유지하고 canceled.
        if (chunker.read_state(base) or st).get("stop"):
            _mark(scan_id, "canceled")
            return
        xml_path = nmap_runner.xml_of(b_base)
        if rc != 0 or not xml_path.exists():
            _mark(scan_id, "failed")
            return
        try:
            _ingest_batch(scan_id, xml_path.read_bytes())
        except Exception:
            _mark(scan_id, "failed")
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
        _mark(scan_id, "failed")
        return
    log = Path(str(base) + ".log")
    _set_current_log(scan_id, log)
    if (chunker.read_state(base) or {}).get("stop"):
        _mark(scan_id, "canceled")
        return
    try:
        proc = nmap_runner.popen(argv, log)
    except OSError:
        _mark(scan_id, "failed")
        return
    with _LOCK:
        _PROCS[scan_id] = proc
    rc = proc.wait()
    with _LOCK:
        _PROCS.pop(scan_id, None)
    if (chunker.read_state(base) or {}).get("stop"):
        _mark(scan_id, "canceled")
        return
    xml_path = nmap_runner.xml_of(base)
    if rc != 0 or not xml_path.exists():
        _mark(scan_id, "failed")
        return
    try:
        # 직접 명령은 -p 범위가 불투명 → 닫힘 판정을 끄고 가산만(미스캔 포트 오closure 방지).
        _ingest_batch(scan_id, xml_path.read_bytes(), no_close=True)
    except Exception:
        _mark(scan_id, "failed")
        return
    _mark(scan_id, "done")


def _ingest_xml(db: Session, scan: ScanRun, xml_bytes: bytes, scan_date=None) -> dict:
    findings = taxonomy.enrich_all(db, parse_xml(xml_bytes))
    counts = ingest(db, scan.id, findings, up_hosts(xml_bytes), scan_date=scan_date)
    from .assets import match_assets
    match_assets(db)
    scan.host_count = len({f["host_ip"] for f in findings})
    scan.port_count = len(findings)
    scan.status = "done"
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()
    return counts


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
        counts = _ingest_xml(db, scan, xml_bytes, scan_date=sdate)
    except Exception as e:
        scan.status = "failed"
        db.commit()
        record(db, user, "SCAN_IMPORT", target=file.filename or "", detail=f"#{scan.id} 실패", ok=False)
        raise HTTPException(status_code=400, detail=f"XML 파싱 실패: {e}")
    record(db, user, "SCAN_IMPORT", target=file.filename or "", detail=f"#{scan.id}")
    return IngestSummary(scan_id=scan.id, counts=counts)


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
    try:
        hosts = chunker.expand_targets(body.targets)
        if not hosts:
            raise ValueError("유효한 타겟이 없습니다.")
        scope.check_scope(hosts)   # 허용 대역(scope) 밖이면 시작 전에 거절
        batches = chunker.make_batches(hosts, body.batch_size)
        # 옵션/프리셋·포트·NSE 사전 검증(첫 배치로) — 잘못된 입력은 시작 전에 거절.
        if body.options or body.nse:
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
        "options": body.options, "ports": body.ports, "preset": body.preset, "nse": body.nse,
    })
    # 명령 표기는 대표(타겟·-oA 제외) — 호스트 수/배치 수를 덧붙여 가독.
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
        state["stop"] = True
        chunker.write_state(base, state)
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
    })
    return prog


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

    want = _profile(body.options, body.ports, body.preset)
    rates: list[float] = []
    for s in db.query(ScanRun).filter(ScanRun.status == "done").order_by(ScanRun.id.desc()).limit(50):
        st = chunker.read_state(_basename(s.id))
        if not st:
            continue
        if _profile(st.get("options") or [], st.get("ports", ""), st.get("preset", "quick")) != want:
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
