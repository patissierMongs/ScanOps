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
import shutil
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import SessionLocal, get_db
from ..models import (
    ACTIVE_FINDING_STATES, Finding, FindingEvent, ScanExecution, ScanHostObservation,
    ScanQualityIssue, ScanRun, User,
)
from ..schemas import IngestSummary, KnownResultsIn, RawCommandIn, ScanOut, ScanRunIn
from ..uploads import read_limited
from ..scanning import (
    chunker, engine_runner, nmap_runner, observability, scan_options, scan_summary, scope, taxonomy,
    xml_verdict,
)
from ..scanning.presets import PRESETS
from ..scanning.ingest import ingest
from ..scanning.nmap_parse import observed_at, parse_xml, probed_identity, up_hosts
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
# 합성 스냅샷 표식 — 이 값이 붙은 XML 은 원본 스캔 결과가 아니다.
SNAPSHOT_MARK = "1"
SNAPSHOT_REJECT = (
    "ScanOps 가 만든 스냅샷 XML 은 다시 가져올 수 없습니다. 여러 산출물을 하나로 합치면서 "
    "개별 관측 시각이 사라져, 원본 결과처럼 인입하면 과거 관측이 최신 관측으로 둔갑합니다. "
    "원본 단계 XML(scan_N.<단계>.xml)이나 스캐너 결과 폴더를 가져오세요."
)
STAGE_FILE_RE = re.compile(r"^(?P<base>.+)\.(?P<stage>tcp_discovery|tcp_identify|udp_identify)\.xml$", re.I)
# 단계 엔진(웹 [단계 스캔])이 결과 폴더에 남기는 산출물 이름. 단독 스캐너와 달리 파일명에
# 실행을 식별할 base 가 없다 - **폴더 하나가 실행 하나**라서 폴더로 묶어야 한다.
#
# 이걸 몰랐을 때는 파일마다 STAGE_FILE_RE 에 걸리지 않아 전부 'single' 단위가 됐고,
# 결과 폴더를 통째로 가져오면 **파일 수만큼 스캔 행**이 생겼다(4개 파일 -> 4줄). 배치가
# 여럿인 실행은 이력이 아무 말도 하지 않는 줄로 가득 찼다.
ENGINE_STAGE_RE = re.compile(
    r"^stage(?:"
    r"(?P<discovery>0-discovery)"                             # -sn 호스트 발견
    r"|-(?P<sweep_proto>tcp|udp)-b(?P<sweep_batch>\d+)"       # 포트 스윕
    r"|3-(?P<svc_proto>tcp|udp)-b(?P<svc_batch>\d+)-g(?P<svc_group>\d+)"  # 서비스 식별
    # 호스트 격리 재시도. 접미사는 프로토콜(tcp/udp)이거나 포트가 붙은 tag(tcp443·udp161)다.
    r"|3-(?P<iso_host>\d+_\d+_\d+_\d+)-(?P<iso_proto>[a-z]+[a-z0-9]*)"
    r")(?:-confirm)?\.xml$", re.I)
# 누산기가 아는 역할 이름 - 단독 스캐너의 단계 이름과 같은 자리를 쓴다.
ENGINE_ROLE_DISCOVERY = "engine_discovery"
# 중단본 표식 — 스캐너(scanops_scanner.INTERRUPTED_*)와 같은 문자열이어야 한다.
INTERRUPTED_DIR_NAME = "interrupted"
INTERRUPTED_MARK = ".interrupted"
INTERRUPTED_REJECT = (
    "중단된 스캔 결과는 가져올 수 없습니다. 부분 결과라 못 본 포트가 미탐이 되고, "
    "끊긴 자리의 filtered 가 오탐이 됩니다. 스캔을 다시 완주한 뒤 가져오세요."
)
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
    scan_options.validate_ports(body.exclude_ports or "")
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


def _exclude_tokens(port_spec: str, proto: str) -> list[str]:
    """제외 스펙 전용 토큰화 - **접두사가 없으면 모든 프로토콜에 적용**한다.

    nmap 포트 문법은 접두사 없는 번호를 스캔 중인 protocol list 전부에 넣고,
    ``--exclude-ports`` 도 ``-p`` 와 같은 문법을 쓴다. 실측으로 확인했다 -
    ``-p T:80,U:53 --exclude-ports 53`` 은 UDP scaninfo 를 ``numservices=0`` 으로 만들지만
    ``--exclude-ports T:53`` 은 UDP 53 을 그대로 스캔한다.

    스캔 범위 파싱(_port_tokens)은 접두사 없는 토큰을 TCP 로만 본다. 그쪽은 앱이 T:/U: 를
    명시해 넘기는 자리라 그대로 두고, 제외만 nmap 의미에 맞춘다 - 안 그러면 화면이 예시로
    먼저 보여 주는 ``9100, 515, 631`` 같은 표기가 UDP 를 전혀 보호하지 못한다.
    """
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
        # 접두사가 나오기 전 구간은 두 프로토콜 모두에 걸린다. 접두사가 한 번 나오면
        # 그 뒤로는 nmap 과 같이 다음 접두사까지 그 프로토콜에만 걸린다.
        if not current or current == proto.upper():
            out.append(item)
    return out


def _expand_port_tokens(tokens: list[str]) -> set[int] | None:
    """토큰 -> 포트 집합. ``None`` = 전 포트."""
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


def _port_scope(port_spec: str, proto: str) -> set[int] | None:
    """None means all ports for the protocol were scanned."""
    return _expand_port_tokens(_port_tokens(port_spec, proto))


def is_interrupted_upload(filename: str | None) -> bool:
    """중단본 표식이 붙은 파일인가(`*.interrupted.xml` 또는 `interrupted/` 아래).

    중단된 스캔은 열린 포트를 다 보지 못한 상태다. 관측으로 받아들이면 못 본 포트가
    **미탐**이 되고, 재시도가 잘린 자리의 filtered 를 믿으면 **오탐**이 된다. 스캐너가
    애초에 올리지 않지만, 사람이 파일을 끌어다 놓는 경로가 남아 있으므로 서버에서도 막는다.
    """
    normalized = (filename or "").replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    if f"{INTERRUPTED_MARK}." in name:
        return True
    return f"/{INTERRUPTED_DIR_NAME}/" in f"/{normalized}"


def _stage_file_info(filename: str | None) -> tuple[str, str] | None:
    normalized = (filename or "").replace("\\", "/")
    m = STAGE_FILE_RE.match(normalized)
    if not m:
        return None
    return m.group("base"), m.group("stage").lower()


def _engine_stage_info(filename: str | None) -> tuple[str, str, str] | None:
    """단계 엔진 산출물인가 -> (실행 키, 배치 키, 역할).

    실행 키는 **파일이 든 폴더**다. 엔진은 파일명에 실행 식별자를 넣지 않고 결과 폴더
    하나를 실행 하나로 쓰므로, 폴더로 묶지 않으면 같은 실행의 단계들이 흩어진다.

    역할은 단독 스캐너의 단계 이름으로 옮긴다 - 누산기가 이미 그 세 자리로 '스윕이 증명한
    열림'과 '식별이 밝힌 서비스'를 합치고 있어서, 같은 규칙을 두 벌 만들 이유가 없다.
    호스트 발견은 어느 자리에도 넣지 않는다: `-sn` 산출물에는 `<scaninfo>` 가 아예 없어
    포트를 하나도 관측하지 않았고(실측), 관측하지 않은 것으로 닫으면 안 되기 때문이다.
    """
    normalized = (filename or "").replace("\\", "/")
    folder, _, name = normalized.rpartition("/")
    m = ENGINE_STAGE_RE.match(name)
    if not m:
        return None
    run_key = folder or name          # 폴더 없이 올라온 낱개 파일도 자기 이름으로 묶인다
    # **배치 키는 파일마다 유일해야 한다.** 같은 (배치, 역할) 자리에 두 파일이 들어오면 뒤엣것이
    # 앞엣것을 조용히 덮어쓴다. 실제로 그랬다: 스윕(stage-udp-b0)과 식별(stage3-udp-b0-g0)이
    # 같은 자리를 다퉈 스윕 증거가 사라졌고, 아무것도 못 찾은 식별만 남아 열린 발견이 닫혔다
    # (실측 counts.closed=1). 식별 그룹 g0·g1 과 격리 재시도 tcp/tcp443 도 서로를 덮었다.
    if m.group("discovery"):
        # 발견은 배치에 속하지 않는다. b0 에 얹어 두면 배치 수를 부풀리지 않는다.
        return run_key, "b0", ENGINE_ROLE_DISCOVERY
    if m.group("sweep_proto"):
        proto = m.group("sweep_proto").lower()
        # 스윕은 **열림만 증명**한다. 식별과 다른 역할이어야 stage3 가 아무것도 못 찾았을 때
        # 스윕 증거가 살아남는다 - 실제 실행 경로(engine_runner.collect_results)도 스윕을
        # setdefault 로 깔고 stage3 가 보고한 키만 덮어쓴다.
        role = "tcp_discovery" if proto == "tcp" else "udp_sweep"
        return run_key, f"b{int(m.group('sweep_batch'))}", role
    if m.group("svc_proto"):
        proto = m.group("svc_proto").lower()
        role = "tcp_identify" if proto == "tcp" else "udp_identify"
        # 같은 배치 안의 식별 그룹은 슬롯 접미사로 가른다 - 역할은 같지만 다른 파일이다.
        return run_key, f"b{int(m.group('svc_batch'))}", f"{role}#g{int(m.group('svc_group'))}"
    # 호스트 격리 재시도 - 공통 실행이 실패한 뒤 그 호스트만 다시 돈 것이라 식별로 본다.
    # 파일명에 배치가 없으므로 b0 에 얹되, 슬롯으로 서로를 구분한다.
    suffix = (m.group("iso_proto") or "tcp").lower()
    role = "udp_identify" if suffix.startswith("udp") else "tcp_identify"
    return run_key, "b0", f"{role}#iso-{m.group('iso_host')}-{suffix}"


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


def _observed_after(last_seen: datetime | None, as_of: datetime) -> bool:
    """이 발견이 ``as_of`` 보다 나중에 관측됐는가. 시각을 모르면 False(기존 판정 유지).

    SQLite 는 UTC DateTime 을 tzinfo 없이 돌려주므로 비교 전에 UTC 로 맞춘다 - 안 맞추면
    naive/aware 비교가 TypeError 로 인입 전체를 죽인다.
    """
    if last_seen is None:
        return False
    seen = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
    moment = as_of if as_of.tzinfo else as_of.replace(tzinfo=timezone.utc)
    return seen > moment


def _excluded_port_scope(exclude_ports: str, proto: str) -> set[int] | None | set:
    """제외한 포트 범위. ``None`` = 그 프로토콜 전체 제외, ``set()`` = 제외 없음.

    제외는 **관측하지 않겠다**는 선언이다. 그러므로 닫힘 후보에서도 빠져야 한다 - 전선에서만
    빼고 후보에 남겨 두면, 프로브를 한 번도 보내지 않은 포트를 '부재를 확인했다'며 닫는다.
    운영자가 보호하려고 뺀 포트가 오히려 조용히 사라지는, 정확히 거꾸로 된 결과다.
    """
    if not (exclude_ports or "").strip():
        return set()
    return _expand_port_tokens(_exclude_tokens(exclude_ports, proto))


def _is_excluded(port: int, excluded: set[int] | None | set) -> bool:
    return excluded is None or port in excluded


def _auto_scope_keys(db: Session, scanned_hosts: set[str], findings: list[dict],
                     tcp_scope: set[int] | None | set, udp_scope: set[int] | None | set,
                     as_of: datetime | None = None,
                     tcp_excluded: set[int] | None | set = frozenset(),
                     udp_excluded: set[int] | None | set = frozenset()) -> set[str]:
    """관측 범위 안의 닫힘 후보. ``as_of`` 는 이 결과가 관측된 시각이다.

    그보다 **나중에** 관측된 발견은 후보가 아니다. 이 결과는 그때 그 포트가 없었다고 말할
    뿐, 그 뒤에 열린 것에 대해서는 아무 말도 하지 않는다. ingest() 는 같은 판단을
    `_is_older` 로 하지만, 후보 집합은 병합 XML 의 closed 목록에도 그대로 쓰이므로 여기서
    빼지 않으면 DB 는 지켜도 증거 파일이 반대로 말한다.
    """
    keys = {_finding_key(f) for f in findings}
    if not scanned_hosts:
        return keys
    hosts = sorted(scanned_hosts)
    rows = []
    for start in range(0, len(hosts), 500):
        rows.extend(db.query(Finding).filter(
            Finding.state.in_(ACTIVE_FINDING_STATES), Finding.host_ip.in_(hosts[start:start + 500])
        ).all())
    if as_of is not None:
        rows = [row for row in rows if not _observed_after(row.last_seen, as_of)]
    for row in rows:
        proto = (row.proto or "").lower()
        if (proto == "tcp" and (tcp_scope is None or row.port in tcp_scope)
                and not _is_excluded(row.port, tcp_excluded)):
            keys.add(row.finding_key)
        if (proto == "udp" and (udp_scope is None or row.port in udp_scope)
                and not _is_excluded(row.port, udp_excluded)):
            keys.add(row.finding_key)
    return keys


def _saved_stage_scope(saved_spec: dict, proto: str) -> set[int] | None | set:
    """저장된 엔진 spec 이 '이 프로토콜에서 무엇을 스캔하기로 했는가'.

    ``None`` = 전 포트, ``set()`` = 닫힘 근거 없음. 구형 spec 은 닫힘 후보 목록
    (``scanops.scope_keys``)을 저장하지 않았지만, **무엇을 스캔하기로 했는지**는 그대로
    들고 있다. 그 경계를 버리고 host 단위로 닫으면 스캔한 적도 없는 포트가 '닫힘 +
    정상처리'로 인증된다 - 되돌리기 가장 어려운 미탐이다.

    활성인데 포트 범위가 비어 있으면 무엇을 봤는지 알 수 없다. 전 포트로 넘겨짚지 않고
    닫지 않는 쪽으로 판정한다(엔진 spec 검증은 그런 조합을 애초에 거부하므로, 여기 걸리는
    것은 손상됐거나 손으로 만든 spec 뿐이다).
    """
    stage = (saved_spec.get("stages") or {}).get(proto) or {}
    if not stage.get("enabled", True):
        return set()
    ports = str(stage.get("ports") or "").strip()
    if not ports:
        return set()
    prefix = "T" if proto == "tcp" else "U"
    return _port_scope(f"{prefix}:{ports}", prefix)


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
    # reason 을 빠뜨리면 다운로드·재인입되는 감사 산출물에서만 근거가 '미관측'으로 조용히
    # 바뀐다 — 화면에는 보이는데 증거 파일에는 없는 상태가 된다. nmap 자체 XML 도 --reason
    # 표시 옵션과 무관하게 <state reason=".."> 를 늘 보존한다.
    state_attrs = {"state": finding.get("state") or "open"}
    if finding.get("reason"):
        state_attrs["reason"] = str(finding["reason"])
    ET.SubElement(port, "state", **state_attrs)
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
        # 이 파일은 nmap 산출물이 아니라 **여러 산출물을 합친 스냅샷**이다. nmap XML 은 문서
        # 단위 시각 하나만 표현할 수 있어서, 서로 다른 시각에 관측한 열림을 한 파일로 합치면
        # 개별 관측 시각이 사라진다. 그 상태로 다시 가져오면 과거 관측이 최신 노출로 둔갑한다
        # - 그래서 원본처럼 재인입되지 않도록 표식을 남긴다.
        scanops_snapshot=SNAPSHOT_MARK,
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
                   closure_scope_keys: set[str] | None = None,
                   absence_at: dict | None = None) -> dict:
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
            # 가져온 XML 은 파일 안의 시각이 곧 관측 시각이라, 지난 날짜의 XML 을 오늘 올리는
            # 일이 정상 경로다. ingest() 는 _is_older 로 그 뒤 관측을 지키지만 후보 집합은
            # 병합 XML 의 closed 목록에도 쓰이므로 여기서도 잘라야 둘이 같은 말을 한다.
            as_of=scan_date,
        )
    )
    # 인입을 먼저 하고 **실제로 닫힌 키만** 증거 XML 에 적는다. 후보 전체를 미리 닫힘으로
    # 쓰면, 인입이 시각·커버리지를 근거로 살려 둔 발견까지 증거 파일에는 닫힘으로 남아
    # DB 와 정반대로 증언한다.
    closed_keys: set[str] = set()
    applied_keys: set[str] = set()
    counts = ingest(
        db, scan.id, enriched, scanned_hosts, scope_keys=scope_keys,
        scan_date=scan_date, absence_at=absence_at,
        closed_keys=closed_keys, applied_keys=applied_keys, commit=False,
    )
    if raw_xml_path is not None:
        applied = [f for f in enriched if _finding_key(f) in applied_keys]
        _write_merged_xml(db, raw_xml_path, applied, scanned_hosts,
                          {_finding_key(f) for f in applied} | closed_keys, scan_date)
        scan.raw_xml_path = str(raw_xml_path)
    from .assets import match_assets
    match_assets(db, commit=False)
    # '호스트' 는 이 스캔이 **관측한** 호스트 수다. 발견이 있는 호스트만 세면 열린 포트가
    # 없던 호스트가 통째로 사라져, 같은 대역을 웹에서 돌렸을 때(engine 은 scanned 를 센다)와
    # 숫자가 달라진다. 가져온 결과라고 해서 다르게 셀 이유가 없다.
    scan.host_count = len(scanned_hosts) or len({f["host_ip"] for f in enriched})
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


def _wait_scan_process(scan_id: int, proc, watchdog_seconds: int = 0,
                      out_base: Path | None = None) -> int:
    """Register, honor a stop that raced with spawn, then release tree ownership.

    ``watchdog_seconds`` 는 nmap 프로세스당 상한이다(0 = 끔). 호스트 상한을 뺀 자리에
    두는 제어라 레거시/자동 워크플로에서도 켤 수 있어야 한다 - 한쪽 경로에만 달아 두면
    사용자는 보호만 잃고 대체는 못 얻는다.

    ``--host-timeout`` 과 달리 프로세스를 밖에서 끝내므로, 그때까지 ``-oA`` 로 쓰인 관측이
    남는다. 다만 nmap 은 ``</nmaprun>`` 을 못 쓰고 죽어 표준 파서가 그 파일을 통째로
    거절하므로(실측: 587바이트, ParseError) **여기서 복구까지 해야** 그 말이 성립한다.
    ``out_base`` 를 주면 워치독이 끊었을 때 그 산출물을 복구한다 - 안 주면 복구하지
    않으므로, 워치독을 켜는 호출부는 반드시 넘겨야 한다.

    복구본에는 ``runstats`` 가 없어 완결성 검사가 그대로 실패한다. 관측은 살리되 미관측
    닫힘 권한은 주지 않는다.
    """
    with _LOCK:
        _PROCS[scan_id] = proc
    if chunker.stop_requested(_basename(scan_id)) and proc.poll() is None:
        proc.terminate()
    timer = None
    fired = threading.Event()
    if watchdog_seconds and watchdog_seconds > 0:
        def _fire():
            if proc.poll() is None:
                logger.warning("scan %s: nmap exceeded %ss watchdog, terminating",
                               scan_id, watchdog_seconds)
                fired.set()
                proc.terminate()
        timer = threading.Timer(watchdog_seconds, _fire)
        timer.daemon = True
        timer.start()
    try:
        return nmap_runner.wait_owned(proc)
    finally:
        if timer is not None:
            timer.cancel()
        if fired.is_set() and out_base is not None:
            if nmap_runner.repair_truncated_xml(nmap_runner.xml_of(out_base)):
                logger.warning("scan %s: repaired watchdog-truncated XML at %s",
                               scan_id, nmap_runner.xml_of(out_base))
        with _LOCK:
            if _PROCS.get(scan_id) is proc:
                _PROCS.pop(scan_id, None)


def _run_stage(scan_id: int, argv: list[str], log_path: Path,
               watchdog_seconds: int = 0, out_base: Path | None = None) -> int:
    _set_current_log(scan_id, log_path)
    try:
        proc = nmap_runner.popen(argv, log_path)
    except OSError:
        return -1
    return _wait_scan_process(scan_id, proc, watchdog_seconds, out_base)


class _WorkerFailure(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _checked_stage(scan_id: int, argv: list[str], log_path: Path,
                   watchdog_seconds: int = 0, out_base: Path | None = None) -> None:
    rc = _run_stage(scan_id, argv, log_path, watchdog_seconds, out_base)
    if rc == -1:
        raise _WorkerFailure("nmap_launch_failed")
    if rc != 0:
        raise _WorkerFailure("nmap_failed")


def _mark_stage(scan_id: int, state: dict, stage: str, hosts: int = 0) -> None:
    """지금 어느 단계를 돌고 있는지 sidecar 에 남긴다.

    자동 스캔은 배치 하나 안에서 발견 -> 식별 -> UDP 를 순서대로 돈다. 그 사실을 남기지
    않으면 화면은 nmap 이 뱉는 퍼센트 하나만 볼 수 있어서, 몇 분째 같은 숫자를 보면서
    '무엇을 하는 중인지' 알 수 없다.
    """
    state["stage"] = stage
    if hosts:
        state["stage_hosts"] = hosts
    try:
        chunker.write_state(_basename(scan_id), state)
    except OSError:
        logger.warning("failed to record scan %s stage", scan_id, exc_info=True)


def _run_auto_batch(scan_id: int, nmap: str, batch: list[str], b_base: Path, state: dict) -> bool:
    """Run discovery -> identify -> UDP for one batch, then ingest the final observations once."""
    ports = state.get("ports", "")
    nse = state.get("nse") if state.get("nse") is not None else scan_options.NSE_DEFAULT_KEYS
    udp_all_targets = bool(state.get("udp_all_targets"))
    # nmap 프로세스당 상한(0=끔). state 에서 읽으므로 재개해도 같은 값이 유지된다.
    watchdog = int(state.get("watchdog_seconds") or 0)
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
        _mark_stage(scan_id, state, "tcp_discovery", len(batch))
        _checked_stage(scan_id, argv, discovery_log, watchdog, discovery_base)
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
            _mark_stage(scan_id, state, "tcp_identify", len(discovery_live or batch))
            _checked_stage(scan_id, argv, identify_log, watchdog, identify_base)
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
        _mark_stage(scan_id, state, "udp_identify",
                    len(batch if udp_all_targets else (discovery_live or batch)))
        _checked_stage(scan_id, argv, udp_log, watchdog, udp_base)
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
        rc = _wait_scan_process(scan_id, proc, int(st.get("watchdog_seconds") or 0), b_base)

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
    excluded = {proto: _excluded_port_scope(saved_spec.get("exclude_ports", ""), prefix)
                for proto, prefix in (("tcp", "T"), ("udp", "U"))}
    for host, port, proto in parsed_keys:
        port_scope = tcp_ports if proto == "tcp" else udp_ports
        if host not in effective_hosts or (port_scope is not None and port not in port_scope):
            raise ValueError(
                "저장된 단계 스캔 닫힘 범위(scope_keys)가 유효 스캔 범위를 벗어났습니다."
            )
        # 손으로 고친 spec 이 제외 포트를 닫힘 후보로 되돌리는 것을 막는다.
        if _is_excluded(port, excluded.get(proto, frozenset())):
            raise ValueError(
                "저장된 단계 스캔 닫힘 범위(scope_keys)에 제외한 포트가 들어 있습니다."
            )


def _read_engine_spec(out_dir: Path) -> dict | None:
    """진행 표시에 쓰는 spec 읽기 — 없거나 깨졌으면 None(진행을 넘겨짚지 않는다)."""
    try:
        return _load_engine_spec(out_dir / "spec.json")
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _target_label(hosts: list[str]) -> str:
    """현재 배치를 한 줄로. 64개를 다 적으면 표가 무너지므로 대표 하나와 개수만."""
    if not hosts:
        return ""
    return hosts[0] if len(hosts) == 1 else f"{hosts[0]} 외 {len(hosts) - 1}대"


def _scan_started_at(scan: ScanRun):
    started = scan.started_at
    if started is not None and started.tzinfo is None:
        # SQLite reloads UTC DateTime values without tzinfo; timestamp() would otherwise apply
        # the Windows local offset and move this phase backwards in the heatmap chronology.
        started = started.replace(tzinfo=timezone.utc)
    return started


def _commit_engine_ingest(db: Session, scan: ScanRun, out_dir: Path,
                          scope_keys: set[str],
                          force_scanned_hosts: bool, saved_spec: dict | None = None) -> dict:
    """Persist staged findings and the equivalent authoritative heatmap snapshot.

    ``scope_keys`` 는 언제나 명시적 집합이다. 구형 spec(저장된 목록이 없는 실행)은 호출자가
    미리 stages 의 포트/프로토콜 경계로 후보를 세워 넘긴다 - ``None`` 을 받아 host 단위로
    닫는 경로는 스캔하지 않은 포트까지 '닫힘 + 정상처리'로 만들어서 없앴다.
    """
    findings, scanned_hosts = engine_runner.collect_results(
        out_dir, scope_keys=scope_keys, force_scanned_hosts=force_scanned_hosts,
    )
    merged_path = _settings.scans_dir / f"scan_{scan.id}.xml"
    # 부재(닫힘)를 주장할 수 있는 시점은 authority sweep 이 **끝난** 시각이다. 시작 시각을
    # 쓰면 /24 처럼 몇 시간 도는 스캔에서 그 사이 다른 스캔이 남긴 결과가 더 새것으로
    # 판정되어, 이 스캔이 나중에 실제로 확인한 열린 포트가 통째로 버려진다 - 노출을 숨기는
    # 미탐이다. 산출물이 시각을 말하지 않을 때만 시작 시각으로 되돌아간다.
    snapshot_date = None
    if saved_spec is not None:
        snapshot_date = engine_runner.authority_observed_at(
            out_dir, saved_spec, force_scanned_hosts)
    if snapshot_date is None:
        snapshot_date = _scan_started_at(scan)
    # 인입을 **먼저** 하고, 실제로 닫힌 키만 증거 XML 에 적는다. 예전에는 scope_keys 전체를
    # '닫힘'으로 미리 써 버려서, 인입이 시각·커버리지를 근거로 살려 둔 발견까지 증거 파일에는
    # 닫힘으로 남았다 - DB 와 증거가 정반대로 증언한다. 닫힌 행도 그대로 남아 있으므로
    # 순서를 바꿔도 서비스명 등 표시값은 그대로 읽힌다.
    closed_keys: set[str] = set()
    applied_keys: set[str] = set()
    counts = engine_runner.ingest_results(
        db, scan, out_dir, scope_keys=scope_keys,
        force_scanned_hosts=force_scanned_hosts, scan_date=snapshot_date,
        spec=saved_spec, closed_keys=closed_keys, applied_keys=applied_keys, commit=False,
    )
    # 열림도 닫힘과 같은 조건이어야 한다. 인입이 '더 새로운 관측이 있다'며 버린 open 을
    # 증거에는 그대로 적으면, 그 파일이 DB 가 거절한 과거 관측을 최신 노출로 되살린다.
    applied = [f for f in findings if _finding_key(f) in applied_keys]
    _write_merged_xml(
        db, merged_path, applied, scanned_hosts,
        {_finding_key(f) for f in applied} | closed_keys,
        scan_date=snapshot_date,
    )
    scan.raw_xml_path = str(merged_path)
    return counts


def _artifact_issue_inputs(report: dict, problems: list[str]) -> list[dict]:
    issues: list[dict] = []

    def stage_for(name: str) -> str:
        lowered = name.lower()
        proto = "udp" if "udp" in lowered else "tcp" if "tcp" in lowered else ""
        return f"{proto}_service" if "stage3" in lowered and proto else proto or "service"

    for bucket, kind in (
        ("authority_missing", "artifact_missing"),
        ("authority_broken", "artifact_broken"),
        ("enrichment_missing", "artifact_missing"),
        ("enrichment_broken", "artifact_broken"),
    ):
        for artifact in report.get(bucket) or []:
            name = str(artifact)
            issues.append({
                "issue_key": f"{kind}|{bucket}|{name}", "kind": kind,
                "stage": stage_for(name), "host_ip": "",
                "detail": f"{bucket}: {name}",
            })
    for index, problem in enumerate(problems):
        issues.append({
            "issue_key": f"nse_degraded|{index}|{hashlib.sha256(problem.encode('utf-8')).hexdigest()[:16]}",
            "kind": "nse_degraded", "stage": "service", "host_ip": "",
            "detail": problem,
        })
    return issues


def _resolve_retry_observations(db: Session, retry_scan_id: int, saved_spec: dict) -> int:
    scanops = saved_spec.get("scanops") if isinstance(saved_spec, dict) else None
    source_id = scanops.get("retry_of") if isinstance(scanops, dict) else None
    if not isinstance(source_id, int) or source_id <= 0:
        return 0
    source_issues = db.query(ScanQualityIssue).filter(
        ScanQualityIssue.scan_id == source_id,
        ScanQualityIssue.retry_scan_id == retry_scan_id,
        ScanQualityIssue.resolved_by_scan_id.is_(None),
    ).all()
    if not source_issues:
        return 0
    host_rows = {
        row.host_ip: row for row in db.query(ScanHostObservation).filter_by(
            scan_id=retry_scan_id
        ).all()
    }
    child_issues = {
        (issue.kind, engine_runner.canonical_stage(issue.stage), issue.host_ip)
        for issue in db.query(ScanQualityIssue).filter_by(scan_id=retry_scan_id).all()
        if issue.resolved_by_scan_id is None
    }
    stage_field = {
        "discovery": "discovery_status", "tcp": "tcp_sweep_status",
        "tcp_service": "tcp_service_status", "udp": "udp_sweep_status",
        "udp_service": "udp_service_status",
    }
    resolved = []
    for issue in source_issues:
        canonical = engine_runner.canonical_stage(issue.stage)
        field = stage_field.get(canonical)
        host = host_rows.get(issue.host_ip)
        if not field or host is None or getattr(host, field) != "done":
            continue
        if (issue.kind, canonical, issue.host_ip) in child_issues:
            continue
        resolved.append(issue.issue_key)
    return observability.resolve_quality_issues(
        db, source_id, retry_scan_id, resolved,
    )


def _materialize_engine_terminal(
    db: Session, scan: ScanRun, out_dir: Path, saved_spec: dict,
    report: dict, problems: list[str],
) -> dict:
    projection = engine_runner.terminal_observability(out_dir, saved_spec)
    issues = list(projection["issues"])
    issues.extend(_artifact_issue_inputs(report, problems))
    counts = observability.materialize_terminal_observability(
        db, scan.id, executions=projection["executions"], issues=issues,
        hosts=projection["hosts"],
    )
    _resolve_retry_observations(db, scan.id, saved_spec)
    return {**projection, "materialized": counts}


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
    # 닫힘 권한은 산출물 완결성으로 판정한다 — 단독 스캐너와 같은 계약이다.
    # rc=0 · stages_done 에 job 이 있어도 nmap 이 XML 을 끝맺지 못했거나 아예 만들지 못했을 수
    # 있다. 그 상태로 닫으면 '못 본 포트'가 '닫힌 포트'가 되고, 닫힘은 status 까지 '정상처리'로
    # 바꾸므로 되돌리기 가장 어려운 미탐이 된다. 그래서 '있는 파일'이 아니라 '만들기로 한 집합'과
    # 대조하고, 열림을 정하는 산출물(authority)과 상세만 채우는 산출물(enrichment)을 가른다.
    report = engine_runner.artifact_report(out_dir, saved_spec, force_scanned_hosts)
    unfinished = report["authority_missing"] + report["authority_broken"]
    # NSE/소켓 오류는 이와 다른 축이다. 스크립트 소켓 하나가 bind 에 실패해도(WSAEACCES 10013)
    # nmap 은 포트 결과를 온전히 내고 rc=0 으로 끝난다. 그런 실행에서 닫힘 권한을 빼면 사라진
    # 서비스가 영영 닫히지 않아 오탐이 쌓인다 — 사실만 남기고 권한은 건드리지 않는다.
    problems = engine_runner.log_problems(out_dir / "engine.log")
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        if scan is not None:
            # 산출물이 완결됐다는 것과 '이 호스트의 포트를 봤다'는 것은 다른 사실이다.
            # sn discovery 에서 호스트가 응답하지 않으면 live 가 비고 sweep 이 아예 돌지
            # 않는데, 그때 기대 산출물은 discovery 하나뿐이라 완결성 검사가 공허하게
            # 통과한다. 그 상태로 scope_keys 를 그대로 닫으면 패킷을 한 번도 보내지 않은
            # 포트가 전부 '닫힘 + 정상처리'가 된다 - 관측하지 못한 것을 없다고 말하는,
            # 이 PR 이 내내 막아 온 바로 그 오류다.
            legacy_scope = scope_keys is None
            if legacy_scope:
                # 구형 spec 은 닫힘 후보 **목록**만 없을 뿐, 무엇을 스캔하기로 했는지는
                # stages 에 남아 있다. 그 경계로 후보를 세워 명시적 집합으로 만든다 -
                # 여기서 None 을 그대로 흘려보내면 인입이 host 단위로 닫아, 스캔하지도
                # 않은 포트와 비활성 프로토콜까지 '닫힘 + 정상처리'가 된다.
                # 호스트 축은 기존과 같이 실제 관측한 호스트로만 한정한다.
                # 후보를 **마감 시점의 현재 DB** 에서 만들므로, 그 스캔이 끝난 뒤에 새로
                # 관측된 발견까지 딸려 들어온다. 이 결과는 그때 그 포트가 없었다고 말할 뿐
                # 그 뒤에 열린 것에 대해서는 아무 말도 하지 않는다 - 실행 시각으로 잘라낸다.
                scope_keys = _auto_scope_keys(
                    db,
                    engine_runner.observed_hosts(out_dir, saved_spec, force_scanned_hosts),
                    [],
                    _saved_stage_scope(saved_spec, "tcp"),
                    _saved_stage_scope(saved_spec, "udp"),
                    as_of=scan.started_at,
                    # 저장된 spec 의 제외도 같이 읽는다 - 마감·재개가 후보를 다시 세우므로
                    # 여기서 빠뜨리면 실행 시점에 뺀 포트가 마감 때 되살아나 닫힌다.
                    tcp_excluded=_excluded_port_scope(saved_spec.get("exclude_ports", ""), "T"),
                    udp_excluded=_excluded_port_scope(saved_spec.get("exclude_ports", ""), "U"),
                )
            closing = (set() if unfinished
                       else engine_runner.observed_scope(
                           scope_keys, out_dir, saved_spec, force_scanned_hosts))
            # 구형 spec 의 후보는 실행 전 스냅샷이 아니라 관측한 호스트에서 세운 것이라
            # '빠진 건수'를 셀 기준이 없다. 없는 숫자를 지어내지 않는다.
            unobserved = (0 if unfinished or legacy_scope
                          else len(scope_keys) - len(closing))
            _commit_engine_ingest(
                db, scan, out_dir,
                closing,                               # 빈 집합 = 닫힘 후보 없음
                force_scanned_hosts,
                saved_spec,
            )
            _materialize_engine_terminal(
                db, scan, out_dir, saved_spec, report, problems,
            )
            scan.status = "partial" if unfinished else "done"
            scan.finished_at = datetime.now(timezone.utc)
            if unfinished:
                scan.failure_code = "nmap_xml_incomplete"
                scan.failure_message = (
                    "nmap 이 결과 XML 을 끝맺지 못했습니다 — 관측이 불완전해 닫힘 판정에서 "
                    f"제외했습니다. ({', '.join(unfinished[:3])})"
                )
            else:
                # done 인데 failure_* 를 쓰는 자리가 아니다. 이 코드는 '실패'가 아니라
                # '부가 증거가 덜 찼다'는 참고이며, UI 도 실패 원인과 다른 라벨로 그린다.
                degraded = (report["enrichment_missing"] or report["enrichment_broken"]
                            or problems)
                scan.failure_code = "nse_degraded" if degraded else ""
                scan.failure_message = (
                    "NSE/소켓 오류 또는 서비스 상세 산출물 손상이 있었습니다 — 포트 결과는 "
                    f"온전하지만 스크립트 결과는 일부 빠졌을 수 있습니다. ({str(degraded[0])[:120]})"
                    if degraded else ""
                )
                if unobserved:
                    # 미관측과 NSE 저하는 **다른 축**이다. 하나로 뭉치면 둘이 겹쳤을 때
                    # '포트 결과는 온전하다'고 반대로 말하게 된다 — 실제로는 그 호스트의
                    # 포트를 아예 못 봤다. 코드는 더 중요한 사실(포트 미관측)을 가리키고,
                    # 메시지는 두 사실을 모두 싣는다.
                    scan.failure_code = "observation_incomplete"
                    note = (f"응답하지 않은 호스트가 있어 발견 {unobserved}건은 관측하지 "
                            "못했습니다 - 관측하지 않은 포트는 닫지 않습니다.")
                    scan.failure_message = (
                        f"{note} 또한 NSE/서비스 상세 산출물도 일부 빠졌습니다."
                        if degraded else note
                    )
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


def is_scanops_snapshot(xml_bytes: bytes) -> bool:
    """ScanOps 가 합성한 스냅샷인가(원본 nmap 산출물이 아님).

    표식(scanops_snapshot)은 이번 버전부터 붙는다. 그 이전에 만들어져 이미 반출된 파일에는
    없지만, `_write_merged_xml` 은 처음부터 ``scanner="scanops"`` 를 써 왔다 - 그리고 nmap 은
    자기 산출물에 언제나 ``scanner="nmap"`` 을 쓴다. 단독 스캐너 결과도 nmap 이 직접 쓴
    파일이라 마찬가지다. 그래서 이 값 하나로 구형 합성물을 원본과 충돌 없이 가려낼 수 있다.
    업그레이드 이후에도 과거 반출물이 그대로 돌아오는 경로가 열려 있으면, 이 수정이 겨냥한
    '과거 관측 -> 최신 노출' 둔갑이 그대로 재현된다.
    """
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return False
    if root.tag != "nmaprun":
        return False
    return bool(root.get("scanops_snapshot")) or (root.get("scanner") or "").lower() == "scanops"


def _prepare_import_xml(xml_bytes: bytes, filename: str | None = None) -> tuple:
    """Parse every XML-derived value before creating a ScanRun or writing a file."""
    if is_scanops_snapshot(xml_bytes):
        raise _InvalidImportXML(SNAPSHOT_REJECT)
    try:
        # 시작 시각이 아니라 **관측을 끝낸** 시각이다. 몇 시간 도는 스캔에서 시작 시각을 쓰면
        # 그 사이 다른 스캔이 남긴 결과가 더 새것으로 판정되어, 이 XML 이 나중에 확인한
        # 열린 포트가 통째로 버려진다(observed_at = finished, 없으면 start).
        scan_date = observed_at(xml_bytes)
        stage = (_stage_file_info(filename) or ("", ""))[1]
        findings = [{**f, "observed_at": scan_date} for f in parse_xml(xml_bytes)]
        # 두 근거 중 하나라도 'sweep' 이라고 하면 식별 미관측으로 받는다. 파일명은 단계
        # 계약이라 정확하지만 이름이 바뀌면 뚫리고, XML 인자는 이름과 무관하게 남는다.
        sweep_only = stage == "tcp_discovery" or probed_identity(xml_bytes) is False
        if sweep_only:
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


def result_fingerprint(xml_payloads: list[bytes]) -> str:
    """가져온 결과 단위의 내용 지문.

    같은 XML 을 다시 도킹하면 같은 값이 나오도록 파일 내용만으로 계산한다(파일명·경로 무관).
    묶음은 구성 파일 지문을 정렬해 합치므로 단계 순서가 달라도 같은 값이다.
    """
    parts = sorted(hashlib.sha256(payload).hexdigest() for payload in xml_payloads)
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def _absence_from_xml(xml_bytes: bytes, hosts: set[str], when) -> dict:
    """이 XML 이 부재를 증명할 수 있는 ``(host, proto)`` 범위와 그 시각.

    커버 범위를 XML 의 host 목록에서 읽으면 안 된다 - ``--open`` 으로 돌린 산출물은 열린
    포트가 없는 호스트를 아예 싣지 않는데, 닫힘 판정이 필요한 것이 정확히 그 호스트들이다.
    그래서 범위는 호출자가 아는 것(manifest 의 closure_targets, 없으면 up 호스트)을 쓴다.
    """
    tcp, udp = xml_verdict.scan_scope(xml_bytes)
    protos = [p for p, spec in (("tcp", tcp), ("udp", udp)) if spec]
    return {(host, proto): when for host in hosts for proto in protos}


def _import_command(name: str, xml_bytes: bytes) -> str:
    """가져온 XML 의 '명령 표기' — 파일이 스스로 밝힌 범위를 정규 꼬리표로 붙인다."""
    tcp, udp = xml_verdict.scan_scope(xml_bytes)
    return f"가져온 XML · {name}  ·  {scan_summary.scope_note(tcp, udp)}"


def _import_review(scan: ScanRun, reviews: list[dict]) -> None:
    """자동 검증 결과를 스캔 행에 남긴다 — 실패가 아니라 '참고'다.

    닫힘 권한은 산출물 완결성 계약이 따로 정한다. 여기서 하는 일은 사람이 따로 도구를 돌리지
    않아도 '이 결과를 그대로 믿어도 되는가'를 보게 하는 것뿐이다. 그래서 status 는 건드리지
    않고 참고 코드만 붙인다.
    """
    flagged = [r for r in reviews if not r["usable"]]
    if not flagged:
        return
    worst = xml_verdict.worst(flagged)
    others = f" 외 {len(flagged) - 1}건" if len(flagged) > 1 else ""
    scan.failure_code = "import_unverified"
    scan.failure_message = f"[{worst['mark']}] {worst['file']}{others} - {worst['why']}"[:256]


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
    scan = ScanRun(name=f"가져오기: {name}", status="running", created_by=user.id,
                   source_fingerprint=result_fingerprint([xml_bytes]))
    stage = (_stage_file_info(name) or ("", ""))[1]
    # 가져온 스캔의 범위는 추측할 필요가 없다 - nmap 이 <scaninfo services=> 에 적어 둔다.
    # 이걸 읽지 않으면 이력이 명령 없음을 이유로 nmap 기본값(상위 1000개 TCP)을 가정해,
    # UDP 만 스캔한 XML 도 'TCP · 기본 1000개' 로 표시된다.
    scan.command = _import_command(name, xml_bytes)
    db.add(scan)
    db.commit()
    if sdate is not None:
        scan.started_at = sdate
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
            absence_at=_absence_from_xml(
                xml_bytes,
                scanned_hosts if closure_hosts is None else closure_hosts,
                sdate,
            ),
        )
    except Exception:
        _fail_import(db, scan.id, artifact_paths)
        raise
    reviews = [xml_verdict.review(xml_bytes, name, stage)]
    _import_review(scan, reviews)
    db.commit()
    record(db, user, "SCAN_IMPORT", target=name, detail=f"#{scan.id}")
    return {"scan_id": scan.id, "name": scan.name, "counts": counts,
            "files": [name], "reviews": reviews}


def _stage_artifact_name(scan_id: int, stage: str, batch: int, many: bool) -> str:
    """단계 산출물 파일명. 배치가 여럿이면 배치 번호로 갈라야 서로 덮어쓰지 않는다.

    ``stage`` 는 슬롯 이름이라 같은 배치·같은 역할의 다른 파일이면 ``#`` 뒤에 접미사가
    붙는다(단계 엔진의 ``gN`` 그룹·격리 재시도). 파일명에 ``#`` 을 그대로 쓰지는 않는다.
    """
    slot = stage.replace("#", "_")
    return f"scan_{scan_id}.b{batch}.{slot}.xml" if many else f"scan_{scan_id}.{slot}.xml"


# 역할 -> 화면이 이름을 아는 단계(Scans.jsx STAGE_LABEL). 여기 없는 역할은 그리지 않는다 -
# 이름 없는 칩을 띄우느니 빼는 편이 낫다.
_TIMELINE_STAGE = {
    ENGINE_ROLE_DISCOVERY: "discovery",
    "tcp_discovery": "tcp_discovery",
    "udp_sweep": "udp",
    "tcp_identify": "tcp_identify",
    "udp_identify": "udp_identify",
}
# 실제로 도는 순서. dict 순서에 맡기면 배치마다 칩 순서가 달라진다.
_TIMELINE_ORDER = ("discovery", "tcp_discovery", "udp", "tcp_identify", "udp_identify")


def _import_timeline(batches: list[tuple[str, dict]], prepared: list[dict]) -> list[dict]:
    """가져온 실행의 단계 타임라인 — 웹에서 돌린 단계 스캔과 같은 모양으로 보이게 한다.

    단독 스캐너로 돌린 결과라고 해서 이력에서 덜 보여 줄 이유가 없다. 어떤 단계를 어느
    배치에서 돌렸고 무엇을 찾았는지는 XML 이 다 들고 있다.
    """
    timeline = []
    for index, (base, stages) in enumerate(batches):
        # 한 배치에 같은 역할의 파일이 여럿일 수 있다(엔진의 gN 식별 그룹·격리 재시도).
        # 역할별로 **합쳐서** 한 줄로 그린다 - 정확한 슬롯 이름만 찾으면 그 산출물들이
        # 발견으로는 인입되면서 타임라인에서는 통째로 사라진다(실측: 5개 파일 -> 1줄).
        merged: dict[str, dict] = {}
        for slot, values in prepared[index].items():
            if values is None:
                continue
            stage = _TIMELINE_STAGE.get(slot.split("#", 1)[0])
            if stage is None:
                continue
            _date, findings, hosts, _tcp, _udp = values
            entry = merged.setdefault(stage, {"live": set(), "open_ports": 0})
            entry["live"] |= set(hosts)
            entry["open_ports"] += len(findings)
        for stage in _TIMELINE_ORDER:
            entry = merged.get(stage)
            if entry is None:
                continue
            timeline.append({
                "stage": stage,
                "status": "done",
                "percent": 100,
                "seconds": None,
                "counts": {"live": len(entry["live"]), "open_ports": entry["open_ports"]},
                "batch": index,
                "base": Path(base.replace("\\", "/")).name,
            })
    return timeline


class _ImportAccumulator:
    """여러 배치의 단계 산출물을 한 스캔으로 합친다.

    배치마다 같은 규칙을 반복하는 자리라, 단계별 처리를 한 곳에 모아 둔다. 포트 범위는
    배치마다 같지만(같은 실행이므로) 첫 배치에서 읽은 값을 유지하고, ``None``(=전 포트)은
    빈 집합보다 넓으므로 덮어쓰지 않는다.
    """

    def __init__(self) -> None:
        self.scanned_hosts: set[str] = set()
        self.closure_scope_keys: set[str] = set()
        # (host, proto) -> 그 부재를 확인한 시각. 배치·단계마다 다르므로 실행 전체의 min/max
        # 하나로 뭉치면 다른 배치의 시각을 빌려 오게 된다.
        self.absence_at: dict = {}
        self.tcp_scope: set[int] | None | set = set()
        self.udp_scope: set[int] | None | set = set()
        self._discovery: list[dict] = []
        self._identified: list[dict] = []
        self._udp: list[dict] = []
        # UDP 스윕은 **열림만 증명**한다. 식별과 같은 통에 담으면 stage3 가 아무것도 못 찾았을 때
        # 스윕 증거가 남지 않아 이미 열려 있던 발견이 닫힌다(실측 counts.closed=1).
        self._udp_sweep: list[dict] = []

    @staticmethod
    def _widen(current, incoming):
        if current is None or incoming is None:
            return None                       # 전 포트가 한 번이라도 나오면 전 포트다
        return set(current) | set(incoming)

    def add_batch(self, db: Session, stages: dict[str, dict], prepared: dict) -> None:
        # 호스트 발견(-sn)은 **관측 전용**이다. 어느 포트도 보지 않았으므로(산출물에
        # <scaninfo> 자체가 없다) 살아 있는 호스트만 보태고 닫힘 범위에는 넣지 않는다.
        # 한 배치에 같은 역할의 파일이 여럿일 수 있다(엔진의 gN 식별 그룹·격리 재시도).
        # 슬롯 이름은 `역할#접미사` 라 역할만 떼어 쓴다 - 레거시 단계 이름은 접미사가 없다.
        buckets = {
            "tcp_discovery": (self._discovery, False),
            "tcp_identify": (self._identified, False),
            "udp_sweep": (self._udp_sweep, True),
            "udp_identify": (self._udp, True),
        }
        order = list(buckets) + [ENGINE_ROLE_DISCOVERY]
        for slot in sorted(stages, key=lambda s: (order.index(s.split("#", 1)[0])
                                                  if s.split("#", 1)[0] in order else len(order),
                                                  s)):
            role = slot.split("#", 1)[0]
            values = prepared.get(slot)
            if values is None:
                continue
            if role == ENGINE_ROLE_DISCOVERY:
                # 호스트 발견(-sn)은 **관측 전용**이다. 어느 포트도 보지 않았으므로(산출물에
                # <scaninfo> 자체가 없다) 살아 있는 호스트만 보태고 닫힘 범위에는 넣지 않는다.
                self.scanned_hosts |= values[2]
                continue
            if role not in buckets:
                continue
            bucket, is_udp = buckets[role]
            stage_date, findings, hosts, stage_tcp_scope, stage_udp_scope = values
            self.scanned_hosts |= hosts
            bucket.extend(findings)
            item = stages[slot]
            covered = hosts if item.get("closure_hosts") is None else item["closure_hosts"]
            for key, when in _absence_from_xml(item["bytes"], covered, stage_date).items():
                current = self.absence_at.get(key)
                if key not in self.absence_at or (
                    when is not None and (current is None or when > current)
                ):
                    self.absence_at[key] = when
            if is_udp:
                self.udp_scope = self._widen(self.udp_scope, stage_udp_scope)
                tcp_arg, udp_arg = set(), stage_udp_scope
            else:
                self.tcp_scope = self._widen(self.tcp_scope, stage_tcp_scope)
                tcp_arg, udp_arg = stage_tcp_scope, set()
            self.closure_scope_keys |= _auto_scope_keys(
                db,
                hosts if item.get("closure_hosts") is None else item["closure_hosts"],
                findings,
                tcp_arg,
                udp_arg,
            )

    def findings(self) -> list[dict]:
        """식별 결과가 있으면 그것을, 없으면 sweep 이 증명한 열림을 남긴다.

        **두 프로토콜 모두 같은 규칙**이다. 한때 UDP 만 한 통에 담았는데, 그러면 식별이
        아무것도 못 찾았을 때 스윕이 증명한 열림까지 함께 사라져 이미 열려 있던 발견이
        닫혔다. 실제 실행 경로(``engine_runner.collect_results``)도 스윕을 fallback 으로
        깔고 stage3 가 **보고한 키만** 덮어쓴다 - 여기가 그 규칙과 갈리면 같은 산출물이
        돌린 경로냐 가져온 경로냐에 따라 다른 결론을 낸다. 단독 스캐너에는 UDP 스윕 단계가
        없어 그쪽은 비어 있고, 그때는 식별이 그대로 통과한다.
        """
        return [*_prefer_identified(self._identified, self._discovery),
                *_prefer_identified(self._udp, self._udp_sweep)]


def _import_stage_bundle(db: Session, user: User, display: str,
                         batches: list[tuple[str, dict[str, dict]]],
                         engine: bool = False) -> dict:
    """단독 스캐너 실행 하나 = 스캔 이력 한 줄.

    예전에는 배치마다, 심지어 단계 하나만 남은 배치마다 별도 ScanRun 이 생겼다. /24 스캔은
    열린 포트가 없는 배치가 대부분이라 tcp_discovery 파일 하나짜리 행이 이력을 가득 채웠고,
    그 행들은 아무것도 말해 주지 않으면서 자리만 차지했다. 웹에서 돌린 단계 스캔은 배치가
    몇 개든 한 줄이므로, 가져온 실행도 같아야 한다.
    """
    # Validate and derive every stage before the first DB/file side effect. One malformed
    # member invalidates the unit atomically instead of leaving a failed row and partial files.
    prepared = [
        {stage: _prepare_import_xml(item["bytes"], item["name"])
         for stage, item in stages.items()}
        for _base, stages in batches
    ]
    dates = [values[0] for per_batch in prepared for values in per_batch.values()
             if values[0] is not None]
    sdate = min(dates) if dates else None
    all_items = [item for _base, stages in batches for item in stages.values()]
    kind_label = "단계 스캔 묶음" if engine else "자동 스캔 묶음"
    scan = ScanRun(name=f"가져오기: {display} {kind_label}", status="running", created_by=user.id,
                   source_fingerprint=result_fingerprint([item["bytes"] for item in all_items]))
    # 묶음의 범위는 구성 XML 이 스스로 밝힌 것을 합친 것이다(단계마다 프로토콜이 다르다).
    bundle_tcp, bundle_udp = set(), set()
    for item in all_items:
        tcp, udp = xml_verdict.scan_scope(item["bytes"])
        if tcp:
            bundle_tcp.add(tcp)
        if udp:
            bundle_udp.add(udp)
    batch_note = f" · {len(batches)}배치" if len(batches) > 1 else ""
    flow = ("호스트 발견 → 포트 스윕 → 서비스 식별" if engine
            else "TCP 발견 → TCP 식별 → UDP 식별")
    label = "단계 스캔 XML 묶음" if engine else "자동 스캔 XML 묶음"
    scan.command = (
        f"{label} · {flow}{batch_note}  ·  "
        + scan_summary.scope_note(",".join(sorted(bundle_tcp)), ",".join(sorted(bundle_udp)))
    )
    db.add(scan)
    db.commit()
    if sdate is not None:
        scan.started_at = sdate

    many = len(batches) > 1
    merged_path = _settings.scans_dir / f"scan_{scan.id}.xml"
    artifact_paths = [
        merged_path,
        *(
            _settings.scans_dir / _stage_artifact_name(scan.id, stage, index, many)
            for index, (_base, stages) in enumerate(batches)
            for stage in stages
        ),
    ]
    try:
        acc = _ImportAccumulator()
        for index, (_base, stages) in enumerate(batches):
            for stage, item in stages.items():
                (_settings.scans_dir / _stage_artifact_name(
                    scan.id, stage, index, many)).write_bytes(item["bytes"])
            acc.add_batch(db, stages, prepared[index])

        findings = acc.findings()
        scanned_hosts = acc.scanned_hosts or {
            f["host_ip"] for f in findings if f.get("host_ip")
        }

        counts = _commit_ingest(
            db,
            scan,
            findings,
            scanned_hosts,
            acc.tcp_scope,
            acc.udp_scope,
            scan_date=sdate,
            raw_xml_path=merged_path,
            closure_scope_keys=acc.closure_scope_keys,
            absence_at=acc.absence_at,
        )
    except Exception:
        _fail_import(db, scan.id, artifact_paths)
        raise
    files = [item["name"] for _base, stages in batches for item in stages.values()]
    reviews = [xml_verdict.review(item["bytes"], item["name"], stage)
               for _base, stages in batches for stage, item in sorted(stages.items())]
    _import_review(scan, reviews)
    # 웹에서 돌린 단계 스캔과 같은 타임라인을 남긴다 - 이력에서 둘이 다르게 보일 이유가 없다.
    scan.stages_json = _import_timeline(batches, prepared)
    db.commit()
    record(db, user, "SCAN_IMPORT_BUNDLE", target=display, detail=f"#{scan.id} · {len(files)} files")
    return {"scan_id": scan.id, "name": scan.name, "counts": counts,
            "files": sorted(files), "reviews": reviews}


def _scan_history_summary(scan: ScanRun) -> dict:
    """현재 명령과 저장된 실행 사양을 합쳐 오래된 단계 스캔의 제외값까지 복원한다."""
    command = scan.command or ""
    saved = _read_engine_spec(_settings.scans_dir / f"scan_{scan.id}")
    if saved is None:
        saved = chunker.read_state(_basename(scan.id)) or {}
    excluded_ports = str(saved.get("exclude_ports") or "").strip()
    excluded_hosts = [str(host) for host in (saved.get("exclude") or []) if str(host).strip()]
    if excluded_ports and "--exclude-ports" not in command:
        command += f"  ·  --exclude-ports {excluded_ports}"
    has_excluded_hosts = bool(re.search(r"(?:^|\s)--exclude(?:\s|=)", command))
    if excluded_hosts and not has_excluded_hosts:
        command += f"  ·  --exclude {','.join(excluded_hosts)}"
    return scan_summary.summarize_command(command, scan.targets)


def _durable_retry_detail(db: Session, scan_id: int) -> dict | None:
    rows = db.query(ScanQualityIssue).filter(
        ScanQualityIssue.scan_id == scan_id,
        ScanQualityIssue.resolved_by_scan_id.is_(None),
    ).order_by(ScanQualityIssue.id).all()
    if not rows:
        return None
    retryable = [
        row for row in rows
        if row.host_ip and row.kind in {
            "host_timeout", "retransmission_cap", "service_degraded",
        }
    ]
    by_stage: dict[str, list[str]] = {}
    reasons: dict[str, list[str]] = {}
    for row in retryable:
        stage = engine_runner.canonical_stage(row.stage)
        by_stage.setdefault(stage, []).append(row.host_ip)
        reasons.setdefault(row.host_ip, []).append(row.kind)
    for stage, hosts in by_stage.items():
        by_stage[stage] = list(dict.fromkeys(hosts))
    targets = sorted(set(reasons), key=engine_runner._retry_ip_key)
    return {
        "required": bool(targets), "count": len(targets), "targets": targets,
        "by_stage": by_stage, "reasons": reasons,
        "issues": [row.issue_key for row in retryable],
    }


def _retry_history(rows: list[ScanRun], db: Session) -> dict[int, dict]:
    """Return retry state from durable exact issues, with sidecars only for legacy scans."""
    raw = {}
    children: dict[int, ScanRun] = {}
    for scan in rows:
        out_dir = _settings.scans_dir / f"scan_{scan.id}"
        raw[scan.id] = engine_runner.gave_up_detail(out_dir)
        saved = _read_engine_spec(out_dir)
        scanops = saved.get("scanops") if isinstance(saved, dict) else None
        source = scanops.get("retry_of") if isinstance(scanops, dict) else None
        if isinstance(source, int) and source > 0 and source not in children:
            children[source] = scan

    scan_ids = [scan.id for scan in rows]
    issue_rows = db.query(ScanQualityIssue).filter(
        ScanQualityIssue.scan_id.in_(scan_ids)
    ).all() if scan_ids else []
    issues_by_scan: dict[int, list[ScanQualityIssue]] = {}
    for issue in issue_rows:
        issues_by_scan.setdefault(issue.scan_id, []).append(issue)

    result = {}
    for scan in rows:
        durable = issues_by_scan.get(scan.id, [])
        if durable:
            unresolved = [issue for issue in durable if issue.resolved_by_scan_id is None]
            retry_ids = [
                issue.retry_scan_id for issue in durable if issue.retry_scan_id is not None
            ]
            retry_scan_id = max(retry_ids) if retry_ids else None
            retry_scan = next((row for row in rows if row.id == retry_scan_id), None)
            if retry_scan is None and retry_scan_id is not None:
                retry_scan = db.get(ScanRun, retry_scan_id)
            if unresolved:
                retry_status = (
                    "running" if retry_scan and retry_scan.status in {"running", "canceling"}
                    else "required"
                )
            else:
                retry_status = "resolved" if any(
                    issue.resolved_by_scan_id is not None for issue in durable
                ) else "none"
            hosts = {issue.host_ip for issue in unresolved if issue.host_ip}
            stages = list(dict.fromkeys(issue.stage for issue in unresolved if issue.stage))
            severe = any(
                issue.kind in {"command_error", "artifact_missing", "artifact_broken"}
                for issue in unresolved
            )
            result[scan.id] = {
                "retry_required": bool(unresolved) and retry_status != "running",
                "retry_count": len(hosts) or len(unresolved),
                "retry_stages": stages,
                "retry_status": retry_status,
                "retry_scan_id": retry_scan_id,
                "quality_status": "error" if severe else "warning" if unresolved else "ok",
                "unresolved_issue_count": len(unresolved),
                "unresolved_host_count": len(hosts),
            }
            continue
        detail = raw[scan.id]
        update = {
            "retry_required": detail["required"], "retry_count": detail["count"],
            "retry_stages": list(detail["by_stage"]),
            "retry_status": "required" if detail["required"] else "none",
            "retry_scan_id": None,
        }
        child = children.get(scan.id)
        if child is not None and detail["required"]:
            update["retry_scan_id"] = child.id
            child_detail = raw.get(child.id) or {}
            if child.status in {"running", "canceling"}:
                update["retry_status"] = "running"
                update["retry_required"] = False
            elif child.status == "done" and not child_detail.get("required"):
                # New scans use exact issue rows above. This branch is strictly the legacy
                # sidecar contract, retained for scans created before durable quality rows.
                update.update({"retry_status": "resolved", "retry_required": False,
                               "retry_count": 0, "retry_stages": []})
            elif child_detail.get("required"):
                update.update({
                    "retry_status": "required", "retry_required": True,
                    "retry_count": child_detail.get("count", detail["count"]),
                    "retry_stages": list((child_detail.get("by_stage") or {}).keys()),
                })
            else:
                update["retry_status"] = "failed"
        update.update({
            "quality_status": "warning" if detail["required"] else "ok",
            "unresolved_issue_count": detail["count"],
            "unresolved_host_count": detail["count"],
        })
        result[scan.id] = update
    return result


def _scan_out(scan: ScanRun, db: Session, retry: dict | None = None) -> ScanOut:
    creator = db.get(User, scan.created_by) if scan.created_by is not None else None
    if retry is None:
        retry = _retry_history(
            db.query(ScanRun).order_by(ScanRun.id.desc()).all(), db,
        ).get(scan.id, {})
    return ScanOut.model_validate(scan).model_copy(update={
        "summary": _scan_history_summary(scan),
        "created_by_name": (creator.display_name or creator.username) if creator else "",
        **retry,
    })


@router.get("", response_model=list[ScanOut])
def list_scans(_: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(ScanRun).order_by(ScanRun.id.desc()).all()
    retry = _retry_history(rows, db)
    user_ids = {row.created_by for row in rows if row.created_by is not None}
    user_names = {
        user.id: user.display_name or user.username
        for user in db.query(User).filter(User.id.in_(user_ids)).all()
    } if user_ids else {}
    return [
        ScanOut.model_validate(row).model_copy(update={
            "summary": _scan_history_summary(row),
            "created_by_name": user_names.get(row.created_by, ""),
            **retry[row.id],
        })
        for row in rows
    ]


@router.delete("/{scan_id}")
def delete_scan(
    scan_id: int,
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """스캔 이력 1건 삭제 — 그 스캔이 유일한 근거인 발견도 함께 지운다.

    '함께 지운다'의 범위를 좁게 잡는다. 발견은 여러 스캔에 걸쳐 살아 있는 물건이라,
    이 스캔에서 '다시 관측'되기만 한 발견까지 지우면 사람이 달아 둔 상태·담당자·메모와
    그 이전 이력까지 사라진다. 그래서 **첫 관측도 마지막 관측도 이 스캔인 발견**만 지우고,
    살아남는 발견은 이 스캔을 가리키던 참조만 끊는다(유령 ID 방지).

    실행 중인 스캔은 거절한다 — 워커가 아직 같은 행과 파일을 쓰고 있다.
    """
    scan = db.get(ScanRun, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="스캔을 찾을 수 없습니다.")
    if scan.status in {"running", "canceling"}:
        raise HTTPException(
            status_code=409,
            detail="실행 중인 스캔은 삭제할 수 없습니다. 먼저 중지하세요.",
        )

    # '이 스캔만이 근거인 발견'을 골라낸다. 예전에는 first·last 가 **둘 다 이 스캔**인
    # 행만 봤는데, 그러면 여러 스캔에 걸친 발견은 마지막 스캔을 지울 때 참조만 NULL 로
    # 끊긴다. 그 뒤에 남은 스캔을 지워도 조건(first==last==scan_id)에 걸리지 않아, 결국
    # **모든 스캔을 지워도 발견은 영영 남는다** - 게다가 가리키는 스캔이 없으니 지울 방법도
    # 사라진다. 조건은 '이 스캔을 지우고 나면 이 발견을 가리키는 스캔이 하나도 없는가'다.
    # NULL 은 `IN (NULL, 1)` 에 걸리지 않는다(SQL 에서 NULL 비교는 참이 아니라 '모름'이다).
    # in_ 로 적으면 이미 참조가 끊긴 행이 조용히 빠져 고치려던 버그가 그대로 남는다.
    def _gone(column):
        return or_(column.is_(None), column == scan_id)

    owned_ids = [
        row.id for row in db.query(Finding.id).filter(
            or_(Finding.first_scan_id == scan_id, Finding.last_scan_id == scan_id),
            _gone(Finding.first_scan_id), _gone(Finding.last_scan_id),
        ).all()
    ]
    # 위 버그로 이미 참조가 모두 끊긴 발견들. 어떤 스캔도 이들을 뒷받침하지 않으므로
    # 화면에 남아 있으면 '근거 없는 열린 포트'가 된다. 조용히 지우지 않고 건수를 감사와
    # 응답에 남긴다 - 지운 사실이 보여야 사람이 확인할 수 있다.
    stranded_ids = [
        row.id for row in db.query(Finding.id).filter(
            Finding.first_scan_id.is_(None), Finding.last_scan_id.is_(None),
        ).all()
    ]
    owned_ids = list(dict.fromkeys(owned_ids + stranded_ids))
    for start in range(0, len(owned_ids), 500):
        chunk = owned_ids[start:start + 500]
        db.query(FindingEvent).filter(FindingEvent.finding_id.in_(chunk)).delete(
            synchronize_session=False)
        db.query(Finding).filter(Finding.id.in_(chunk)).delete(synchronize_session=False)
    # 살아남는 발견/이벤트가 사라진 스캔을 가리키지 않게 한다.
    kept_events = db.query(FindingEvent).filter(FindingEvent.scan_id == scan_id).update(
        {FindingEvent.scan_id: None}, synchronize_session=False)
    db.query(Finding).filter(Finding.first_scan_id == scan_id).update(
        {Finding.first_scan_id: None}, synchronize_session=False)
    db.query(Finding).filter(Finding.last_scan_id == scan_id).update(
        {Finding.last_scan_id: None}, synchronize_session=False)

    db.delete(scan)
    stranded_note = f" (근거 없이 남아 있던 {len(stranded_ids)}건 포함)" if stranded_ids else ""
    record(db, user, "SCAN_DELETE", target=str(scan_id),
           detail=f"발견 {len(owned_ids)}건 삭제{stranded_note}")
    # 파일은 커밋이 끝난 뒤에 지운다. 먼저 지우면 커밋이 실패했을 때 DB 행은 살아 있는데
    # 그 행이 가리키는 증거 파일만 사라져, 되돌릴 수도 확인할 수도 없는 상태가 된다.
    artifacts = _scan_artifact_paths(scan)
    db.commit()
    _remove_paths(artifacts)
    return {"scan_id": scan_id, "findings_deleted": len(owned_ids),
            "stranded_removed": len(stranded_ids),
            "events_detached": int(kept_events or 0)}


def _scan_artifact_paths(scan: ScanRun) -> list[Path]:
    """이 스캔이 남긴 파일/폴더 경로. 삭제 전에 미리 모아 둔다 — 커밋 뒤에는 ORM 객체의
    속성을 더 읽을 수 없기 때문이다(만료된 인스턴스)."""
    paths = [Path(v) for v in (scan.raw_xml_path, scan.log_path) if v]
    paths.append(_settings.scans_dir / f"scan_{scan.id}")
    return paths


def _remove_paths(paths: list[Path]) -> None:
    """파일 정리. 실패해도 예외를 올리지 않는다 — DB 는 이미 커밋됐고, 여기서 실패해도
    남는 것은 고아 파일뿐이라 되돌리는 것보다 로그를 남기고 넘어가는 편이 안전하다."""
    for path in paths:
        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
        except OSError:
            logger.warning("failed to remove scan artifact %s", path, exc_info=True)


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
    return _scan_out(scan, db)


@router.post("/known-results")
def known_results(
    body: KnownResultsIn,
    _: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
) -> dict:
    """이미 가져온 결과의 지문을 알려 준다 — 단독 스캐너 도킹의 중복 인입 방지용.

    스캐너가 매번 폴더 전체를 올리면 같은 결과로 스캔 이력이 불어나고 닫힘 판정이 다시 돈다.
    올리기 전에 이 목록을 빼면 새 결과만 전송된다. 지문은 XML 내용만으로 계산하므로 파일을
    다른 경로로 복사해 와도 같은 결과로 인식된다.
    """
    wanted = {f for f in body.fingerprints if isinstance(f, str) and f}
    if not wanted:
        return {"known": []}
    if len(wanted) > 5000:
        raise HTTPException(status_code=400, detail="한 번에 확인할 수 있는 지문은 5000개까지입니다.")
    # 실패로 끝난 인입은 '가져온 것'이 아니다 — 그렇게 세면 재시도가 영구히 막힌다.
    rows = db.query(ScanRun.source_fingerprint).filter(
        ScanRun.source_fingerprint.in_(wanted), ScanRun.status == "done",
    ).all()
    return {"known": sorted({row[0] for row in rows if row[0]})}


@router.post("/import", response_model=IngestSummary)
async def import_xml(
    file: UploadFile = File(...),
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    if is_interrupted_upload(file.filename):
        record(db, user, "SCAN_IMPORT", target=file.filename or "", detail="중단본 거절", ok=False)
        raise HTTPException(status_code=400, detail=INTERRUPTED_REJECT)
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
    return IngestSummary(scan_id=result["scan_id"], counts=result["counts"],
                         reviews=result.get("reviews", []))


@router.post("/import-bundle")
async def import_xml_bundle(
    files: list[UploadFile] = File(...),
    skip_known: bool = False,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    """XML 묶음 가져오기.

    skip_known=true(단독 스캐너 도킹)면 이미 같은 내용을 가져온 단위는 건너뛴다. **중복 판정은
    서버가 한다** — import 단위를 나누는 것도 서버(_stage_file_info 기준 base 묶음)이므로,
    클라이언트가 자기 방식으로 묶어 지문을 내면 배치 스캔처럼 단위가 갈라지는 순간 판정이
    어긋나 같은 결과가 다시 인입된다.
    """
    payloads = []
    manifests = []
    total_bytes = 0
    for f in files:
        name = f.filename or "scan.xml"
        lower_name = name.lower()
        if not (lower_name.endswith(".xml") or lower_name.endswith(".manifest.json")):
            continue
        # 폴더째 가져오기는 `interrupted/` 까지 재귀로 딸려 온다. 조용히 섞이면
        # 부분 결과가 온전한 결과와 같은 무게로 인입된다.
        if is_interrupted_upload(name):
            record(db, user, "SCAN_IMPORT", target=name, detail="중단본 거절", ok=False)
            raise HTTPException(status_code=400, detail=INTERRUPTED_REJECT)
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
    # 단계 엔진 산출물은 **폴더 하나가 실행 하나**다: {폴더: {배치: {역할: item}}}.
    # 파일명 base 로 묶는 STAGE_FILE_RE 규칙이 통하지 않아, 예전에는 파일마다 별도 스캔
    # 행이 생겼다(결과 폴더 4개 파일 -> 이력 4줄).
    engine: dict[str, dict[str, dict[str, dict]]] = {}
    units: list[dict] = []
    for item in payloads:
        engine_info = _engine_stage_info(item["name"])
        if engine_info:
            run_key, batch_key, role = engine_info
            engine.setdefault(run_key, {}).setdefault(batch_key, {})[role] = item
            continue
        info = _stage_file_info(item["name"])
        if not info:
            units.append({"kind": "single", "sort": item["name"], "item": item})
            continue
        base, stage = info
        grouped.setdefault(base, {})[stage] = item
    for run_key, batches in sorted(engine.items(), key=lambda kv: kv[0].lower()):
        units.append({
            "kind": "bundle", "sort": run_key, "base": run_key, "engine": True,
            # 실제 배치 순서대로. 문자열 정렬이면 b10 이 b2 앞에 온다.
            "batches": sorted(batches.items(), key=lambda kv: int(kv[0][1:])),
        })
    if grouped:
        if manifests:
            # manifest 하나 = 단독 스캐너 실행 하나. 배치가 몇 개든 이력에는 한 줄이어야
            # 웹에서 돌린 단계 스캔과 같아진다. 예전에는 배치마다 행이 생겼고, 열린 포트가
            # 없어 tcp_discovery 파일 하나만 남은 배치까지 각자 행을 차지해서 이력이
            # 아무 말도 하지 않는 줄로 가득 찼다.
            run_name = Path(manifests[0]["name"].replace("\\", "/")).name
            run_name = run_name[:-len(".manifest.json")] if run_name.lower().endswith(
                ".manifest.json") else run_name
            units.append({
                "kind": "bundle", "sort": run_name, "base": run_name,
                "batches": sorted(grouped.items(), key=lambda kv: kv[0].lower()),
            })
        else:
            # manifest 가 없으면 어떤 파일들이 한 실행인지 단언할 근거가 없다. 파일명 base 로만
            # 묶고, 그 이상은 넘겨짚지 않는다.
            for base, stages in sorted(grouped.items(), key=lambda kv: kv[0].lower()):
                units.append({"kind": "bundle", "sort": base, "base": base,
                              "batches": [(base, stages)]})

    total = _zero_counts()
    imported = []
    failed = []
    skipped = []
    for unit in sorted(units, key=lambda u: str(u["sort"]).lower()):
        if skip_known:
            payload_bytes = ([unit["item"]["bytes"]] if unit["kind"] == "single"
                             else [member["bytes"]
                                   for _base, stages in unit["batches"]
                                   for member in stages.values()])
            fingerprint = result_fingerprint(payload_bytes)
            # **성공한 인입만** 이미 가져온 것으로 본다. _fail_import 는 실패해도 지문을 남긴 채
            # status="failed" 로 행을 보존하므로, 상태를 보지 않으면 일시적인 디스크/DB 오류 한 번이
            # 그 결과를 영구히 건너뛰게 만든다 — 스캐너에는 "이미 가져온 결과"로 보여 유실이 조용하다.
            if db.query(ScanRun.id).filter(
                ScanRun.source_fingerprint == fingerprint, ScanRun.status == "done",
            ).first():
                skipped.append(str(unit["sort"]))
                continue
        try:
            if unit["kind"] == "bundle":
                result = _import_stage_bundle(
                    db, user, Path(unit["base"].replace("\\", "/")).name, unit["batches"],
                    engine=bool(unit.get("engine")))
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
    if not imported and failed and not skipped:
        raise HTTPException(status_code=400, detail=f"XML 파싱 실패: {failed[0]['error']}")
    return {
        "imported": len(imported),
        "failed": len(failed),
        "skipped": len(skipped),
        "skipped_units": skipped,
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
            # nmap 프로세스당 상한(초, 0=끔). 호스트 상한을 뺀 자리에 두는 제어라
            # 레거시/자동 워크플로에서도 켤 수 있어야 한다.
            "watchdog_seconds": int(body.watchdog_seconds or 0),
        })
        # 명령 표기는 대표(타겟·-oA 제외) — 호스트 수/배치 수를 덧붙여 가독.
        if body.workflow == "auto":
            stages = []
            tcp_spec = nmap_runner.auto_tcp_port_spec(body.ports)
            udp_spec = nmap_runner.auto_udp_port_spec(body.ports)
            if tcp_spec:
                stages.extend([AUTO_STAGE_LABELS["tcp_discovery"], AUTO_STAGE_LABELS["tcp_identify"]])
            if udp_spec:
                label = AUTO_STAGE_LABELS["udp_identify"]
                if body.udp_all_targets:
                    label += "(전체 타깃)"
                stages.append(label)
            # 설명 문구만 남기면 이력 요약이 이것을 argv 로 오인해 '기본 1000개 TCP' 라고
            # 단언한다. 실제 범위는 여기서만 알 수 있으므로 함께 적는다.
            scan.command = (
                f"자동 스캔 · {' → '.join(stages)}  ·  {len(hosts)}호스트 / {len(batches)}배치"
                f"  ·  {scan_summary.scope_note(tcp_spec, udp_spec)}"
            )
            if exclude_ports:
                scan.command += f"  ·  --exclude-ports {exclude_ports}"
            if excludes:
                scan.command += f"  ·  --exclude {','.join(excludes)}"
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
        if excludes and body.workflow != "auto":
            scan.command += f"  ·  제외 {', '.join(excludes)}"
        # 배치 구성은 실행이 끝나면 sidecar 와 함께 사라진다. 이력이 나중에도 '어떻게
        # 돌았는지'를 말할 수 있게 스캔 행에 남긴다.
        scan.batch_total = len(batches)
        scan.batch_size = max((len(b) for b in batches), default=0)
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
            exclude_ports=body.exclude_ports,
            watchdog_seconds=body.watchdog_seconds,
        )
        tcp_scope = _port_scope(nmap_runner.auto_tcp_port_spec(body.ports), "T")
        udp_scope = (_port_scope(nmap_runner.auto_udp_port_spec(body.ports), "U")
                     if "udp" in body.options else set())
        spec["scanops"] = {
            # Empty is meaningful: this scan must not close any pre-existing finding.
            # 제외한 포트는 프로브를 보내지 않으므로 닫힘 후보에서도 빼야 한다.
            "scope_keys": sorted(_auto_scope_keys(
                db, set(hosts), [], tcp_scope, udp_scope,
                tcp_excluded=_excluded_port_scope(body.exclude_ports, "T"),
                udp_excluded=_excluded_port_scope(body.exclude_ports, "U"),
            )),
        }
        (out_dir / "spec.json").write_text(json.dumps(spec, ensure_ascii=False), encoding="utf-8")
        scan.command = f"{engine_runner.describe(spec)}  ·  {len(hosts)}호스트"
        exclude_ports = scan_options.validate_ports(body.exclude_ports or "")
        if exclude_ports:
            scan.command += f"  ·  --exclude-ports {exclude_ports}"
        if excludes:
            scan.command += f"  ·  --exclude {','.join(excludes)}"
        # 엔진도 같은 대역을 배치로 나눠 sweep 한다(stage-tcp-b0.xml …). 청킹 스캔과 같은
        # 자리에 같은 뜻으로 남겨야 이력에서 둘을 나란히 읽을 수 있다.
        scan.batch_size = int(spec.get("batch_size") or 0)
        scan.batch_total = (
            -(-len(hosts) // scan.batch_size) if scan.batch_size and hosts else 0
        )
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


@router.post("/{scan_id}/retry-timeouts", response_model=ScanOut)
def retry_timed_out_hosts(
    scan_id: int,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    """Start a new staged scan containing only hosts retained in the retry queue."""
    source = db.get(ScanRun, scan_id)
    if source is None:
        raise HTTPException(status_code=404, detail="스캔을 찾을 수 없습니다.")
    if source.status in {"running", "canceling"}:
        raise HTTPException(status_code=400, detail="원본 스캔이 끝난 뒤 재스캔할 수 있습니다.")
    source_dir = _settings.scans_dir / f"scan_{source.id}"
    if not engine_runner.is_engine_scan(source_dir):
        raise HTTPException(status_code=400, detail="단계 엔진 스캔만 확인 필요 대상을 재스캔할 수 있습니다.")

    rows = db.query(ScanRun).order_by(ScanRun.id.desc()).all()
    history = _retry_history(rows, db).get(source.id) or {}
    if history.get("retry_status") == "running":
        raise HTTPException(status_code=400, detail="확인 필요 대상 재스캔이 이미 진행 중입니다.")
    if history.get("retry_status") == "resolved":
        raise HTTPException(status_code=400, detail="확인 필요 대상 재스캔이 이미 완료되었습니다.")
    retry = _durable_retry_detail(db, source.id)
    if retry is None:
        retry_evidence_dir = source_dir
        child_id = history.get("retry_scan_id")
        if history.get("retry_required") and isinstance(child_id, int):
            child_dir = _settings.scans_dir / f"scan_{child_id}"
            if engine_runner.gave_up_detail(child_dir)["required"]:
                retry_evidence_dir = child_dir
        retry = engine_runner.gave_up_detail(retry_evidence_dir)
    if not retry["required"]:
        raise HTTPException(status_code=400, detail="재스캔이 필요한 확인 대상이 없습니다.")

    try:
        saved = _load_engine_spec(source_dir / "spec.json")
        targets = list(retry["targets"])
        nmap_runner.validate_targets(targets)
        scope.check_scope(targets)
        engine_runner.ensure_available()
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not nmap_runner.find_nmap(_settings.nmap_path):
        raise HTTPException(status_code=400, detail="서버에서 nmap 을 찾을 수 없습니다.")

    scan = ScanRun(
        name=f"확인 필요 재스캔 #{source.id} · {len(targets)}대",
        targets=" ".join(targets), status="running", created_by=user.id,
    )
    db.add(scan)
    db.flush()
    retry_stage_set = {
        engine_runner.canonical_stage(stage)
        for stage in retry["by_stage"] if isinstance(stage, str)
    }
    selected_issue_keys = [
        issue.issue_key
        for issue in db.query(ScanQualityIssue).filter(
            ScanQualityIssue.scan_id == source.id,
            ScanQualityIssue.resolved_by_scan_id.is_(None),
        ).all()
        if issue.host_ip in set(targets)
        and engine_runner.canonical_stage(issue.stage) in retry_stage_set
    ]
    observability.set_quality_retry(
        db, source.id, scan.id, issue_keys=selected_issue_keys,
    )
    db.commit()
    db.refresh(scan)
    out_dir = _settings.scans_dir / f"scan_{scan.id}"
    launch_paths = [out_dir / "spec.json", out_dir / "run-state.json", out_dir / "stop-requested"]
    try:
        spec = json.loads(json.dumps(saved))
        spec.update({
            "job_id": f"scan_{scan.id}", "targets": targets, "exclude": [],
            "out_dir": str(out_dir), "targets_ports": None, "rescan_units": None,
        })
        stages = spec.setdefault("stages", {})
        stages.setdefault("discovery", {}).update({"enabled": True, "mode": "pn"})
        retry_stages = set(retry["by_stage"])
        if retry_stages and "discovery" not in retry_stages:
            for proto in ("tcp", "udp"):
                needed = proto in retry_stages or f"service:{proto}" in retry_stages
                needed = needed or f"{proto}_service" in retry_stages
                stage_spec = stages.get(proto)
                if isinstance(stage_spec, dict):
                    stage_spec["enabled"] = bool(stage_spec.get("enabled")) and needed
        for stage_name in ("tcp", "udp", "service"):
            stage_spec = stages.get(stage_name)
            if isinstance(stage_spec, dict):
                stage_spec["max_retries"] = 4
        scanops = spec.setdefault("scanops", {})
        original_keys = scanops.get("scope_keys") or []
        target_set = set(targets)
        enabled_protocols = {
            proto for proto in ("tcp", "udp")
            if isinstance(stages.get(proto), dict) and stages[proto].get("enabled")
        }
        scanops["scope_keys"] = [
            key for key in original_keys
            if (isinstance(key, str) and key.split("|", 1)[0] in target_set
                and key.rsplit("|", 1)[-1] in enabled_protocols)
        ]
        scanops.update({
            "retry_of": source.id, "retry_stages": list(retry["by_stage"]),
            "retry_targets": targets,
        })
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "spec.json").write_text(json.dumps(spec, ensure_ascii=False), encoding="utf-8")
        scan.command = (
            f"{engine_runner.describe(spec)}  ·  {len(targets)}호스트"
            f"  ·  확인 필요 재스캔 #{source.id} · --max-retries 4"
        )
        scan.batch_size = int(spec.get("batch_size") or 0)
        scan.batch_total = -(-len(targets) // scan.batch_size) if scan.batch_size else 0
        db.commit()
        db.refresh(scan)
        threading.Thread(target=_engine_worker, args=(scan.id,), daemon=True).start()
    except Exception:
        _fail_launch_setup(db, scan.id, user, scan.targets, launch_paths, artifact_dirs=[out_dir])
    record(
        db, user, "SCAN_RETRY_TIMEOUTS", target=scan.targets,
        detail=f"#{source.id} → #{scan.id} · {len(targets)}대 · {','.join(retry['by_stage'])}",
    )
    return _scan_out(scan, db)


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
    # 단계 엔진에는 sidecar cursor 가 없다. 배치 진행은 산출물이 기록하고 있으므로 그걸 센다.
    engine_dir = _settings.scans_dir / f"scan_{scan_id}"
    if not has_batches and scan.batch_total:
        total = scan.batch_total
        saved_spec = _read_engine_spec(engine_dir)
        # 분자와 분모는 같은 모집단이어야 한다. batch_total 은 discovery 이전의 전체 대상으로
        # 센 값이고, swept_batches 는 live 로 실제 만들어진 산출물을 센다. 그대로 나란히 두면
        # 없는 배치를 진행 중이라고 말한다 - live 를 알게 된 뒤에는 그쪽으로 갈아탄다.
        if saved_spec and (live_total := engine_runner.swept_total(engine_dir, saved_spec)):
            total = live_total
        done = (total if scan.status == "done"
                else engine_runner.swept_batches(engine_dir, saved_spec) if saved_spec else 0)
        has_batches = True
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
    # 지금 무엇을 보고 있는지. 퍼센트 하나만으로는 몇 분째 같은 숫자를 보면서 진행 중인지
    # 멈춘 것인지조차 알 수 없다 - 현재 배치가 어느 대역이고 어느 단계인지를 함께 준다.
    batch_hosts: list[str] = []
    # 배치 대역은 sidecar 에만 있다. 단계 엔진은 batch_total 로 진행만 세므로(state 없음)
    # 여기서 대역까지 지어내지 않는다.
    stored = (state or {}).get("batches")
    if isinstance(stored, list) and 0 <= done < len(stored):
        current = stored[done]
        batch_hosts = [str(h) for h in current] if isinstance(current, list) else []
    started = _scan_started_at(scan)
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
        "stage": (state or {}).get("stage", ""),
        "stage_hosts": (state or {}).get("stage_hosts") or None,
        "batch_hosts": len(batch_hosts),
        "batch_size": scan.batch_size or (len(batch_hosts) or None),
        "batch_label": _target_label(batch_hosts),
        "elapsed_seconds": (
            round((datetime.now(timezone.utc) - started).total_seconds())
            if started is not None and scan.status in ("running", "canceling") else None
        ),
        # 호스트당 상한을 넘겨 포기당한 호스트. 이 실행에서는 부재를 말할 자격이 없고
        # 나중에 따로 다시 스캔할 대상이라, 진행 상황과 함께 꺼내 볼 수 있어야 한다.
        "gave_up": engine_runner.gave_up_detail(
            _settings.scans_dir / _basename(scan.id)
        )["targets"],
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
    durable_executions = db.query(ScanExecution).filter_by(scan_id=scan_id).order_by(
        ScanExecution.id
    ).all()
    durable_issues = db.query(ScanQualityIssue).filter_by(scan_id=scan_id).order_by(
        ScanQualityIssue.id
    ).all()
    durable_hosts = db.query(ScanHostObservation).filter_by(scan_id=scan_id).order_by(
        ScanHostObservation.host_ip
    ).all()
    terminal = scan.status not in {"running", "canceling"}
    use_db = terminal and bool(durable_executions or durable_issues or durable_hosts)
    stages = (scan.stages_json or []) if use_db else derived["stages"] or (scan.stages_json or [])
    overall = dict(derived["overall"])
    retry = engine_runner.gave_up_detail(out_dir)
    if use_db:
        executions = [{
            "id": row.execution_key, "stage": row.stage, "group": row.group_kind,
            "role": row.role, "reason": row.reason, "artifact": row.artifact,
            "argv": row.argv_json or [], "status": row.status,
            "started_at": row.started_at, "finished_at": row.finished_at,
            "seconds": row.seconds, "rc": row.return_code,
        } for row in durable_executions]
        issues = [{
            "issue_key": row.issue_key, "type": row.kind, "stage": row.stage,
            "host": row.host_ip, "status": "resolved" if row.resolved_by_scan_id is not None
            else "retrying" if row.retry_scan_id is not None else "unresolved",
            "message": row.detail, "retry_scan_id": row.retry_scan_id,
            "resolved_by_scan_id": row.resolved_by_scan_id,
        } for row in durable_issues]
        hosts = [{
            "host_ip": row.host_ip, "discovery_status": row.discovery_status,
            "tcp_sweep_status": row.tcp_sweep_status,
            "tcp_service_status": row.tcp_service_status,
            "udp_sweep_status": row.udp_sweep_status,
            "udp_service_status": row.udp_service_status,
        } for row in durable_hosts]
        unresolved = [issue for issue in issues if issue["status"] != "resolved"]
        retry = {
            "required": bool(unresolved), "count": len({
                issue["host"] for issue in unresolved if issue["host"]
            }) or len(unresolved),
            "targets": sorted({issue["host"] for issue in unresolved if issue["host"]}),
            "by_stage": {}, "reasons": {}, "issues": unresolved,
        }
        for issue in unresolved:
            retry["by_stage"].setdefault(issue["stage"], []).append(issue["host"])
    else:
        executions = derived.get("executions") or []
        issues = derived.get("quality_issues") or []
        hosts = []
    # The database lifecycle is authoritative. An empty/truncated event stream must not make a
    # terminal scan look like it is still running after a restart or worker failure.
    overall["status"] = scan.status
    # 같은 이유가 실행 기록에도 적용된다. 엔진이 command_start 를 남기고 command_done 을
    # 못 남긴 채 죽으면(프로세스 강제 종료, 머신 손실) 그 실행은 계속 '실행 중' 이고,
    # 경과시간이 폴링할 때마다 늘어난다 - 스캔이 이미 실패로 마감된 뒤에도 그렇다.
    # 생산자 쪽은 예외 경로에서 닫도록 고쳤지만(pipeline._nmap), 그쪽이 손쓸 수 없는
    # 종료도 있으므로 여기서 한 번 더 막는다.
    if scan.status not in ("running", "canceling"):
        for execution in executions:
            if execution.get("status") == "running":
                execution["status"] = "error"
                execution["interrupted"] = True
    return {
        "scan_id": scan_id,
        "status": scan.status,
        "kind": "staged" if use_db or engine_runner.is_engine_scan(out_dir) else "legacy_or_import",
        "source": "db" if use_db else "live_events" if not terminal else "legacy_events",
        "timeline_available": bool(stages),
        "stages": stages,
        "overall": overall,
        "current": derived.get("current") or {},
        "executions": executions,
        "issues": issues,
        "recoveries": derived.get("recoveries") or [],
        "hosts": hosts,
        "failure_code": scan.failure_code,
        "failure_message": scan.failure_message,
        "host_count": scan.host_count,
        "port_count": scan.port_count,
        "finished_at": scan.finished_at,
        # 완료 후에도 다시 스캔할 타겟을 복사할 수 있도록 상세 응답에 남긴다.
        "gave_up": retry["targets"],
        "retry": retry,
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
