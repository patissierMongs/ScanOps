#!/usr/bin/env python3
"""이미 닫힌 발견 중 '실제로 닫혔는지 확인되지 않은' 것을 찾는다 - 읽기 전용 dry-run.

ScanOps 는 부재로 닫는다: 완결됐다고 판단한 스캔에서 안 보인 포트를 닫힌 것으로 본다.
그 판단이 틀렸던 시기(산출물 완결성 게이트 이전)에는, 중간에 끊긴 스캔이 '관측 0건'으로
통과해 열린 포트를 닫아 버릴 수 있었다. 닫힘은 status 까지 '정상처리'로 바꾸므로 되돌리기
가장 어려운 미탐이다.

이 스크립트는 **아무것도 바꾸지 않는다.** CLOSED 이벤트를 그 스캔의 원본 산출물과 대조해
'근거가 확인되는 닫힘'과 '근거를 확인할 수 없는 닫힘'을 가른다. 결과를 보고 재스캔할지는
사람이 정한다 - 재스캔해서 여전히 열려 있으면 인입이 REOPENED 로 되살린다.

판정 규칙 두 가지가 이 도구의 전부다.

1. **있는 파일이 아니라 만들기로 한 집합과 대조한다.** spec.json + run-state.json 에서
   그 실행이 만들기로 한 authority 산출물을 세우고, 부재와 손상을 똑같이 취급한다.
   완결된 discovery 하나만 남고 sweep 이 통째로 없는 디렉터리를 '확인됨'이라 하면,
   이 도구가 검출하려는 바로 그 오류를 스스로 저지르는 것이다.
2. **그 닫힘이 실제로 그 실행의 관측 범위 안이었는지 본다.** 다른 호스트·다른 포트의
   완결 XML 하나로 같은 scan 의 모든 닫힘을 확인해 줄 수는 없다.

메타데이터가 없어 위 둘을 증명할 수 없으면 '확인 불가'다. 모르는 것을 확인됨으로 넘겨짚지
않는 것이 이 도구의 존재 이유다.

**주의**: scan_runs.raw_xml_path 를 완결성 근거로 쓰지 않는다. 자동 배치.staged 경로에서
그 파일은 우리가 재구성한 병합본이고 _write_merged_xml 이 원본 실행이 어땠든 항상
exit="success" 를 찍는다.

사용:
    AUDIT.bat                                       (에어갭 번들: 번들 data 를 자동으로 본다)
    python scripts/audit_closures.py --list
    python scripts/audit_closures.py --db /경로/scanops.db --scans /경로/scans
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import sqlite3
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _cp949_note() -> None:
    """한국어 Windows 콘솔(CP949) 대응은 **출력 문자 자체를 제한**하는 것으로 한다.

    처음에는 sys.stdout 을 UTF-8 로 reconfigure 했지만 그건 전역 스트림을 바꾸는 일이라,
    캡처된 스트림(테스트 러너·파이프)에서 예기치 않게 동작한다. CP949 로 표현 가능한 글자만
    쓰면 보정 자체가 필요 없다(em dash 대신 하이픈). 그 규칙은 테스트로 고정돼 있다.

    번들 런처는 별도로 chcp 65001 + PYTHONIOENCODING 을 걸어 한글이 제대로 그려지게 한다.
    """


def _xml_finished(path: Path) -> bool:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return False
    finished = root.findall("./runstats/finished")
    return len(finished) == 1 and finished[0].get("exit") == "success"


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _ports(spec_value: object) -> set[int] | None:
    """포트 스펙 문자열 -> 포트 집합. 해석할 수 없으면 None(= 범위를 모른다)."""
    text = str(spec_value or "").strip()
    if not text:
        return None
    out: set[int] = set()
    for chunk in text.replace("T:", "").replace("U:", "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            if "-" in chunk:
                lo, hi = (int(x) for x in chunk.split("-", 1))
                out.update(range(lo, hi + 1))
            else:
                out.add(int(chunk))
        except ValueError:
            return None
    return out or None


def _stage3_path(out_dir: Path, ip: str, tag: str, confirm: bool = False) -> Path:
    return out_dir / f"stage3-{ip.replace('.', '_')}-{tag}{'-confirm' if confirm else ''}.xml"


def _probe_found_nothing(path: Path) -> bool:
    """이 stage3 가 '완결됐지만 아무것도 못 찾은' 결과인가."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return False
    return not [el for el in root.findall("./host/ports/port/state")
                if (el.get("state") or "").startswith("open")]


def _stage3_expected(out_dir: Path, ip: str, tag: str, confirm: bool) -> list[Path]:
    """운영 게이트(engine_runner._stage3_expected)와 **같은 규칙**으로 확인 패스를 센다.

    확인 패스는 1차가 빈손일 때만 돈다(pipeline._probe_unit 의 `sp.confirm and not found`).
    무조건 기대하면 1차에서 서비스를 찾은 정상 재스캔이 전부 부재 판정되고, 아예 안 세면
    확인 패스가 실패했던 과거 재스캔의 닫힘을 정상 근거로 인증하게 된다.
    """
    base = _stage3_path(out_dir, ip, tag)
    expected = [base]
    if confirm and base.exists() and _xml_finished(base) and _probe_found_nothing(base):
        expected.append(_stage3_path(out_dir, ip, tag, confirm=True))
    return expected


def expected_authority(out_dir: Path, spec: dict, state: dict) -> list[Path] | None:
    """이 실행이 만들기로 한 포트-관측 산출물. 계산할 수 없으면 None."""
    stages = spec.get("stages") or {}
    confirm = bool(((stages.get("service") or {}).get("confirm", False)))
    if spec.get("rescan_units"):
        # 선택 재스캔은 sweep 이 없고 stage3 가 유일한 근거다.
        paths = []
        for unit in spec["rescan_units"]:
            try:
                ip, port = str(unit["ip"]), int(unit["port"])
            except (KeyError, TypeError, ValueError):
                return None
            proto = str(unit.get("proto") or "tcp")
            paths += _stage3_expected(out_dir, ip, f"{proto}{port}", confirm)
        return paths
    if spec.get("targets_ports"):
        paths = []
        for ip in spec["targets_ports"]:
            paths += _stage3_expected(out_dir, str(ip), "tcp", confirm)
        return paths

    disc = stages.get("discovery") or {}
    runs_discovery = disc.get("enabled", True) and disc.get("mode", "sn") != "pn"
    expected = [out_dir / "stage0-discovery.xml"] if runs_discovery else []
    live = [h for h in (state.get("live") or []) if isinstance(h, str)]
    if not live:
        # sweep 기대치를 셀 수 없다. discovery 조차 없으면 아무것도 증명하지 못한다.
        return expected or None
    batch = max(1, int(spec.get("batch_size") or 256))
    count = math.ceil(len(live) / batch)
    for proto in ("tcp", "udp"):
        if (stages.get(proto) or {}).get("enabled", True):
            expected += [out_dir / f"stage-{proto}-b{i}.xml" for i in range(count)]
    return expected


def _covers(spec: dict, state: dict, host_ip: str, port: int, proto: str) -> bool | None:
    """이 닫힘이 그 실행의 관측 범위 안이었는가. 안전하게 판단할 수 없으면 None.

    실행 당시의 **정확한** 권한 목록이 있으면 그것을 쓴다. spec 의 scanops.scope_keys 가
    ingest 에 실제로 넘어간 닫힘 후보 집합이므로(api/findings._start_engine_rescan,
    api/scans 의 staged 경로), 근사한 target/포트 범위로 덮으면 같은 host 의 다른 포트까지
    '확인됨'이 된다.
    """
    scope_keys = ((spec.get("scanops") or {}).get("scope_keys"))
    if isinstance(scope_keys, list):
        return f"{host_ip}|{port}|{proto}" in set(scope_keys)

    if spec.get("rescan_units"):
        return any(str(u.get("ip")) == host_ip and int(u.get("port", -1)) == port
                   and str(u.get("proto") or "tcp") == proto
                   for u in spec["rescan_units"])
    if spec.get("targets_ports"):
        ports = spec["targets_ports"].get(host_ip)
        return proto == "tcp" and ports is not None and port in {int(p) for p in ports}

    live = {h for h in (state.get("live") or []) if isinstance(h, str)}
    if live:
        if host_ip not in live:
            return False
    else:
        targets = [str(t) for t in (spec.get("targets") or [])]
        nets = [t for t in targets if _is_network(t)]
        if not nets:
            return None                      # 대상 범위를 해석할 수 없다
        try:
            addr = ipaddress.ip_address(host_ip)
        except ValueError:
            return None
        if not any(addr in ipaddress.ip_network(t, strict=False) for t in nets):
            return False
    stage = (spec.get("stages") or {}).get(proto) or {}
    if not stage.get("enabled", True):
        return False
    scope = _ports(stage.get("ports"))
    return True if scope is None else port in scope


def _scaninfo_scope(root, proto: str) -> set[int] | None:
    """업로드 XML 의 <scaninfo protocol services=> 범위. 없으면 None(=범위를 모른다).

    nmap XML 은 실제로 이 범위를 담고 있고 서버 인입도 _scaninfo_scope 로 같은 값을 써서
    닫힘 후보를 만든다. host 만 비교하면 TCP/22 만 스캔한 XML 이 같은 host 의 TCP/23
    닫힘까지 보증하게 된다.
    """
    scopes = []
    for info in root.findall("scaninfo"):
        if (info.get("protocol") or "").lower() != proto:
            continue
        services = (info.get("services") or "").strip()
        if services:
            scopes.append(_ports(services))
    if not scopes or any(x is None for x in scopes):
        return None
    merged: set[int] = set()
    for x in scopes:
        merged.update(x)
    return merged


def _is_network(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return True


def _upload_covers(state: dict, host_ip: str, port: int, proto: str) -> bool | None:
    """업로드 XML 이 이 (host, port, proto) 를 실제로 스캔했는가."""
    if host_ip not in set(state.get("live") or []):
        return False
    scope = (state.get("scaninfo") or {}).get(proto)
    if scope is None:
        return None                          # 범위를 모른다 - 넘겨짚지 않는다
    return port in scope


def scan_evidence(scans_dir: Path, scan_id: int) -> tuple[str, str, dict, dict]:
    """(판정, 이유, spec, state) - 이 스캔의 닫힘 근거를 믿을 수 있는가."""
    out_dir = scans_dir / f"scan_{scan_id}"
    uploaded = scans_dir / f"scan_{scan_id}.xml"
    spec = _read_json(out_dir / "spec.json")
    state = _read_json(out_dir / "run-state.json")

    if spec:
        expected = expected_authority(out_dir, spec, state)
        if expected is None:
            return ("확인 불가", "spec/run-state 로 기대 산출물을 셀 수 없습니다.", spec, state)
        missing = [p.name for p in expected if not p.exists()]
        broken = [p.name for p in expected if p.exists() and not _xml_finished(p)]
        if missing:
            return ("확인 불가", f"만들기로 한 산출물이 없습니다: {', '.join(missing[:3])}",
                    spec, state)
        if broken:
            return ("확인 불가", f"산출물이 끝맺히지 않았습니다: {', '.join(broken[:3])}",
                    spec, state)
        return ("확인됨", f"기대 산출물 {len(expected)}건이 모두 완결됐습니다.", spec, state)

    # spec 이 없다 - 업로드 경로이거나 산출물.메타데이터가 지워졌다.
    if uploaded.exists():
        try:
            root = ET.parse(uploaded).getroot()
        except (OSError, ET.ParseError):
            return ("확인 불가", "업로드 XML 이 파싱되지 않습니다(중간에서 끊김).", spec, state)
        if (root.get("scanner") or "") == "scanops":
            return ("확인 불가", ("남은 파일이 병합본입니다 - 항상 success 로 기록되므로 "
                               "원본 실행이 온전했는지 알 수 없습니다."), spec, state)
        if not _xml_finished(uploaded):
            return ("확인 불가", '업로드 XML 에 <finished exit="success"> 가 없습니다.',
                    spec, state)
        # 업로드본에도 범위 메타데이터가 있다 - host 뿐 아니라 scaninfo 의 protocol/services
        # 까지 재구성해야 TCP/22 만 스캔한 XML 이 같은 host 의 TCP/23 을 보증하지 않는다.
        seen = {(el.get("addr") or "")
                for el in root.findall("./host/address[@addrtype='ipv4']")}
        state = {"live": sorted(x for x in seen if x),
                 "scaninfo": {proto: _scaninfo_scope(root, proto)
                              for proto in ("tcp", "udp")}}
        return ("확인됨", f"업로드 XML 이 완결됐습니다(호스트 {len(state['live'])}대).",
                spec, state)

    return ("확인 불가", "원본 산출물이 남아 있지 않습니다(삭제되었거나 보존 기간 경과).",
            spec, state)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="닫힘 근거 감사(읽기 전용)")
    ap.add_argument("--db", default="scanops.db", help="SQLite DB 경로")
    ap.add_argument("--scans", default="scanops_scans", help="스캔 산출물 디렉터리")
    ap.add_argument("--list", action="store_true", help="의심 발견을 하나씩 나열")
    args = ap.parse_args(argv)

    db_path, scans_dir = Path(args.db), Path(args.scans)
    if not db_path.exists():
        print(f"DB 를 찾지 못했습니다: {db_path}")
        return 2

    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    rows = con.execute("""
        SELECT e.scan_id, e.finding_id, f.host_ip, f.port, f.proto, f.state, f.status
          FROM finding_events e JOIN findings f ON f.id = e.finding_id
         WHERE e.type = 'CLOSED'
      ORDER BY e.scan_id, f.host_ip, f.port
    """).fetchall()
    con.close()

    if not rows:
        print("닫힘 이벤트가 없습니다 - 검사할 것이 없습니다.")
        return 0

    cache: dict[int, tuple[str, str, dict, dict]] = {}
    reasons: dict[int, tuple[str, str]] = {}
    suspect: list[tuple] = []
    confirmed = 0
    for row in rows:
        scan_id = row["scan_id"]
        if scan_id is None:
            reasons[-1] = ("확인 불가", "이 닫힘을 만든 스캔 기록이 없습니다.")
            suspect.append((row, -1))
            continue
        if scan_id not in cache:
            cache[scan_id] = scan_evidence(scans_dir, scan_id)
            reasons[scan_id] = cache[scan_id][:2]
        mark, why, spec, state = cache[scan_id]
        if mark != "확인됨":
            suspect.append((row, scan_id))
            continue
        # 산출물이 온전해도 이 닫힘이 그 실행의 관측 범위 밖이면 증명된 게 아니다.
        proto = (row["proto"] or "tcp").lower()
        covered = (_covers(spec, state, row["host_ip"], row["port"], proto) if spec
                   else _upload_covers(state, row["host_ip"], row["port"], proto))
        if covered is not True:
            note = ("범위 밖입니다" if covered is False else "범위를 해석할 수 없습니다")
            reasons[scan_id] = ("확인 불가", f"{why} 다만 일부 닫힘은 이 실행의 관측 {note}.")
            suspect.append((row, scan_id))
            continue
        confirmed += 1

    print(f"닫힘 이벤트 {len(rows)}건 · 스캔 {len(reasons)}개")
    print(f"  확인됨      {confirmed}건 - 기대 산출물이 모두 완결된 실행이 관측 범위 안에서 닫았습니다.")
    print(f"  확인 불가   {len(suspect)}건 - 근거를 확인할 수 없습니다.")
    print()
    for scan_id, (mark, why) in sorted(reasons.items()):
        if mark != "확인됨":
            n = sum(1 for _, sid in suspect if sid == scan_id)
            label = "(스캔 기록 없음)" if scan_id == -1 else f"scan {scan_id}"
            print(f"[{mark}] {label} · 닫힘 {n}건 - {why}")

    if args.list and suspect:
        print()
        print("의심 발견:")
        for row, scan_id in suspect:
            print(f"  {row['host_ip']}:{row['port']}/{row['proto']} "
                  f"· {row['status']} · scan {scan_id}")

    print()
    print("=" * 60)
    if suspect:
        print("이 목록은 '잘못 닫혔다'가 아니라 '닫혔다고 확인할 수 없다'입니다.")
        print("되살리는 방법: 해당 IP:포트를 재스캔하세요. 여전히 열려 있으면 인입이")
        print("REOPENED 이벤트로 되살리고, 실제로 닫혔으면 그대로 둡니다.")
        print("이 스크립트는 아무것도 바꾸지 않았습니다.")
    else:
        print("모든 닫힘이 완결된 기대 산출물과 관측 범위로 뒷받침됩니다.")
    return 1 if suspect else 0


if __name__ == "__main__":
    raise SystemExit(main())
