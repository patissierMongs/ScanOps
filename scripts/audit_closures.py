#!/usr/bin/env python3
"""이미 닫힌 발견 중 '실제로 닫혔는지 확인되지 않은' 것을 찾는다 — 읽기 전용 dry-run.

ScanOps 는 부재로 닫는다: 완결됐다고 판단한 스캔에서 안 보인 포트를 닫힌 것으로 본다.
그 판단이 틀렸던 시기(산출물 완결성 게이트 이전)에는, 중간에 끊긴 스캔이 '관측 0건'으로
통과해 열린 포트를 닫아 버릴 수 있었다. 닫힘은 status 까지 '정상처리'로 바꾸므로 되돌리기
가장 어려운 미탐이다.

이 스크립트는 **아무것도 바꾸지 않는다.** CLOSED 이벤트를 그 스캔의 원본 산출물과 대조해
'근거가 확인되는 닫힘'과 '근거를 확인할 수 없는 닫힘'을 가른다. 결과를 보고 재스캔할지는
사람이 정한다 — 재스캔해서 여전히 열려 있으면 인입이 REOPENED 로 되살린다.

**중요**: scan_runs.raw_xml_path 를 완결성 근거로 쓰지 않는다. 자동 배치·staged 경로에서
그 파일은 우리가 재구성한 병합본이고 _write_merged_xml 이 원본 실행이 어땠든 항상
exit="success" 를 찍는다. 그래서 원본 산출물(엔진 stage-*.xml, 업로드 scan_N.xml)만 본다.

사용:
    python scripts/audit_closures.py                    # 요약
    python scripts/audit_closures.py --list             # 의심 발견까지 나열
    python scripts/audit_closures.py --db /경로/scanops.db --scans /경로/scans
"""
from __future__ import annotations

import argparse
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path

# 이 스캔의 포트 관측을 담은 원본 산출물. 병합본(scan_N.xml)은 늘 success 라 제외한다.
_ORIGINAL_GLOBS = ("stage-tcp-b*.xml", "stage-udp-b*.xml", "stage0-discovery.xml")


def _xml_finished(path: Path) -> bool:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return False
    finished = root.findall("./runstats/finished")
    return len(finished) == 1 and finished[0].get("exit") == "success"


def scan_evidence(scans_dir: Path, scan_id: int) -> tuple[str, str]:
    """(판정, 이유) — 이 스캔의 닫힘 근거를 믿을 수 있는가."""
    out_dir = scans_dir / f"scan_{scan_id}"
    uploaded = scans_dir / f"scan_{scan_id}.xml"
    stage_files = [p for pattern in _ORIGINAL_GLOBS for p in sorted(out_dir.glob(pattern))]

    if stage_files:
        broken = [p.name for p in stage_files if not _xml_finished(p)]
        if broken:
            return "확인 불가", f"원본 산출물이 끝맺히지 않았습니다: {', '.join(broken[:3])}"
        return "확인됨", f"원본 산출물 {len(stage_files)}건이 모두 끝맺혔습니다."

    # 엔진 산출물이 없다 — 업로드 경로이거나 산출물이 지워졌다.
    if uploaded.exists():
        # 업로드본은 원본 nmap XML 이지만, 자동 배치가 병합본을 같은 경로에 쓰기도 한다.
        # 병합본은 scanner="scanops" 로 구분된다.
        try:
            root = ET.parse(uploaded).getroot()
        except (OSError, ET.ParseError):
            return "확인 불가", "업로드 XML 이 파싱되지 않습니다(중간에서 끊김)."
        if (root.get("scanner") or "") == "scanops":
            return "확인 불가", ("남은 파일이 병합본입니다 — 항상 success 로 기록되므로 "
                              "원본 실행이 온전했는지 알 수 없습니다.")
        return ("확인됨" if _xml_finished(uploaded) else "확인 불가",
                "업로드 XML 을 확인했습니다." if _xml_finished(uploaded)
                else "업로드 XML 에 <finished exit=\"success\"> 가 없습니다.")

    return "확인 불가", "원본 산출물이 남아 있지 않습니다(삭제되었거나 보존 기간 경과)."


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
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
        SELECT e.scan_id, e.finding_id, e.detail, f.host_ip, f.port, f.proto,
               f.state, f.status
          FROM finding_events e JOIN findings f ON f.id = e.finding_id
         WHERE e.type = 'CLOSED'
      ORDER BY e.scan_id, f.host_ip, f.port
    """).fetchall()
    con.close()

    if not rows:
        print("닫힘 이벤트가 없습니다 — 검사할 것이 없습니다.")
        return 0

    verdicts: dict[int, tuple[str, str]] = {}
    suspect: list[sqlite3.Row] = []
    confirmed = 0
    for row in rows:
        scan_id = row["scan_id"]
        if scan_id is None:
            verdicts.setdefault(-1, ("확인 불가", "이 닫힘을 만든 스캔 기록이 없습니다."))
            suspect.append(row)
            continue
        if scan_id not in verdicts:
            verdicts[scan_id] = scan_evidence(scans_dir, scan_id)
        if verdicts[scan_id][0] == "확인됨":
            confirmed += 1
        else:
            suspect.append(row)

    print(f"닫힘 이벤트 {len(rows)}건 · 스캔 {len(verdicts)}개")
    print(f"  확인됨      {confirmed}건 — 원본 산출물이 끝맺힌 스캔이 닫았습니다.")
    print(f"  확인 불가   {len(suspect)}건 — 근거를 확인할 수 없습니다.")
    print()
    for scan_id, (mark, why) in sorted(verdicts.items()):
        if mark != "확인됨":
            n = sum(1 for r in suspect if r["scan_id"] == scan_id)
            label = "(스캔 기록 없음)" if scan_id == -1 else f"scan {scan_id}"
            print(f"[{mark}] {label} · 닫힘 {n}건 — {why}")

    if args.list and suspect:
        print()
        print("의심 발견:")
        for row in suspect:
            still = "" if row["state"] == "closed" else f" (현재 {row['state']})"
            print(f"  {row['host_ip']}:{row['port']}/{row['proto']} "
                  f"· {row['status']}{still} · scan {row['scan_id']}")

    print()
    print("=" * 60)
    if suspect:
        print("이 목록은 '잘못 닫혔다'가 아니라 '닫혔다고 확인할 수 없다'입니다.")
        print("되살리는 방법: 해당 IP:포트를 재스캔하세요. 여전히 열려 있으면 인입이")
        print("REOPENED 이벤트로 되살리고, 실제로 닫혔으면 그대로 둡니다.")
        print("이 스크립트는 아무것도 바꾸지 않았습니다.")
    else:
        print("모든 닫힘이 끝맺힌 원본 산출물에 근거합니다.")
    return 1 if suspect else 0


if __name__ == "__main__":
    raise SystemExit(main())
