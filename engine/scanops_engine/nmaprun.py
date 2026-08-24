"""nmap 래퍼 — 단계별 실행(라이브 진행 스트리밍) + XML 파싱.

엔진의 유일한 외부 명령 실행 지점. shell=False, -oA 서버 강제로 명령 주입 차단.
nmap stdout 의 'About X% done' 을 파싱해 stage_progress 콜백으로 흘린다.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from .process_control import close_kill_job, popen_owned, terminate_owned

_PCT_RE = re.compile(r"About\s+([\d.]+)%\s+done")
_RETRANSMISSION_CAP_RE = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3})\s+giving up on port because "
    r"retransmission cap hit\b",
    re.IGNORECASE,
)


def find_nmap(explicit: str = "") -> str | None:
    if explicit and os.path.isfile(explicit):
        return explicit
    for c in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"):
        if os.path.isfile(c):
            return c
    return shutil.which("nmap")


def _need_sudo(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    # auto: POSIX 비root → sudo (Windows+Npcap 은 불필요)
    return os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0


# nmap 이 --stats-every 로 찍는 단계 진행 줄. 예:
#   "SYN Stealth Scan Timing: About 42.86% done; ETC: 14:30 (0:00:30 remaining)"
#   "Service scan Timing: About 12.50% done; ETC: ..."
# 이름이 곧 nmap 내부 단계다 - 포트스캔이 오래 걸리는 것과 서비스 식별이 오래 걸리는 것은
# 원인도 대책도 다른데, 바깥에서 잰 총 소요는 둘을 구분해 주지 못한다.
_PHASE_RE = re.compile(
    r"^(?P<phase>[A-Za-z0-9][A-Za-z0-9 ./_-]*?)\s+Timing:\s+About\s+[\d.]+%\s+done")
# 첫 stats 줄이 나오기 전 구간. nmap 이 아직 아무 단계도 보고하지 않았다(호스트 발견·DNS
# 해석·시작 준비). 어느 단계에도 귀속시키지 않고 이 이름 그대로 남긴다.
_PHASE_UNREPORTED = "보고 전"


def _stream_output(stream, log, progress, retransmission_cap_hosts,
                   phases=None, clock=time.time) -> None:
    """stdout 을 로그에 흘리면서 진행률·재전송 상한·**단계별 체류시간**을 뽑는다.

    체류시간은 stats 줄 사이의 간격을 **직전에 관측된 단계**에 닫는다. 뒤에 오는 줄이
    말하는 단계에 귀속시키면 첫 줄 이전의 시간이 그 단계로 들어가고, 샘플 간격이
    불균등할수록 원인을 크게 오표시한다 - 0·5·7·20초에 SYN·SYN·Service 가 찍히면
    SYN 7초 / Service 13초가 되어, 아직 시작도 안 한 Service 가 13초를 뒤집어쓴다.

    첫 관측 이전 구간은 어느 단계도 아니므로 `보고 전` 으로 남긴다. 마지막 줄 이후의
    꼬리는 그때 돌던 단계(직전에 관측된 것)에 닫는다 - 같은 규칙이다.
    """
    last = clock()
    current = None
    for line in stream:
        log.write(line)
        log.flush()
        if m := _RETRANSMISSION_CAP_RE.search(line):
            retransmission_cap_hosts.add(m.group(1))
        if phases is not None and (m := _PHASE_RE.search(line)):
            now = clock()
            bucket = current if current is not None else _PHASE_UNREPORTED
            phases[bucket] = round(phases.get(bucket, 0.0) + max(0.0, now - last), 1)
            last = now
            current = m.group("phase").strip()
        if progress and (m := _PCT_RE.search(line)):
            try:
                progress(float(m.group(1)))
            except Exception:
                pass
    if phases is not None:
        # 스트림이 닫혔다 = 프로세스가 끝났다. 마지막 구간도 같은 규칙으로 닫는다.
        bucket = current if current is not None else _PHASE_UNREPORTED
        phases[bucket] = round(phases.get(bucket, 0.0) + max(0.0, clock() - last), 1)


def build_command(nmap, args, out_base, sudo_mode="auto", stats="5s") -> list[str]:
    """Return the exact argv used by :func:`run` for history/UI evidence."""
    return (['sudo'] if _need_sudo(sudo_mode) else []) + [
        str(nmap), "--stats-every", str(stats), *[str(arg) for arg in args],
        "-oA", str(Path(out_base)),
    ]


def run(nmap, args, out_base, sudo_mode="auto", progress=None, stats="5s",
        stop_requested=None, poll_interval=0.1, watchdog_seconds=0) -> dict:
    """nmap 한 패스 — -oA out_base 강제 + --stats-every. stdout 스트리밍하며 progress(pct).

    stdout 유무와 무관하게 stop_requested 를 짧게 poll하고, 중지 시 이 호출이 소유한
    프로세스 트리만 종료한다.
    반환: {"rc", "seconds", "cmd", "stopped", "timed_out_by_watchdog", ...}.

    ``watchdog_seconds`` 는 **프로세스 단위** 상한이다(0 = 끔). ``--host-timeout`` 과는
    성격이 다르다:

    * ``--host-timeout`` 은 nmap 이 상한을 넘긴 호스트의 **포트 표를 아예 쓰지 않고**
      실행은 ``exit="success"`` 로 끝낸다. 그래서 그 호스트가 '살아 있는데 열린 포트가
      없다'로 읽혀 기존 발견이 전부 닫힌다 - 관측을 버리면서 그 사실을 숨긴다.
    * 워치독은 nmap 을 **밖에서** 끝낸다. 실행은 비정상 종료로 표시되어 닫힘 권한을 얻지
      못하고(산출물 완결성 검사가 ``<finished exit="success">`` 를 요구한다), 그때까지
      끝난 호스트의 관측은 살린다.

    즉 워치독은 '못 본 것을 봤다고 말하는' 사고를 만들지 않는다. 그래서 상한을 되살리는
    대신 이쪽을 둔다.

    다만 ``-oA`` 가 증분 기록이라는 것만으로는 부족하다 - 중간에 끊긴 XML 은
    ``</nmaprun>`` 이 없어 표준 파서가 ``ParseError`` 를 내고, 그러면 **끝난 호스트의
    관측까지 통째로 사라진다**(실측: 킬 직후 547바이트, "no element found"). SIGTERM·SIGINT
    로 바꿔도 nmap 이 닫아 주지 않는다. 그래서 워치독이 끊은 뒤 ``_repair_truncated_xml``
    로 마지막 완결 ``</host>`` 까지만 남기고 닫는다. ``runstats`` 는 만들지 않으므로 완결성
    검사는 그대로 실패한다 - 관측은 살리되 닫힘 권한은 주지 않는다.
    """
    out_base = Path(out_base)
    cmd = build_command(nmap, args, out_base, sudo_mode=sudo_mode, stats=stats)
    t0 = time.time()
    with open(str(out_base) + ".stdout.log", "w", encoding="utf-8") as log:
        proc = popen_owned(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, bufsize=1)
        retransmission_cap_hosts = set()
        # nmap 이 스스로 보고한 단계별 체류시간. 같은 10분이라도 포트스캔에 쓴 10분과
        # 서비스 식별에 쓴 10분은 원인도 대책도 다르다.
        phases: dict[str, float] = {}
        reader = threading.Thread(
            target=_stream_output,
            args=(proc.stdout, log, progress, retransmission_cap_hosts, phases), daemon=True,
        )
        reader.start()
        stopped = False
        watchdog_fired = False
        deadline = t0 + watchdog_seconds if watchdog_seconds and watchdog_seconds > 0 else None
        try:
            while proc.poll() is None:
                if stop_requested is not None and stop_requested():
                    stopped = True
                    terminate_owned(proc)
                    break
                if deadline is not None and time.time() >= deadline:
                    watchdog_fired = True
                    terminate_owned(proc)
                    break
                time.sleep(poll_interval)
            rc = proc.wait()
        except BaseException:
            if proc.poll() is None:
                terminate_owned(proc)
            raise
        finally:
            # Closing the Windows Job Object also removes a descendant that outlived its
            # parent and still owns the stdout pipe. POSIX stop uses the private process group.
            close_kill_job(proc)
            reader.join(timeout=2)
            if reader.is_alive() and proc.stdout is not None:
                proc.stdout.close()
                reader.join(timeout=0.5)
    # 워치독이 끊은 실행은 rc 가 0 이어서는 안 된다. 종료 신호를 받은 nmap 이 0 으로 끝낼
    # 수 있는데, 그대로 두면 '정상 완료'로 읽혀 미관측 닫힘 권한을 얻는다 - 워치독을 둔
    # 이유가 통째로 뒤집힌다. 여기서 실패로 못박는다.
    if watchdog_fired and rc == 0:
        rc = -1
    # 끊긴 XML 을 살려 둔다. 이걸 안 하면 워치독이 '관측을 보존한다'는 말이 거짓이 된다.
    repaired = _repair_truncated_xml(Path(str(out_base) + ".xml")) if watchdog_fired else False
    return {
        "rc": rc,
        "phases": phases,
        "xml_repaired": repaired,
        "seconds": round(time.time() - t0, 2),
        "cmd": cmd,
        "stopped": stopped,
        "timed_out_by_watchdog": watchdog_fired,
        "retransmission_cap_hosts": sorted(retransmission_cap_hosts, key=_ipkey),
    }


def _repair_truncated_xml(path: Path) -> bool:
    """중간에 끊긴 nmap XML 을 **파싱 가능한 데까지만** 남기고 닫는다.

    워치독이 프로세스를 끝내면 nmap 은 ``</nmaprun>`` 을 쓰지 못한다. 그 파일은 표준 파서가
    통째로 거절하므로, 이미 끝난 호스트의 관측까지 같이 버려진다 - 몇 시간짜리 스캔에서
    그건 워치독을 둔 이유를 스스로 지우는 일이다.

    마지막 완결 ``</host>`` 뒤를 잘라내고 루트만 닫는다. **``runstats`` 는 만들지 않는다** -
    그것이 있어야 산출물 완결성 검사가 통과하므로, 없는 채로 두면 이 실행은 관측만 제공하고
    미관측 닫힘 권한은 얻지 못한다. 그 성질이 이 함수의 존재 이유다.

    반환: 손봤으면 True. 이미 온전하거나 살릴 호스트가 없으면 손대지 않고 False.
    """
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if not raw.strip():
        return False
    try:
        ET.fromstring(raw)
        return False                      # 이미 온전하다 - 건드리지 않는다
    except ET.ParseError:
        pass
    cut = raw.rfind("</host>")
    if cut == -1:
        return False                      # 살릴 호스트가 없다 - 빈 파일로 두는 편이 정직하다
    repaired = raw[:cut + len("</host>")] + "\n</nmaprun>\n"
    try:
        ET.fromstring(repaired)
    except ET.ParseError:
        return False
    try:
        path.write_text(repaired, encoding="utf-8")
    except OSError:
        return False
    return True


# ── XML 파싱 ──

# nmap 이 -oA 로 함께 쓰는 확장자. 재시도를 채택·폐기할 때 셋을 같이 다뤄야 한다.
OUTPUT_SUFFIXES = (".xml", ".nmap", ".gnmap")


def retry_base(base: Path) -> Path:
    """재시도용 임시 산출물 base.

    접미사가 아니라 **접두사**로 만든다 - 산출물 이름은 `...<단계>` 로 끝나고 단계를 그
    끝으로 판별하는 곳이 여럿이라, 뒤에 붙이면 재시도만 단계를 잃는다.
    """
    return base.with_name(f"retry~{base.name}")


def adopt_artifacts(src_base: Path, dst_base: Path) -> None:
    """재시도 산출물을 원래 자리로 옮긴다 - 채택했을 때만 부른다."""
    for suffix in OUTPUT_SUFFIXES:
        src = Path(str(src_base) + suffix)
        if src.exists():
            src.replace(Path(str(dst_base) + suffix))


def discard_artifacts(base: Path) -> None:
    """채택하지 않은 산출물을 지운다 - 결과 폴더에 유령 파일을 남기지 않는다."""
    for suffix in OUTPUT_SUFFIXES:
        try:
            Path(str(base) + suffix).unlink()
        except OSError:
            pass


def xml_usable(base: Path) -> bool:
    """읽을 수 있는 산출물이 실제로 있는가.

    '끊기지 않았다' 로는 부족하다 - 파일이 **없을 때도** 그 말이 참이라, 아무것도 남기지
    못한 실행을 '멀쩡하다' 로 읽는다. 재시도를 채택할지 정하는 자리에서는 그 차이가
    '부분 결과' 와 '완주' 를 가른다.
    """
    path = Path(str(base) + ".xml")
    if not path.exists():
        return False
    try:
        ET.parse(path)
        return True
    except (ET.ParseError, OSError):
        return False


def artifact_yield(xml_path) -> dict:
    """산출물이 실제로 **무엇을 담았는지** — 호스트 / 확정 열림 / 무응답 추정 / 버전 식별 수.

    소요만 적어 두면 107초를 돌고 빈 파일을 남긴 실행이 '성공' 과 구분되지 않는다. 실제로
    그렇게 마감된 실행이 32대분 식별을 통째로 잃었다. 수확량은 그 실패를 화면에서 즉시
    보이게 하는 유일한 값이다.

    ``open`` 과 ``open|filtered`` 를 **나눠 센다.** nmap 정의상 후자는 열린지 필터링됐는지
    가르지 못한 상태라, 합쳐서 '열림' 이라고 적으면 불확실성을 확정으로 바꾸는 거짓 양성이
    된다 - 이 저장소의 observation 경로도 두 상태를 구분한다.
    """
    hosts = _hosts(xml_path)
    confirmed = inferred = products = 0
    for host in hosts:
        for port in host.findall("ports/port"):
            state = port.find("state")
            value = (state.get("state") or "") if state is not None else ""
            if value == "open":
                confirmed += 1
            elif value.startswith("open"):        # open|filtered
                inferred += 1
            service = port.find("service")
            if service is not None and (service.get("product") or "").strip():
                products += 1
    return {
        "hosts_found": len(hosts),
        "open_ports": confirmed,
        "inferred_open": inferred,
        "products": products,
        # 볼 것이 있어서 돈 실행인데 아무것도 담지 못했다는 사실.
        "empty": bool(hosts) and confirmed == 0 and inferred == 0,
    }


def _ipkey(ip: str):
    try:
        return tuple(int(o) for o in ip.split("."))
    except ValueError:
        return (ip,)


def _hosts(xml_path):
    try:
        return ET.parse(str(xml_path)).getroot().findall("host")
    except (ET.ParseError, FileNotFoundError, OSError):
        return []


def _ipv4(h):
    a = h.find("address[@addrtype='ipv4']")
    return a.get("addr") if a is not None else None


def timed_out(xml_path) -> list[str]:
    """``--host-timeout`` 으로 nmap 이 포기한 호스트.

    nmap 은 상한을 넘긴 호스트를 건너뛰고 포트 표를 아예 쓰지 않으며, `<host>` 에
    ``timedout="true"`` 만 남긴 뒤 실행 자체는 ``exit="success"`` 로 끝낸다. 그래서 이
    표식을 안 읽으면 '살아 있는데 열린 포트가 없다'로 보인다 - 그 호스트의 기존 발견이
    전부 닫힘 처리되는 자리다.
    """
    return sorted({ip for h in _hosts(xml_path)
                   if h.get("timedout") == "true" and (ip := _ipv4(h))}, key=_ipkey)


def hosts_up(xml_path) -> list[str]:
    ups = [ip for h in _hosts(xml_path)
           if (st := h.find("status")) is not None and st.get("state") == "up"
           and (ip := _ipv4(h))]
    return sorted(ups, key=_ipkey)


def open_ports(xml_path, proto=None) -> dict[str, list[int]]:
    """{ip: [열린 포트]} — proto 지정 시 그 프로토콜만."""
    out: dict[str, list[int]] = {}
    for h in _hosts(xml_path):
        ip = _ipv4(h)
        if not ip:
            continue
        ports = [int(p.get("portid")) for p in h.findall("ports/port")
                 if (not proto or p.get("protocol") == proto)
                 and (s := p.find("state")) is not None
                 and (s.get("state") or "").startswith("open")]
        if ports:
            out[ip] = sorted(ports)
    return out


def services(xml_path) -> list[dict]:
    rows = []
    for h in _hosts(xml_path):
        ip = _ipv4(h)
        if not ip:
            continue
        for p in h.findall("ports/port"):
            s = p.find("state")
            if s is None or not (s.get("state") or "").startswith("open"):
                continue
            svc = p.find("service")
            scripts = {sc.get("id"): (sc.get("output") or "").strip()[:300]
                       for sc in p.findall("script")}
            rows.append({
                "ip": ip, "port": int(p.get("portid")), "proto": p.get("protocol"),
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "scripts": scripts,
            })
    return rows
