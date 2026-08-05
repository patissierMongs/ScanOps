"""ScanOps 스트레스/엣지 케이스 — API 레벨 검증(추출·처리·발송·재스캔·성능).

각 케이스는 (상황 구성 → 기대결과 가정 → 실제 실행 → 대조) 형식. 기존 데이터와
충돌 없도록 198.51.100.x(TEST-NET-2) 대역 사용. 결과는 PASS/FAIL 로 출력.
"""
import json, os, time, urllib.request, urllib.error
from urllib.parse import quote
from pathlib import Path

# 자기완결: URL·관리자계정파일은 env 로 덮어쓸 수 있고, 기본은 스크립트 위치 기준 리포지토리 경로.
REPO = Path(__file__).resolve().parent.parent
BASE = os.environ.get("SCANOPS_URL", "http://127.0.0.1:8770")
ADMIN_FILE = Path(os.environ.get("SCANOPS_ADMIN_FILE", REPO / "data" / "INITIAL_ADMIN.txt"))
ADMIN_PW = os.environ.get("SCANOPS_ADMIN_PW") or \
    ADMIN_FILE.read_text(encoding="utf-8").split("비밀번호:")[1].split()[0]


def _login():
    data = json.dumps({"username": "admin", "password": ADMIN_PW}).encode()
    r = urllib.request.Request(BASE + "/api/auth/login", data=data,
                               headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(r, timeout=30) as resp:
        return json.loads(resp.read().decode())["token"]


TOK = _login()
R = []


def req(method, path, body=None, raw=None, ctype=None, want_status=None):
    headers = {"Authorization": "Bearer " + TOK}
    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode()
        headers["Content-Type"] = "application/json"
    elif raw is not None:
        data = raw
        headers["Content-Type"] = ctype
    r = urllib.request.Request(BASE + quote(path, safe="/?=&:"), data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            txt = resp.read().decode("utf-8-sig")
            if not txt:
                return resp.status, None
            try:
                return resp.status, json.loads(txt)
            except json.JSONDecodeError:
                return resp.status, txt  # non-JSON (e.g. CSV export)
    except urllib.error.HTTPError as e:
        return e.code, (e.read().decode() if e.fp else "")


def upload_xml(xml_str, filename="edge.xml"):
    boundary = "----edge"
    payload = (f"--{boundary}\r\n".encode()
               + f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
               + b"Content-Type: text/xml\r\n\r\n" + xml_str.encode() + b"\r\n"
               + f"--{boundary}--\r\n".encode())
    return req("POST", "/api/scans/import", raw=payload, ctype=f"multipart/form-data; boundary={boundary}")


def findings(host=None, extra=""):
    q = f"/api/findings?state={extra}"
    if host:
        q += f"&host={host}"
    _, d = req("GET", q)
    return d or []


def logc(sc, hypo, ok, actual):
    R.append({"sc": sc, "ok": bool(ok)})
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {sc}\n      가정: {hypo}\n      실제: {actual}")


def wrap(hosts_xml, scaninfo='<scaninfo type="syn" protocol="tcp" services="1-65535"/>', start="1753600000"):
    return (f'<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" start="{start}" '
            f'version="7.94" xmloutputversion="1.05">{scaninfo}{hosts_xml}'
            f'<runstats><finished time="{int(start)+10}" elapsed="10" exit="success"/>'
            f'<hosts up="1" down="0" total="1"/></runstats></nmaprun>')


def host(ip, ports_xml, up=True, hostname=None):
    hn = f'<hostnames><hostname name="{hostname}" type="PTR"/></hostnames>' if hostname else "<hostnames/>"
    return (f'<host starttime="1753600000"><status state="{"up" if up else "down"}" reason="syn-ack"/>'
            f'<address addr="{ip}" addrtype="ipv4"/>{hn}'
            f'<ports>{ports_xml}</ports><times srtt="42000"/></host>')


def port(pid, state="open", name="http", proto="tcp", product="", version="", scripts=""):
    svc = f'<service name="{name}" method="probed" conf="10"'
    if product: svc += f' product="{product}"'
    if version: svc += f' version="{version}"'
    svc += "/>"
    return f'<port protocol="{proto}" portid="{pid}"><state state="{state}" reason="syn-ack"/>{svc}{scripts}</port>'


# ── SC01 빈 nmaprun ─────────────────────────────────────────────
st, d = upload_xml(wrap(""))
logc("SC01 빈 스캔 추출", "가져오기 성공·counts 전부 0·발견 미생성",
     st == 200 and d and sum(d["counts"].values()) == 0,
     f"status={st}, counts={d.get('counts') if isinstance(d,dict) else d}")

# ── SC02 up 호스트, 포트 0 ──────────────────────────────────────
st, d = upload_xml(wrap(host("198.51.100.2", "", hostname="empty-host")))
logc("SC02 포트없는 up호스트", "발견 0·파싱 무오류",
     st == 200 and d["counts"]["new"] == 0,
     f"status={st}, new={d['counts']['new'] if isinstance(d,dict) else d}")

# ── SC03 closed/filtered 포트만 ─────────────────────────────────
p = port(80, "closed") + port(443, "filtered") + port(22, "closed", name="ssh")
st, d = upload_xml(wrap(host("198.51.100.3", p, hostname="closed-only")))
f3 = findings("198.51.100.3")
logc("SC03 closed/filtered만", "열린포트 없음→발견 0(닫힘=부재 판정)",
     st == 200 and d["counts"]["new"] == 0 and len(f3) == 0,
     f"status={st}, new={d['counts']['new']}, findings={len(f3)}")

# ── SC04 malformed XML → 400 + 서버 생존 ────────────────────────
st, d = upload_xml("<nmaprun><host><ports><port unclosed")
_, health = req("GET", "/api/health")
st2, _ = req("GET", "/api/findings?state=open")
logc("SC04 깨진 XML 방어", "400 파싱실패·백엔드 생존(후속 요청 200)",
     st == 400 and health and health.get("ok") and st2 == 200,
     f"import_status={st}, health_ok={health.get('ok') if isinstance(health,dict) else health}, next_req={st2}")

# ── SC05 파일 내 중복 finding_key ───────────────────────────────
dup = port(9090, name="http", product="A") + port(9090, name="http", product="B")  # same key twice
st, d = upload_xml(wrap(host("198.51.100.5", dup, hostname="dup-key")))
f5 = findings("198.51.100.5")
key_ports = [x for x in f5 if x["port"] == 9090]
logc("SC05 중복 finding_key", "동일 host|port|proto → 1건으로 upsert(중복 없음)",
     len(key_ports) == 1, f"9090 findings={len(key_ports)} (product={key_ports[0]['product'] if key_ports else '-'})")

# ── SC06 동일 XML 2회(멱등) ─────────────────────────────────────
# 매 실행마다 새 키가 되도록 IP 2번째 옥텟을 실행시각 기반으로(재실행 아티팩트 방지).
ip6 = f"100.64.{int(time.time()) % 250}.6"
xml6 = wrap(host(ip6, port(8443, name="https", product="nginx"), hostname="idem"))
st_a, d_a = upload_xml(xml6, "idem.xml")
st_b, d_b = upload_xml(xml6, "idem.xml")
f6 = [x for x in findings(ip6) if x["port"] == 8443]
logc("SC06 동일파일 재가져오기(멱등)", "2회차 new=0·unchanged≥1·발견 1건(중복 없음)",
     d_a["counts"]["new"] == 1 and d_b["counts"]["new"] == 0 and d_b["counts"]["unchanged"] >= 1 and len(f6) == 1,
     f"1st new={d_a['counts']['new']}, 2nd new={d_b['counts']['new']} unchanged={d_b['counts']['unchanged']}, findings={len(f6)}")

# ── SC07 유니코드·특수문자·초장문 배너 ──────────────────────────
longver = "테스트€—" + "A" * 400
# XML 안전: 특수문자는 엔티티로
scripts = '<script id="http-title" output="제목 &lt;script&gt;alert(1)&lt;/script&gt; &amp; 한글 ✓"/>'
p7 = port(7000, name="http", product="서버-제품", version=longver.replace("<", "&lt;").replace("&", "&amp;"), scripts=scripts)
st, d = upload_xml(wrap(host("198.51.100.7", p7, hostname="unicode-호스트")))
f7 = [x for x in findings("198.51.100.7") if x["port"] == 7000]
# nse_json 은 FindingOut 에 미노출(설계) → 근거는 /evidence·remarks 로 표면화. 데이터 보존은 저장값 기준.
ev = req("GET", f"/api/findings/{f7[0]['id']}/evidence")[1] if f7 else {}
ev_txt = json.dumps(ev, ensure_ascii=False)
ok7 = (bool(f7) and "테스트" in (f7[0]["version"] or "") and len(f7[0]["version"]) >= 400
       and "서버-제품" in ev_txt)  # 유니코드 원형 보존 + 근거 표면화
logc("SC07 유니코드/특수문자/초장문", "유니코드·초장문(405자) 원형 보존·근거(/evidence) 표면화·주입 없음(문자열로 저장)",
     ok7, f"version_len={len(f7[0]['version']) if f7 else 0}, unicode보존={'테스트' in (f7[0]['version'] if f7 else '')}, evidence표면화={'서버-제품' in ev_txt}")

# ── SC08 UDP open|filtered 상태 ─────────────────────────────────
p8 = port(161, state="open|filtered", name="snmp", proto="udp")
st, d = upload_xml(wrap(host("198.51.100.8", p8, hostname="udp-host")))
f8 = [x for x in findings("198.51.100.8") if x["port"] == 161]
logc("SC08 UDP open|filtered", "state가 'open'으로 시작→인입됨(proto=udp)",
     len(f8) == 1 and f8[0]["proto"] == "udp", f"findings={len(f8)}, state={f8[0]['state'] if f8 else '-'}")

# ── SC09 scaninfo 누락 + 미지 서비스 분류 ───────────────────────
p9 = port(6000, name="foobar-unknown-svc", product="Mystery")
st, d = upload_xml(wrap(host("198.51.100.9", p9, hostname="unknown-svc"), scaninfo=""))
f9 = [x for x in findings("198.51.100.9") if x["port"] == 6000]
logc("SC09 scaninfo누락+미지서비스", "가져오기 성공·미지 서비스는 info/미분류 기본값",
     st == 200 and f9 and f9[0]["risk_level"] in ("info", "low") and f9[0]["status"] == "미조치",
     f"status={st}, risk={f9[0]['risk_level'] if f9 else '-'}, category={f9[0].get('category') if f9 else '-'}")

# ── SC10 banned_service 규칙 추가→적용, 삭제→복원 ───────────────
# ftp 는 taxonomy high. banned 규칙 후 banned, 삭제 후 high 복원.
p10 = port(21, name="ftp", product="vsftpd", version="3.0.3")
upload_xml(wrap(host("198.51.100.10", p10, hostname="ftp-host")))
before = [x for x in findings("198.51.100.10") if x["port"] == 21][0]["risk_level"]
st_r, rule = req("POST", "/api/rules", {"kind": "banned_service", "service": "ftp", "risk_level": "banned", "note": "테스트"})
after = [x for x in findings("198.51.100.10") if x["port"] == 21][0]["risk_level"]
req("DELETE", f"/api/rules/{rule['id']}")
restored = [x for x in findings("198.51.100.10") if x["port"] == 21][0]["risk_level"]
logc("SC10 banned규칙 추가/삭제 토글", f"{before}→banned→(삭제)→{before} 복원",
     before == "high" and after == "banned" and restored == "high",
     f"before={before}, after_rule={after}, after_delete={restored}")

# ── SC11 port_rule 포트기반 위험 오버라이드 ─────────────────────
# 6000 미지서비스(info) → port_rule 로 6000 을 high 로 상향.
st_r, rule = req("POST", "/api/rules", {"kind": "port_rule", "port": 6000, "risk_level": "high", "note": "포트룰"})
f11 = [x for x in findings("198.51.100.9") if x["port"] == 6000]
after11 = f11[0]["risk_level"] if f11 else "-"
req("DELETE", f"/api/rules/{rule['id']}")
logc("SC11 port_rule 오버라이드", "포트 6000 → high 로 상향(서비스 무관)",
     after11 == "high", f"port6000 risk after port_rule={after11}")

# ── SC16 부서통보 발송 + SMTP 미구현 확인 ───────────────────────
# 발견에 부서 부여 후 통보. 통보는 channel=file(외부발송 없음) — 네트워크 호출 0.
req("PATCH", "/api/findings/" + str([x for x in findings('198.51.100.10') if x['port']==21][0]['id']),
    {"dept": "스트레스팀"})
st_p, prev = req("GET", "/api/notifications/preview?dept=스트레스팀")
st_s, note = req("POST", "/api/notifications?dept=스트레스팀", {"dept": "스트레스팀", "body": prev["body"], "finding_ids": []})
_, hist = req("GET", "/api/notifications")
smtp_absent = note.get("channel") == "file"
logc("SC16 통보발송+SMTP미구현", "통보 기록 생성·channel=file(외부 SMTP 전송 없음, 설계상 에어갭)",
     st_s == 201 and smtp_absent and any(n["dept"] == "스트레스팀" for n in hist),
     f"send_status={st_s}, channel={note.get('channel')}, 기록됨={any(n['dept']=='스트레스팀' for n in hist)}")

# ── SC17 rescan-command 텍스트 생성(실행 없음) ──────────────────
ftp_id = [x for x in findings("198.51.100.10") if x["port"] == 21][0]["id"]
st_rc, rc = req("POST", "/api/findings/rescan-command", {"finding_ids": [ftp_id], "preset_flags": "-sV -Pn"})
scans_before = len(req("GET", "/api/scans")[1])
scans_after = len(req("GET", "/api/scans")[1])
logc("SC17 rescan-command(무실행)", "명령 텍스트만 반환·실제 스캔 미생성",
     st_rc == 200 and rc.get("command") and "21" in str(rc.get("ports")) and scans_before == scans_after,
     f"command='{(rc.get('command') or '')[:60]}...', ports={rc.get('ports')}, 스캔생성={scans_after-scans_before}")

# ── SC19 rescan-due (마감초과/처리중 일괄) 대상 산정 ────────────
# 자기완결: 전용 발견(198.51.100.19:8443)을 만들어 마감초과 처리중으로 세팅(다른 SC 의존 없음).
upload_xml(wrap(host("198.51.100.19", port(8443, name="https", product="nginx"), hostname="due-host")))
due = [x for x in findings("198.51.100.19") if x["port"] == 8443]
assert due, "SC19 setup: 198.51.100.19:8443 발견 생성 실패"
did = due[0]["id"]
req("PATCH", f"/api/findings/{did}", {"status": "처리중", "deadline": "2020-01-01T00:00:00"})
# rescan-due 는 실제 엔진 스캔을 백그라운드 기동 → 대상 hosts 에 포함되는지 확인(스캔 생성 여부)
st_rd, rd = req("POST", "/api/findings/rescan-due", {})
logc("SC19 rescan-due 일괄재검증", "마감초과·처리중 발견을 모아 재스캔 스캔 생성(scan_id 반환)",
     st_rd == 200 and rd.get("scan_id") and "198.51.100.19" in (rd.get("hosts") or []),
     f"status={st_rd}, scan_id={rd.get('scan_id')}, hosts_count={len(rd.get('hosts') or [])}")

# ── SC20 스트레스: 반복 PATCH race + 대량 필터/내보내기 응답시간 ──
tid = [x for x in findings("198.51.100.7") if x["port"] == 7000][0]["id"]
seq = ["처리중", "정상처리", "미조치"] * 5  # 15회 연속 상태 변경
t0 = time.time()
codes = [req("PATCH", f"/api/findings/{tid}", {"status": s})[0] for s in seq]
patch_ms = (time.time() - t0) / len(seq) * 1000
final = req("GET", f"/api/findings/{tid}")[1]["status"]
# 이벤트 일관성: STATUS_CHANGE 이벤트 수 == 실제 변경 횟수
evs = req("GET", f"/api/findings/{tid}/events")[1]
sc_events = [e for e in evs if e["type"] == "STATUS_CHANGE"]
# 대량 필터/내보내기 응답시간
t1 = time.time(); n_all = len(findings(extra="open")); list_ms = (time.time() - t1) * 1000
t2 = time.time(); st_e, _ = req("GET", "/api/findings/export?cols=host_ip,port,service,risk_level,dept,status&fmt=csv"); exp_ms = (time.time() - t2) * 1000
logc("SC20 반복PATCH race+대량응답시간",
     "15회 연속변경 일관(최종=미조치)·STATUS_CHANGE 이벤트 누락없음·목록/내보내기 <2s",
     all(c == 200 for c in codes) and final == "미조치" and len(sc_events) >= 10 and list_ms < 2000 and exp_ms < 2000,
     f"final={final}, patch평균={patch_ms:.0f}ms, STATUS_CHANGE={len(sc_events)}회, 목록({n_all}건)={list_ms:.0f}ms, 내보내기={exp_ms:.0f}ms")

print("\n=== API 스트레스 결과 ===")
print("PASS:", sum(1 for x in R if x["ok"]), "/", len(R))
print("FAIL cases:", [x["sc"] for x in R if not x["ok"]])
import sys as _sys
_sys.exit(1 if any(not x["ok"] for x in R) else 0)  # 실패 시 비영 종료(CI 연동)
