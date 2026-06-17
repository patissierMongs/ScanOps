"""실 nmap 스캔 결과 위에 운영 맥락을 입힌다 (UTF-8 안전 — urllib 직접).

전제: 서버가 8770 에서 떠 있고, live_sample/scan_live.xml 이 이미 import 됨.
사용: python live_sample/seed_live.py <admin_password>
"""
import json
import sys
import urllib.request

BASE = "http://127.0.0.1:8770"


def req(method, path, token=None, body=None):
    headers = {}
    data = None
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(r) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else None


def main(pw):
    tok = req("POST", "/api/auth/login", body={"username": "admin", "password": pw})["token"]

    # 자산대장: 127.0.0.1 → 부서/담당 (finding 자동 매칭 소스)
    try:
        req("POST", "/api/assets", tok, {
            "ip": "127.0.0.1", "hostname": "ops-gateway-01",
            "dept": "인프라운영팀", "owner": "김도현 책임", "asset_no": "SRV-0142",
        })
        print("asset: 127.0.0.1 -> 인프라운영팀")
    except urllib.error.HTTPError as e:
        print("asset skip:", e.read().decode("utf-8"))

    findings = req("GET", "/api/findings", tok)
    by_port = {f["port"]: f for f in findings}

    # telnet(23): 처리중 + 마감 (라이프사이클 시연)
    if 23 in by_port:
        req("PATCH", f"/api/findings/{by_port[23]['id']}", tok,
            {"status": "처리중", "deadline": "2026-06-18T00:00:00"})
        print("finding 23/telnet -> 처리중, 마감 2026-06-18")
    # ftp(21): 마감 임박(어제 = 초과) — 마감초과 강조 시연
    if 21 in by_port:
        req("PATCH", f"/api/findings/{by_port[21]['id']}", tok,
            {"status": "미조치", "deadline": "2026-06-15T00:00:00"})
        print("finding 21/ftp -> 마감 2026-06-15 (초과)")

    # 위험 규칙: telnet 금지 서비스
    try:
        r = req("POST", "/api/rules", tok,
                {"kind": "banned_service", "service": "telnet",
                 "risk_level": "high", "note": "평문 원격접속 금지(KISA)"})
        print(f"rule: telnet 금지 (매칭 {r['match_count']}건)")
    except urllib.error.HTTPError as e:
        print("rule skip:", e.read().decode("utf-8"))

    # 재매칭 반영 위해 자산 PATCH 한번(부서 채움)
    assets = req("GET", "/api/assets", tok)
    if assets:
        req("PATCH", f"/api/assets/{assets[0]['id']}", tok, {
            "ip": "127.0.0.1", "hostname": "ops-gateway-01",
            "dept": "인프라운영팀", "owner": "김도현 책임", "asset_no": "SRV-0142",
        })

    print("\n=== 최종 발견 ===")
    for f in sorted(req("GET", "/api/findings", tok), key=lambda x: x["port"]):
        print(f"  {f['host_ip']}:{f['port']:>5}/{f['proto']} {f['service']:11} "
              f"위험={f['risk_level']:6} 상태={f['status']:5} 부서={f['dept'] or '(미지정)'}")
    d = req("GET", "/api/dashboard", tok)
    print(f"\n대시보드: 열린 {d['open_total']} · 위험 {d['by_risk']} · 마감초과 {d['overdue']}")
    print("부서별:", [(x["dept"], x["count"]) for x in d["by_dept"]])


if __name__ == "__main__":
    main(sys.argv[1])
