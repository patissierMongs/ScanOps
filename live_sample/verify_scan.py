"""신기능 검증 1단계 — 옵션 스캔(서버 nmap) + 금지 등급. (UTF-8)"""
import json, sys, urllib.request
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
    with urllib.request.urlopen(r, timeout=300) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else None


def main(pw):
    tok = req("POST", "/api/auth/login", body={"username": "admin", "password": pw})["token"]
    # 자산: 연락처 전파 확인용
    req("POST", "/api/assets", tok, {"ip": "127.0.0.1", "dept": "인프라운영팀", "contact": "010-1111-2222"})
    # 옵션 스캔(버전탐지 + 핑생략, 특정 포트)
    run = req("POST", "/api/scans/run", tok,
              {"name": "옵션 스캔", "options": ["version", "noping"],
               "ports": "21,23,80,5432,6379", "targets": ["127.0.0.1"]})
    scan = req("GET", f"/api/scans/{run['scan_id']}", tok)
    findings = req("GET", "/api/findings", tok)
    by_port = {f["port"]: f for f in findings}
    # 금지 규칙: telnet
    req("POST", "/api/rules", tok, {"kind": "banned_service", "service": "telnet", "risk_level": "banned",
                                    "note": "평문 원격접속 금지(KISA)"})
    telnet = req("GET", f"/api/findings/{by_port[23]['id']}", tok)

    out = {
        "command": scan["command"],
        "counts": run["counts"],
        "n_findings": len(findings),
        "telnet_id": by_port[23]["id"],
        "http_id": by_port[80]["id"],
        "telnet_risk_after_rule": telnet["risk_level"],
        "telnet_contact": telnet["contact"],
        "risks": {f["port"]: f["risk_level"] for f in findings},
    }
    open("live_sample/verify1.json", "w", encoding="utf-8").write(json.dumps(out, ensure_ascii=False, indent=1))
    open("samples/.token", "w").write(tok)
    print("OK scan done")


if __name__ == "__main__":
    main(sys.argv[1])
