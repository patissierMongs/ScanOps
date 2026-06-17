"""신기능 검증 2단계 — 타겟 재스캔(조치 자동검증 + scope 한정). (UTF-8)

전제: telnet(23) 컨테이너를 중지한 상태에서 실행.
"""
import json, urllib.request
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


def main():
    tok = open("samples/.token").read().strip()
    v1 = json.load(open("live_sample/verify1.json", encoding="utf-8"))
    telnet_id, http_id = v1["telnet_id"], v1["http_id"]

    # telnet 발견 처리중+마감 → 닫히면 자동 정상처리 검증
    req("PATCH", f"/api/findings/{telnet_id}", tok, {"status": "처리중", "deadline": "2026-06-20T00:00:00"})

    # 타겟 재스캔: telnet 발견만 (port 23 컨테이너는 중지됨)
    r = req("POST", "/api/findings/rescan", tok, {"finding_ids": [telnet_id], "options": ["version", "noping"]})
    telnet = req("GET", f"/api/findings/{telnet_id}", tok)
    http = req("GET", f"/api/findings/{http_id}", tok)

    out = {
        "rescan_command": r["command"],
        "counts": r["counts"],
        "telnet_state": telnet["state"], "telnet_status": telnet["status"],
        "http_state": http["state"], "http_status": http["status"],
        "scope_ok": http["state"] == "open",  # 스캔 안 한 80포트는 영향 없어야
        "verify_ok": telnet["state"] == "closed" and telnet["status"] == "정상처리",
    }
    open("live_sample/verify2.json", "w", encoding="utf-8").write(json.dumps(out, ensure_ascii=False, indent=1))
    print("OK rescan done")


if __name__ == "__main__":
    main()
