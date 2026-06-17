"""자산대장 기준 데모 — SAMPLE1 자산(분리 owner/contact) 적재 + nmap 샘플 임포트.

전제: 서버 8770 가동, live_sample/sample1_hybrid.json(자산레코드) +
asset_scan_sample.xml(스캔) 존재.
사용: python live_sample/build_ledger_demo.py <admin_password>
"""
import json, sys, urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8770"
HERE = Path(__file__).resolve().parent


def req(method, path, token=None, body=None, file=None):
    headers, data = {}, None
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    if file is not None:
        boundary = "----scanops"
        payload = (f"--{boundary}\r\n".encode()
                   + f'Content-Disposition: form-data; name="file"; filename="{file.name}"\r\n'.encode()
                   + b"Content-Type: text/xml\r\n\r\n" + file.read_bytes() + b"\r\n"
                   + f"--{boundary}--\r\n".encode())
        data = payload
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(r, timeout=120) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else None


def main(pw):
    tok = req("POST", "/api/auth/login", body={"username": "admin", "password": pw})["token"]

    # 1) 자산대장(SAMPLE1 분리 결과) 적재
    recs = json.load(open(HERE / "sample1_hybrid.json", encoding="utf-8"))["records"]
    a = req("POST", "/api/assets/bulk", tok, recs)
    print(f"자산: 신규 {a['added']} / 갱신 {a['updated']}")

    # 2) nmap 샘플 임포트(같은 IP → 부서/담당/연락처 자동 매칭)
    counts = req("POST", "/api/scans/import", tok, file=HERE / "asset_scan_sample.xml")["counts"]
    print(f"스캔: {counts}")

    # 3) 위험 규칙: telnet 금지(고위험 데모)
    try:
        r = req("POST", "/api/rules", tok, {"kind": "banned_service", "service": "telnet",
                                            "risk_level": "banned", "note": "평문 원격접속 금지(KISA)"})
        print(f"규칙: telnet 금지 (매칭 {r['match_count']}건)")
    except urllib.error.HTTPError as e:
        print("규칙 skip:", e.read().decode("utf-8"))

    findings = req("GET", "/api/findings", tok)
    from collections import Counter
    by_dept = Counter(f["dept"] or "(미지정)" for f in findings)
    by_risk = Counter(f["risk_level"] for f in findings)
    sample = next((f for f in findings if f["port"] == 23), findings[0])
    print(f"\n발견 {len(findings)}건 · 부서별 {dict(by_dept)} · 위험별 {dict(by_risk)}")
    print(f"예시(telnet): {sample['host_ip']} 부서={sample['dept']} 연락처={sample['contact']} 위험={sample['risk_level']}")
    print("대시보드:", json.dumps(req("GET", "/api/dashboard", tok), ensure_ascii=False))


if __name__ == "__main__":
    main(sys.argv[1])
