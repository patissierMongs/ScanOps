"""데모 상태 시드 — 실행 중인 ScanOps 서버에 실제 nmap 스캔 2개를 흘려
라이프사이클(가져오기→배정→재스캔→조치 자동검증)을 채운다. UTF-8 보장.

사용: python seed_demo.py <admin_password>
"""
import json
import sys
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8770"
HERE = Path(__file__).resolve().parent


def req(method, path, token=None, body=None, file=None):
    url = BASE + path
    headers = {}
    data = None
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    if file is not None:
        boundary = "----scanops"
        payload = b""
        payload += f"--{boundary}\r\n".encode()
        payload += f'Content-Disposition: form-data; name="file"; filename="{file.name}"\r\n'.encode()
        payload += b"Content-Type: text/xml\r\n\r\n"
        payload += file.read_bytes() + b"\r\n"
        payload += f"--{boundary}--\r\n".encode()
        data = payload
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(r) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main(pw):
    tok = req("POST", "/api/auth/login", body={"username": "admin", "password": pw})["token"]
    req("POST", "/api/assets", tok, body={"ip": "127.0.0.1", "hostname": "wsl-local",
                                          "dept": "인프라운영팀", "owner": "홍길동"})
    print("스캔A:", req("POST", "/api/scans/import", tok, file=HERE / "scanA.xml")["counts"])
    findings = req("GET", "/api/findings", tok)
    f3000 = next(f for f in findings if f["port"] == 3000)
    assigned = req("PATCH", f"/api/findings/{f3000['id']}", tok,
                   body={"status": "처리중", "deadline": "2026-06-20T00:00:00"})
    print(f"3000 배정: status={assigned['status']} 마감={assigned['deadline'][:10]} dept={assigned['dept']}")
    print("스캔B:", req("POST", "/api/scans/import", tok, file=HERE / "scanB.xml")["counts"])
    final = req("GET", f"/api/findings/{f3000['id']}", tok)
    events = req("GET", f"/api/findings/{f3000['id']}/events", tok)
    print(f"3000 결과: state={final['state']} status={final['status']}")
    for e in events:
        print(f"  - {e['type']}: {e['detail']}")
    print("대시보드:", json.dumps(req("GET", "/api/dashboard", tok), ensure_ascii=False))


if __name__ == "__main__":
    main(sys.argv[1])
