"""엣지케이스 nmap 스캔 결과 샘플 생성기 (순수 표준 라이브러리).

ScanOps 의 XML 파서(`nmap_parse.parse_xml`)·인입(`ingest`)·분류(`taxonomy.classify`)·
재스캔 조치검증(diff)이 다양한 현실 엣지케이스에서 어떻게 동작하는지 실측하기 위한
스캔 결과 XML 4종을 만든다. 임베디드 파이썬으로도 돌도록 stdlib 만 사용.

출력(스크립트와 같은 폴더):
  scan_01_baseline.xml       기준 스캔 — 15 호스트, 온갖 엣지 서비스/상태/NSE/인코딩
  scan_02_rescan.xml         재스캔 — 일부 포트 닫힘(조치완료)/신규개방/버전변경 diff
  scan_03_discovery_only.xml 발견만 됨(up) · 열린 포트 0 (노출 없음/partial 경로)
  scan_04_broken.xml         깨진 XML — 가져오기 오류(400) 처리 경로

사용: python gen_scan_samples.py
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent

# 포트 스펙: (portid, proto, state, svc_name, method, product, version, extrainfo,
#            ostype, [cpe...], [(script_id, output)...])
# state 가 open* 이 아니면 파서가 무시(닫힘/필터 섞여도 안전)한다 — 일부러 섞어 둔다.


def _host(root, ip, hostname, ports, *, state="up", reason="syn-ack",
          addrtype="ipv4", extra_addrs=(), hostscripts=()):
    """호스트 엘리먼트 추가. ip=None 이면 주소 생략(MAC 전용 등 특수 케이스)."""
    h = ET.SubElement(root, "host", starttime="1789000000", endtime="1789000600")
    ET.SubElement(h, "status", state=state, reason=reason, reason_ttl="64")
    if ip is not None:
        ET.SubElement(h, "address", addr=ip, addrtype=addrtype)
    for a_addr, a_type in extra_addrs:
        ET.SubElement(h, "address", addr=a_addr, addrtype=a_type)
    hns = ET.SubElement(h, "hostnames")
    if hostname:
        ET.SubElement(hns, "hostname", name=hostname, type="PTR")
    ps = ET.SubElement(h, "ports")
    for (portid, proto, pstate, name, method, product, version, extrainfo,
         ostype, cpes, scripts) in ports:
        p = ET.SubElement(ps, "port", protocol=proto, portid=str(portid))
        ET.SubElement(p, "state",
                      state=pstate,
                      reason="syn-ack" if pstate.startswith("open") else "reset",
                      reason_ttl="64")
        svc = ET.SubElement(p, "service", name=name, method=method,
                            conf="10" if method == "probed" else "3")
        if product:
            svc.set("product", product)
        if version:
            svc.set("version", version)
        if extrainfo:
            svc.set("extrainfo", extrainfo)
        if ostype:
            svc.set("ostype", ostype)
        for c in cpes:
            ET.SubElement(svc, "cpe").text = c
        for sid, out in scripts:
            ET.SubElement(p, "script", id=sid, output=out)
    ET.SubElement(h, "times", srtt="41230", rttvar="9000", to="100000")
    for sid, out in hostscripts:
        hs = ET.SubElement(h, "hostscript")
        ET.SubElement(hs, "script", id=sid, output=out)
    return h


def _wrap(root, elapsed="612.44", up=1, down=0, total=1):
    rs = ET.SubElement(root, "runstats")
    ET.SubElement(rs, "finished", time="1789000612", timestr="Mon Jul 13 04:16:52 2026",
                  summary=f"Nmap done; {total} IP addresses ({up} hosts up) scanned in {elapsed} seconds",
                  elapsed=elapsed, exit="success")
    ET.SubElement(rs, "hosts", up=str(up), down=str(down), total=str(total))


def _root(args, start="1789000000", startstr="Mon Jul 13 04:06:40 2026"):
    root = ET.Element("nmaprun", scanner="nmap", args=args, start=start,
                      startstr=startstr, version="7.94SVN", xmloutputversion="1.05")
    ET.SubElement(root, "scaninfo", type="syn", protocol="tcp", numservices="1000",
                  services="1-1000")
    return root


# NSE 출력 상수(가독성)
SSL_CERT = ("ssl-cert",
            "Subject: commonName=sec-pc-01.corp.local/organizationName=Corp\n"
            "Not valid before: 2025-01-01T00:00:00\nNot valid after:  2026-12-31T23:59:59")
FTP_ANON = ("ftp-anon", "Anonymous FTP login allowed (FTP code 230)")
SNMP_INFO = ("snmp-info", "  community: public (read)\n  engineIDData: ...\n  snmpEngineBoots: 12")
HTTP_TITLE_KO = ("http-title", "사내 인사 포털 - HR Portal")
HTTP_SRV = ("http-server-header", "nginx/1.18.0 (Ubuntu)")
SMB_OS = ("smb-os-discovery",
          "  OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)\n"
          "  Computer name: no-ptr-srv\n  NetBIOS computer name: NO-PTR-SRV\n  Workgroup: CORP")
# 8770(ScanOps 자체) 이 nmap 시그니처 부재로 apple-iphoto 로 오탐되지만
# fingerprint-strings 에 정체(uvicorn) 가 남는 유명 케이스.
FP_UVICORN = ("fingerprint-strings",
              "  GetRequest:\n    HTTP/1.1 404 Not Found\n    date: Mon, 13 Jul 2026 04:10:00 GMT\n"
              "    server: uvicorn\n    content-type: application/json\n    {\"detail\":\"Not Found\"}\n"
              "  HTTPOptions:\n    HTTP/1.1 405 Method Not Allowed\n    server: uvicorn\n    allow: GET")


def build_baseline() -> ET.Element:
    root = _root("nmap -sS -sU -sV -sC -O -oX scan_01_baseline.xml 10.10.20.0/24")
    # 1) Windows 보안 PC — SMB/RDP(고위험) + 닫힌 telnet 섞임 + ssl-cert NSE
    _host(root, "10.10.20.11", "sec-pc-01", [
        (135, "tcp", "open", "msrpc", "probed", "Microsoft Windows RPC", "", "", "Windows", ["cpe:/o:microsoft:windows"], []),
        (139, "tcp", "open", "netbios-ssn", "probed", "Microsoft Windows netbios-ssn", "", "", "Windows", [], []),
        (445, "tcp", "open", "microsoft-ds", "probed", "Windows Server 2019 microsoft-ds", "", "", "Windows", ["cpe:/o:microsoft:windows_server_2019"], []),
        (3389, "tcp", "open", "ms-wbt-server", "probed", "Microsoft Terminal Services", "", "", "Windows", [], [SSL_CERT]),
        (23, "tcp", "closed", "telnet", "table", "", "", "", "", [], []),   # 닫힘 — 파서 무시
    ])
    # 2) 리눅스 인사 서버 — ssh/http/mysql + 한글 http-title + server-header
    _host(root, "10.10.20.12", "hr-srv-01", [
        (22, "tcp", "open", "ssh", "probed", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.6", "Ubuntu Linux; protocol 2.0", "Linux",
         ["cpe:/a:openbsd:openssh:8.9p1", "cpe:/o:linux:linux_kernel"], []),
        (80, "tcp", "open", "http", "probed", "nginx", "1.18.0", "", "", ["cpe:/a:igor_sysoev:nginx:1.18.0"], [HTTP_TITLE_KO, HTTP_SRV]),
        (3306, "tcp", "open", "mysql", "probed", "MySQL", "8.0.32-0ubuntu0.20.04.2", "", "", ["cpe:/a:mysql:mysql:8.0.32"], []),
    ])
    # 3) AIX 인프라 — ftp(anon)/ssh/telnet(평문)
    _host(root, "10.10.20.13", "infra-aix-01", [
        (21, "tcp", "open", "ftp", "probed", "vsftpd", "3.0.3", "", "", [], [FTP_ANON]),
        (22, "tcp", "open", "ssh", "probed", "OpenSSH", "7.5", "protocol 2.0", "AIX", [], []),
        (23, "tcp", "open", "telnet", "probed", "IBM AIX telnetd", "", "", "AIX", [], []),
    ])
    # 4) 금융 DB 서버 — mssql/postgres/redis(무인증)/mongo (전부 고위험 DB 노출)
    _host(root, "10.10.20.14", "fin-db-01", [
        (1433, "tcp", "open", "ms-sql-s", "probed", "Microsoft SQL Server", "2019 15.00.2000", "", "", ["cpe:/a:microsoft:sql_server"], []),
        (5432, "tcp", "open", "postgresql", "probed", "PostgreSQL DB", "13.11", "", "", [], []),
        (6379, "tcp", "open", "redis", "probed", "Redis key-value store", "6.0.16", "", "", [], []),
        (27017, "tcp", "open", "mongodb", "probed", "MongoDB", "4.4.18", "", "", [], []),
    ])
    # 5) 리버스 프록시 — 8770 uvicorn 이 apple-iphoto 로 오탐(fingerprint 에 정체) + tcpwrapped 443
    _host(root, "10.10.20.15", "web-proxy-01", [
        (443, "tcp", "open", "tcpwrapped", "probed", "", "", "", "", [], []),
        (8770, "tcp", "open", "apple-iphoto", "probed", "", "", "", "", [], [FP_UVICORN]),
    ])
    # 6) 미확인/추측 — unknown(미확인) + 이름없음 table(추측)
    _host(root, "10.10.20.16", "misc-01", [
        (9999, "tcp", "open", "unknown", "table", "", "", "", "", [], []),
        (12345, "tcp", "open", "", "table", "", "", "", "", [], []),
    ])
    # 7) IoT 카메라 — XML 특수문자(& < > ") 이스케이프 경로 시험
    _host(root, "10.10.20.17", "iot-cam-01", [
        (554, "tcp", "open", "rtsp", "probed", "Hipcam RealServer/V1.0", "", "", "", [], []),
        (8000, "tcp", "open", "http", "probed", 'Foo & Bar <cam> "web"', "1.0", "a<b>&c", "", [], [("http-title", 'Cam & "Live" <feed>')]),
    ])
    # 8) DNS/NTP/SNMP — UDP open|filtered + snmp public 커뮤니티
    _host(root, "10.10.20.18", "dns-01", [
        (53, "udp", "open", "domain", "probed", "ISC BIND", "9.16.1", "", "", [], []),
        (123, "udp", "open|filtered", "ntp", "table", "", "", "", "", [], []),
        (161, "udp", "open", "snmp", "probed", "SNMPv1 server", "", "public", "", [], [SNMP_INFO]),
    ])
    # 9) 다운 호스트 — 열린 포트 0 (status=down)
    _host(root, "10.10.20.19", "", [], state="down", reason="no-response")
    # 10) MAC 전용 주소 호스트(로컬 이더넷) — ipv4 없음, addrtype=mac 폴백 경로
    _host(root, None, "printer-mac", [
        (9100, "tcp", "open", "jetdirect", "probed", "HP JetDirect", "", "", "", [], []),
    ], extra_addrs=[("A4:BB:6D:11:22:33", "mac")])
    # 11) IPv6 전용 호스트 — ipv4 없음, addrtype=ipv6 폴백 경로
    _host(root, "2001:db8:20::a", "v6-host-01", [
        (22, "tcp", "open", "ssh", "probed", "OpenSSH", "9.6p1", "protocol 2.0", "Linux", [], []),
        (443, "tcp", "open", "https", "probed", "Apache httpd", "2.4.58", "", "", [], []),
    ], addrtype="ipv6")
    # 12) PTR 없는 서버 — hostname 비고, smb-os-discovery(hostscript)에 컴퓨터명(폴백 근거)
    _host(root, "10.10.20.21", "", [
        (445, "tcp", "open", "microsoft-ds", "probed", "Windows Server 2019 microsoft-ds", "", "", "Windows", [], []),
    ], hostscripts=[SMB_OS])
    # 13) 레거시 유닉스 — rpcbind/nfs/r-services (평문·고위험)
    _host(root, "10.10.20.22", "legacy-01", [
        (111, "tcp", "open", "rpcbind", "probed", "", "2-4", "RPC #100000", "", [], []),
        (2049, "tcp", "open", "nfs", "probed", "", "3-4", "RPC #100003", "", [], []),
        (513, "tcp", "open", "login", "probed", "", "", "", "", [], []),
        (514, "tcp", "open", "shell", "probed", "", "", "", "", [], []),
    ])
    # 14) VNC(무인증) — 원격데스크톱 고위험
    _host(root, "10.10.20.23", "ops-vnc-01", [
        (5900, "tcp", "open", "vnc", "probed", "VNC (protocol 3.8)", "", "", "", [], []),
        (5901, "tcp", "open", "vnc", "probed", "VNC (protocol 3.8)", "", "", "", [], []),
    ])
    # 15) 필터 전용 호스트 — up 이지만 열린 포트 0 (전부 filtered) → 발견 0
    _host(root, "10.10.20.26", "fw-shadow-01", [
        (80, "tcp", "filtered", "http", "table", "", "", "", "", [], []),
        (443, "tcp", "filtered", "https", "table", "", "", "", "", [], []),
    ])
    _wrap(root, elapsed="612.44", up=13, down=1, total=254)
    return root


def build_rescan() -> ET.Element:
    """scan_01 의 부분집합 재스캔 — 조치검증 diff 를 만든다.

    - infra-aix-01: telnet 닫힘(조치완료) · ftp 필터드(도달불가 추정) · ssh 유지
    - sec-pc-01:    rdp 닫힘(조치완료) · 445 유지 · winrm 신규개방(NEW_OPEN)
    - hr-srv-01:    nginx 1.18.0 -> 1.24.0 버전변경(SERVICE_CHANGED) · mysql 유지
    """
    root = _root("nmap -sS -sV -p T:22,23,80,445,3306,3389,5985,21 -oX scan_02_rescan.xml 10.10.20.11-13",
                 start="1789600000", startstr="Mon Jul 20 04:06:40 2026")
    _host(root, "10.10.20.11", "sec-pc-01", [
        (445, "tcp", "open", "microsoft-ds", "probed", "Windows Server 2019 microsoft-ds", "", "", "Windows", [], []),
        (3389, "tcp", "closed", "ms-wbt-server", "table", "", "", "", "", [], []),   # 조치완료
        (5985, "tcp", "open", "http", "probed", "Microsoft HTTPAPI httpd", "2.0", "SSDP/UPnP", "", [], []),  # 신규
    ])
    _host(root, "10.10.20.12", "hr-srv-01", [
        (80, "tcp", "open", "http", "probed", "nginx", "1.24.0", "", "", ["cpe:/a:igor_sysoev:nginx:1.24.0"], [HTTP_SRV]),  # 버전변경
        (3306, "tcp", "open", "mysql", "probed", "MySQL", "8.0.32-0ubuntu0.20.04.2", "", "", [], []),
    ])
    _host(root, "10.10.20.13", "infra-aix-01", [
        (22, "tcp", "open", "ssh", "probed", "OpenSSH", "7.5", "protocol 2.0", "AIX", [], []),
        (23, "tcp", "closed", "telnet", "table", "", "", "", "", [], []),   # 조치완료(능동 거부)
        (21, "tcp", "filtered", "ftp", "table", "", "", "", "", [], []),    # 미관측(방화벽/도달불가 추정)
    ])
    _wrap(root, elapsed="48.10", up=3, down=0, total=3)
    return root


def build_discovery_only() -> ET.Element:
    root = _root("nmap -sn -PE -PS22,80,443 -oX scan_03_discovery_only.xml 10.10.30.0/24")
    for i, name in ((41, "vlan30-a"), (42, "vlan30-b"), (43, "vlan30-c")):
        _host(root, f"10.10.30.{i}", name, [
            (80, "tcp", "filtered", "http", "table", "", "", "", "", [], []),
        ])
    _wrap(root, elapsed="9.02", up=3, down=0, total=254)
    return root


def write(root: ET.Element, name: str) -> None:
    out = HERE / name
    ET.ElementTree(root).write(out, encoding="utf-8", xml_declaration=True)
    print(f"wrote {out.name}")


def write_broken() -> None:
    """일부러 깨진 XML — 가져오기 오류(400) 경로 시험. 태그 미완결로 잘림."""
    out = HERE / "scan_04_broken.xml"
    out.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<nmaprun scanner="nmap" args="nmap -sV 10.10.20.11" start="1789000000" version="7.94">\n'
        '<host><status state="up" reason="syn-ack"/>\n'
        '<address addr="10.10.20.11" addrtype="ipv4"/>\n'
        '<ports><port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/>\n'
        '<service name="microsoft-ds" method="probed" conf="10"\n',   # 미완결로 잘림
        encoding="utf-8")
    print(f"wrote {out.name}")


def main() -> None:
    write(build_baseline(), "scan_01_baseline.xml")
    write(build_rescan(), "scan_02_rescan.xml")
    write(build_discovery_only(), "scan_03_discovery_only.xml")
    write_broken()


if __name__ == "__main__":
    main()
