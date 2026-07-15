"""엣지케이스 + 대규모(1000+ 발견) nmap 스캔 결과 샘플 생성기 (순수 표준 라이브러리).

ScanOps 의 XML 파서·인입·분류·재스캔 조치검증(diff)을 현실 규모(1000+ 개방포트)와
다양한 엣지케이스에서 실측한다. IP 대역을 자산대장(asset_ledger_dirty.xlsx)과 겹치게 잡아,
둘 다 가져오면 IP 매칭으로 발견에 부서/담당이 대량 연결되는 것을 검증할 수 있다.
임베디드 파이썬으로도 돌도록 stdlib 만 사용.

출력(스크립트와 같은 폴더):
  scan_01_baseline.xml       기준 스캔 — 엣지 15 호스트 + 대량 ~190 호스트(1000+ 개방포트)
  scan_02_rescan.xml         중복(재)스캔 — 포트 닫힘/신규개방/버전변경/포트번호이동 diff
  scan_03_discovery_only.xml 발견만(up) · 열린 포트 0
  scan_04_broken.xml         깨진 XML — 가져오기 오류 경로

사용: python gen_scan_samples.py
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _host(root, ip, hostname, ports, *, state="up", reason="syn-ack",
          addrtype="ipv4", extra_addrs=(), hostscripts=()):
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


# ---- NSE 출력 상수 ----
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
FP_UVICORN = ("fingerprint-strings",
              "  GetRequest:\n    HTTP/1.1 404 Not Found\n    date: Mon, 13 Jul 2026 04:10:00 GMT\n"
              "    server: uvicorn\n    content-type: application/json\n    {\"detail\":\"Not Found\"}\n"
              "  HTTPOptions:\n    HTTP/1.1 405 Method Not Allowed\n    server: uvicorn\n    allow: GET")


def build_edge_hosts(root) -> None:
    """파서/분류 엣지케이스를 노리는 15 호스트(그대로 유지)."""
    _host(root, "10.10.20.11", "sec-pc-01", [
        (135, "tcp", "open", "msrpc", "probed", "Microsoft Windows RPC", "", "", "Windows", ["cpe:/o:microsoft:windows"], []),
        (139, "tcp", "open", "netbios-ssn", "probed", "Microsoft Windows netbios-ssn", "", "", "Windows", [], []),
        (445, "tcp", "open", "microsoft-ds", "probed", "Windows Server 2019 microsoft-ds", "", "", "Windows", ["cpe:/o:microsoft:windows_server_2019"], []),
        (3389, "tcp", "open", "ms-wbt-server", "probed", "Microsoft Terminal Services", "", "", "Windows", [], [SSL_CERT]),
        (23, "tcp", "closed", "telnet", "table", "", "", "", "", [], []),
    ])
    _host(root, "10.10.20.12", "hr-srv-01", [
        (22, "tcp", "open", "ssh", "probed", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.6", "Ubuntu Linux; protocol 2.0", "Linux",
         ["cpe:/a:openbsd:openssh:8.9p1", "cpe:/o:linux:linux_kernel"], []),
        (80, "tcp", "open", "http", "probed", "nginx", "1.18.0", "", "", ["cpe:/a:igor_sysoev:nginx:1.18.0"], [HTTP_TITLE_KO, HTTP_SRV]),
        (3306, "tcp", "open", "mysql", "probed", "MySQL", "8.0.32-0ubuntu0.20.04.2", "", "", ["cpe:/a:mysql:mysql:8.0.32"], []),
    ])
    _host(root, "10.10.20.13", "infra-aix-01", [
        (21, "tcp", "open", "ftp", "probed", "vsftpd", "3.0.3", "", "", [], [FTP_ANON]),
        (22, "tcp", "open", "ssh", "probed", "OpenSSH", "7.5", "protocol 2.0", "AIX", [], []),
        (23, "tcp", "open", "telnet", "probed", "IBM AIX telnetd", "", "", "AIX", [], []),
    ])
    _host(root, "10.10.20.14", "fin-db-01", [
        (1433, "tcp", "open", "ms-sql-s", "probed", "Microsoft SQL Server", "2019 15.00.2000", "", "", ["cpe:/a:microsoft:sql_server"], []),
        (5432, "tcp", "open", "postgresql", "probed", "PostgreSQL DB", "13.11", "", "", [], []),
        (6379, "tcp", "open", "redis", "probed", "Redis key-value store", "6.0.16", "", "", [], []),
        (27017, "tcp", "open", "mongodb", "probed", "MongoDB", "4.4.18", "", "", [], []),
    ])
    _host(root, "10.10.20.15", "web-proxy-01", [
        (443, "tcp", "open", "tcpwrapped", "probed", "", "", "", "", [], []),
        (8770, "tcp", "open", "apple-iphoto", "probed", "", "", "", "", [], [FP_UVICORN]),
    ])
    _host(root, "10.10.20.16", "misc-01", [
        (9999, "tcp", "open", "unknown", "table", "", "", "", "", [], []),
        (12345, "tcp", "open", "", "table", "", "", "", "", [], []),
    ])
    _host(root, "10.10.20.17", "iot-cam-01", [
        (554, "tcp", "open", "rtsp", "probed", "Hipcam RealServer/V1.0", "", "", "", [], []),
        (8000, "tcp", "open", "http", "probed", 'Foo & Bar <cam> "web"', "1.0", "a<b>&c", "", [], [("http-title", 'Cam & "Live" <feed>')]),
    ])
    _host(root, "10.10.20.18", "dns-01", [
        (53, "udp", "open", "domain", "probed", "ISC BIND", "9.16.1", "", "", [], []),
        (123, "udp", "open|filtered", "ntp", "table", "", "", "", "", [], []),
        (161, "udp", "open", "snmp", "probed", "SNMPv1 server", "", "public", "", [], [SNMP_INFO]),
    ])
    _host(root, "10.10.20.19", "", [], state="down", reason="no-response")
    _host(root, None, "printer-mac", [
        (9100, "tcp", "open", "jetdirect", "probed", "HP JetDirect", "", "", "", [], []),
    ], extra_addrs=[("A4:BB:6D:11:22:33", "mac")])
    _host(root, "2001:db8:20::a", "v6-host-01", [
        (22, "tcp", "open", "ssh", "probed", "OpenSSH", "9.6p1", "protocol 2.0", "Linux", [], []),
        (443, "tcp", "open", "https", "probed", "Apache httpd", "2.4.58", "", "", [], []),
    ], addrtype="ipv6")
    _host(root, "10.10.20.21", "", [
        (445, "tcp", "open", "microsoft-ds", "probed", "Windows Server 2019 microsoft-ds", "", "", "Windows", [], []),
    ], hostscripts=[SMB_OS])
    _host(root, "10.10.20.22", "legacy-01", [
        (111, "tcp", "open", "rpcbind", "probed", "", "2-4", "RPC #100000", "", [], []),
        (2049, "tcp", "open", "nfs", "probed", "", "3-4", "RPC #100003", "", [], []),
        (513, "tcp", "open", "login", "probed", "", "", "", "", [], []),
        (514, "tcp", "open", "shell", "probed", "", "", "", "", [], []),
    ])
    _host(root, "10.10.20.23", "ops-vnc-01", [
        (5900, "tcp", "open", "vnc", "probed", "VNC (protocol 3.8)", "", "", "", [], []),
        (5901, "tcp", "open", "vnc", "probed", "VNC (protocol 3.8)", "", "", "", [], []),
    ])
    _host(root, "10.10.20.26", "fw-shadow-01", [
        (80, "tcp", "filtered", "http", "table", "", "", "", "", [], []),
        (443, "tcp", "filtered", "https", "table", "", "", "", "", [], []),
    ])


# ---- 대량 호스트 생성 (자산대장 IP 대역과 정렬) ----
# 역할별 포트 풀: (portid, proto, service, product, version_tmpl)  version_tmpl 에 {v} 치환
ROLE_PORTS = {
    "win": [
        (135, "tcp", "msrpc", "Microsoft Windows RPC", ""),
        (139, "tcp", "netbios-ssn", "Microsoft Windows netbios-ssn", ""),
        (445, "tcp", "microsoft-ds", "Windows Server 2019 microsoft-ds", ""),
        (3389, "tcp", "ms-wbt-server", "Microsoft Terminal Services", ""),
        (5985, "tcp", "http", "Microsoft HTTPAPI httpd", "2.0"),
    ],
    "web": [
        (22, "tcp", "ssh", "OpenSSH", "8.{v}p1"),
        (80, "tcp", "http", "nginx", "1.1{v}.0"),
        (443, "tcp", "https", "nginx", "1.1{v}.0"),
        (8080, "tcp", "http-proxy", "Apache httpd", "2.4.5{v}"),
    ],
    "db": [
        (22, "tcp", "ssh", "OpenSSH", "8.{v}p1"),
        (3306, "tcp", "mysql", "MySQL", "8.0.3{v}"),
        (5432, "tcp", "postgresql", "PostgreSQL DB", "1{v}.5"),
        (6379, "tcp", "redis", "Redis key-value store", "6.0.1{v}"),
        (1433, "tcp", "ms-sql-s", "Microsoft SQL Server", "2019 15.00.200{v}"),
    ],
    "legacy": [
        (21, "tcp", "ftp", "vsftpd", "3.0.{v}"),
        (23, "tcp", "telnet", "Linux telnetd", ""),
        (22, "tcp", "ssh", "OpenSSH", "7.{v}"),
        (111, "tcp", "rpcbind", "", "2-4"),
        (2049, "tcp", "nfs", "", "3-4"),
    ],
    "mail": [
        (25, "tcp", "smtp", "Postfix smtpd", ""),
        (110, "tcp", "pop3", "Dovecot pop3d", ""),
        (143, "tcp", "imap", "Dovecot imapd", ""),
        (993, "tcp", "imaps", "Dovecot imapd", ""),
        (22, "tcp", "ssh", "OpenSSH", "8.{v}p1"),
    ],
    "infra_udp": [
        (22, "tcp", "ssh", "OpenSSH", "9.{v}p1"),
        (53, "udp", "domain", "ISC BIND", "9.1{v}.1"),
        (123, "udp", "ntp", "NTP", ""),
        (161, "udp", "snmp", "SNMPv1 server", ""),
        (500, "udp", "isakmp", "", ""),
    ],
    "iot": [
        (80, "tcp", "http", "GoAhead WebServer", ""),
        (554, "tcp", "rtsp", "Hipcam RealServer/V1.0", ""),
        (8000, "tcp", "http", "lighttpd", "1.4.{v}"),
        (9100, "tcp", "jetdirect", "HP JetDirect", ""),
    ],
}
ROLE_ORDER = ["web", "db", "win", "legacy", "mail", "infra_udp", "iot"]

# (prefix, first_octet, count) — 자산대장 gen_dirty_ledger 블록과 같은 대역으로 잡아 겹치게.
SUBNETS = [
    ("10.10.20.", 30, 50),
    ("10.10.40.", 11, 50),
    ("10.10.41.", 11, 30),
    ("10.10.42.", 11, 25),
    ("172.16.10.", 11, 25),
    ("172.16.20.", 11, 25),
    ("10.10.50.", 10, 25),
]


def host_plan() -> list[tuple[str, str, str]]:
    """(ip, hostname, role) 결정론적 목록 — baseline/rescan 이 공유."""
    plan: list[tuple[str, str, str]] = []
    idx = 0
    for prefix, start, count in SUBNETS:
        for k in range(count):
            octet = start + k
            role = ROLE_ORDER[idx % len(ROLE_ORDER)]
            ip = f"{prefix}{octet}"
            host = f"{role}-{prefix.replace('.', '_')}{octet}"
            plan.append((ip, host, role))
            idx += 1
    return plan


def ports_for(role: str, octet: int, shift: int = 0) -> list:
    """역할 포트 풀 → _host 포맷 포트 튜플. version_tmpl 의 {v} 를 octet 로 변주."""
    v = str((octet + shift) % 9)
    out = []
    for (portid, proto, name, product, tmpl) in ROLE_PORTS[role]:
        version = tmpl.format(v=v) if tmpl else ""
        method = "probed" if product else "table"
        # UDP 일부는 open|filtered(엣지), snmp 는 public 커뮤니티
        state = "open"
        extrainfo = ""
        scripts = []
        if proto == "udp" and portid in (123, 500):
            state = "open|filtered"
            method = "table"
        if name == "snmp":
            extrainfo = "public"
            scripts = [SNMP_INFO]
        ostype = "Windows" if role == "win" else ""
        out.append((portid, proto, state, name, method, product, version, extrainfo, ostype, [], scripts))
    return out


def add_bulk(root, shift: int = 0) -> int:
    n = 0
    for ip, host, role in host_plan():
        octet = int(ip.split(".")[-1])
        _host(root, ip, host, ports_for(role, octet, shift))
        n += 1
    return n


def build_baseline() -> ET.Element:
    root = _root("nmap -sS -sU -sV -sC -O -oX scan_01_baseline.xml 10.10.20.0/24 10.10.40.0/24 172.16.0.0/16")
    build_edge_hosts(root)
    nb = add_bulk(root, shift=0)
    _wrap(root, elapsed="2841.10", up=15 + nb, down=1, total=1024)
    return root


def _mutate_for_rescan(role: str, octet: int) -> list:
    """재스캔 diff — 버전변경(shift=1) + 포트번호이동/닫힘/신규개방을 섞는다."""
    ports = ports_for(role, octet, shift=1)   # 버전 변주 → SERVICE_CHANGED
    out = []
    for tup in ports:
        portid, proto = tup[0], tup[1]
        # 3의 배수 호스트: 고위험/평문 포트 하나를 닫음(조치완료)
        if octet % 3 == 0 and portid in (23, 3389, 6379, 21):
            out.append((portid, proto, "closed", tup[3], "table", "", "", "", "", [], []))
            continue
        # web 역할: 8080 → 8000 포트번호 이동(옛 포트 닫고 새 포트 개방)
        if role == "web" and portid == 8080:
            out.append((8080, "tcp", "closed", "http-proxy", "table", "", "", "", "", [], []))
            out.append((8000, "tcp", "open", "http", "probed", "Apache httpd", "2.4.59", "moved", "", [], []))
            continue
        out.append(tup)
    # 5의 배수 호스트: 신규 포트 개방(NEW_OPEN)
    if octet % 5 == 0:
        out.append((8443, "tcp", "open", "https-alt", "probed", "nginx", "1.25.3", "", "", [], []))
    return out


def build_rescan() -> ET.Element:
    """중복(재)스캔 — baseline 의 앞부분 대역을 다시 훑어 대량 diff 를 만든다."""
    root = _root("nmap -sS -sU -sV -p- -oX scan_02_rescan.xml 10.10.20.0/24 10.10.40.0/24",
                 start="1789600000", startstr="Mon Jul 20 04:06:40 2026")
    # 엣지 3종 재스캔(조치완료/신규/버전변경) — 기존 시나리오 유지
    _host(root, "10.10.20.11", "sec-pc-01", [
        (445, "tcp", "open", "microsoft-ds", "probed", "Windows Server 2019 microsoft-ds", "", "", "Windows", [], []),
        (3389, "tcp", "closed", "ms-wbt-server", "table", "", "", "", "", [], []),
        (5985, "tcp", "open", "http", "probed", "Microsoft HTTPAPI httpd", "2.0", "SSDP/UPnP", "", [], []),
    ])
    _host(root, "10.10.20.12", "hr-srv-01", [
        (80, "tcp", "open", "http", "probed", "nginx", "1.24.0", "", "", ["cpe:/a:igor_sysoev:nginx:1.24.0"], [HTTP_SRV]),
        (3306, "tcp", "open", "mysql", "probed", "MySQL", "8.0.32-0ubuntu0.20.04.2", "", "", [], []),
    ])
    _host(root, "10.10.20.13", "infra-aix-01", [
        (22, "tcp", "open", "ssh", "probed", "OpenSSH", "7.5", "protocol 2.0", "AIX", [], []),
        (23, "tcp", "closed", "telnet", "table", "", "", "", "", [], []),
        (21, "tcp", "filtered", "ftp", "table", "", "", "", "", [], []),
    ])
    # 대량 재스캔 — 10.10.20. / 10.10.40. 대역만(엣지 IP 제외)
    n = 0
    for ip, host, role in host_plan():
        if not (ip.startswith("10.10.20.") or ip.startswith("10.10.40.")):
            continue
        octet = int(ip.split(".")[-1])
        _host(root, ip, host, _mutate_for_rescan(role, octet))
        n += 1
    _wrap(root, elapsed="1420.55", up=3 + n, down=0, total=512)
    return root


def build_discovery_only() -> ET.Element:
    root = _root("nmap -sn -PE -PS22,80,443 -oX scan_03_discovery_only.xml 10.10.30.0/24")
    for i, name in ((41, "vlan30-a"), (42, "vlan30-b"), (43, "vlan30-c")):
        _host(root, f"10.10.30.{i}", name, [
            (80, "tcp", "filtered", "http", "table", "", "", "", "", [], []),
        ])
    _wrap(root, elapsed="9.02", up=3, down=0, total=254)
    return root


def write(root: ET.Element, name: str) -> int:
    out = HERE / name
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")   # 실제 nmap XML 처럼 요소별 줄바꿈(가독 + 1000줄+)
    tree.write(out, encoding="utf-8", xml_declaration=True)
    lines = out.read_text(encoding="utf-8").count("\n") + 1
    print(f"wrote {out.name} ({lines} lines)")
    return lines


def write_broken() -> None:
    out = HERE / "scan_04_broken.xml"
    out.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<nmaprun scanner="nmap" args="nmap -sV 10.10.20.11" start="1789000000" version="7.94">\n'
        '<host><status state="up" reason="syn-ack"/>\n'
        '<address addr="10.10.20.11" addrtype="ipv4"/>\n'
        '<ports><port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/>\n'
        '<service name="microsoft-ds" method="probed" conf="10"\n',
        encoding="utf-8")
    print(f"wrote {out.name}")


def main() -> None:
    write(build_baseline(), "scan_01_baseline.xml")
    write(build_rescan(), "scan_02_rescan.xml")
    write(build_discovery_only(), "scan_03_discovery_only.xml")
    write_broken()


if __name__ == "__main__":
    main()
