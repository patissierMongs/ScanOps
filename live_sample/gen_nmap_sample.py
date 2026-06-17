"""자산대장(SAMPLE1.xlsx) 기준 nmap 스캔 샘플 XML 생성.

IP(1.1.1.1~1.1.1.7)·OS를 자산대장과 동일하게 맞춰, ScanOps 에 가져오면
부서/담당/연락처가 IP 매칭으로 자동 연결되도록 한다. 실제 nmap -oX 구조를 모사.
출력: live_sample/asset_scan_sample.xml
"""
import xml.etree.ElementTree as ET
from pathlib import Path

# (port, proto, service, product, version, ostype, extrainfo, [cpe], [(script_id, output)])
HOSTS = [
    ("1.1.1.1", "sec-pc-01", "보안 Windows 11", [
        (135, "tcp", "msrpc", "Microsoft Windows RPC", "", "Windows", "", ["cpe:/o:microsoft:windows"], []),
        (139, "tcp", "netbios-ssn", "Microsoft Windows netbios-ssn", "", "Windows", "", [], []),
        (445, "tcp", "microsoft-ds", "Microsoft Windows 11 microsoft-ds", "", "Windows", "", ["cpe:/o:microsoft:windows_11"], []),
        (3389, "tcp", "ms-wbt-server", "Microsoft Terminal Services", "", "Windows", "", [],
         [("ssl-cert", "Subject: commonName=sec-pc-01\nNot valid after: 2026-12-31")]),
    ]),
    ("1.1.1.2", "sec-pc-02", "보안 Windows 10", [
        (135, "tcp", "msrpc", "Microsoft Windows RPC", "", "Windows", "", [], []),
        (139, "tcp", "netbios-ssn", "Microsoft Windows netbios-ssn", "", "Windows", "", [], []),
        (445, "tcp", "microsoft-ds", "Microsoft Windows 10 microsoft-ds", "", "Windows", "", ["cpe:/o:microsoft:windows_10"], []),
    ]),
    ("1.1.1.3", "hr-pc-01", "인사 Ubuntu 22", [
        (22, "tcp", "ssh", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.6", "Linux", "Ubuntu Linux; protocol 2.0",
         ["cpe:/a:openbsd:openssh:8.9p1", "cpe:/o:linux:linux_kernel"], []),
    ]),
    ("1.1.1.4", "hr-srv-01", "인사 Linux 서버", [
        (22, "tcp", "ssh", "OpenSSH", "8.2p1 Ubuntu 4ubuntu0.5", "Linux", "protocol 2.0", ["cpe:/a:openbsd:openssh:8.2p1"], []),
        (80, "tcp", "http", "nginx", "1.18.0", "", "", ["cpe:/a:igor_sysoev:nginx:1.18.0"],
         [("http-title", "사내 인사 포털"), ("http-server-header", "nginx/1.18.0 (Ubuntu)")]),
        (3306, "tcp", "mysql", "MySQL", "8.0.32-0ubuntu0.20.04.2", "", "", ["cpe:/a:mysql:mysql:8.0.32"], []),
    ]),
    ("1.1.1.5", "infra-aix-01", "인프라 AIX 서버", [
        (21, "tcp", "ftp", "vsftpd", "3.0.3", "", "", [], [("ftp-anon", "Anonymous FTP login allowed (FTP code 230)")]),
        (22, "tcp", "ssh", "OpenSSH", "7.5", "AIX", "protocol 2.0", [], []),
        (23, "tcp", "telnet", "IBM AIX telnetd", "", "AIX", "", [], []),
    ]),
    ("1.1.1.6", "infra-cisco-01", "인프라 Cisco 장비", [
        (22, "tcp", "ssh", "Cisco SSH", "1.25", "IOS", "protocol 2.0", ["cpe:/o:cisco:ios"], []),
        (23, "tcp", "telnet", "Cisco router telnetd", "", "IOS", "", [], []),
        (161, "udp", "snmp", "SNMPv1 server", "", "", "public", [],
         [("snmp-info", "community: public (read)")]),
    ]),
    ("1.1.1.7", "infra-nbu-01", "인프라 Veritas 장비", [
        (22, "tcp", "ssh", "OpenSSH", "8.0", "Linux", "protocol 2.0", [], []),
        (443, "tcp", "https", "nginx", "1.20.1", "", "", [], [("ssl-cert", "Subject: commonName=infra-nbu-01")]),
        (1556, "tcp", "veritas-pbx", "Veritas NetBackup PBX", "", "", "", [], []),
    ]),
]


def build() -> ET.Element:
    root = ET.Element("nmaprun", scanner="nmap", args="nmap -sV -sC -O -oX asset_scan_sample.xml 1.1.1.1-7",
                      start="1750000000", version="7.99", xmloutputversion="1.05")
    ET.SubElement(root, "scaninfo", type="syn", protocol="tcp", services="1-65535")
    for ip, host, _desc, ports in HOSTS:
        h = ET.SubElement(root, "host")
        ET.SubElement(h, "status", state="up", reason="syn-ack")
        ET.SubElement(h, "address", addr=ip, addrtype="ipv4")
        hns = ET.SubElement(h, "hostnames")
        ET.SubElement(hns, "hostname", name=host, type="PTR")
        ET.SubElement(h, "times", srtt="42000", rttvar="8000", to="100000")
        ps = ET.SubElement(h, "ports")
        for (port, proto, name, product, version, ostype, extrainfo, cpes, scripts) in ports:
            p = ET.SubElement(ps, "port", protocol=proto, portid=str(port))
            ET.SubElement(p, "state", state="open", reason="syn-ack")
            svc = ET.SubElement(p, "service", name=name, method="probed", conf="10")
            if product:
                svc.set("product", product)
            if version:
                svc.set("version", version)
            if ostype:
                svc.set("ostype", ostype)
            if extrainfo:
                svc.set("extrainfo", extrainfo)
            for c in cpes:
                ET.SubElement(svc, "cpe").text = c
            for sid, out in scripts:
                ET.SubElement(p, "script", id=sid, output=out)
    ET.SubElement(root, "runstats")
    return root


def main():
    out = Path(__file__).resolve().parent / "asset_scan_sample.xml"
    ET.ElementTree(build()).write(out, encoding="utf-8", xml_declaration=True)
    n_ports = sum(len(h[3]) for h in HOSTS)
    print(f"wrote {out} : {len(HOSTS)} hosts, {n_ports} ports")


if __name__ == "__main__":
    main()
