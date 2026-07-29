"""ScanOps 통합 테스트용 더미 샘플 생성기.

산출물(모두 test_samples/ 아래):
  scan_*.xml  x5  — nmap -oX 형식 스캔 결과(각 300줄 이상, 실제 파서가 인입)
  assets_*.csv x5 — 자산대장(각 300행 이상, 프론트 자산 가져오기가 인입)

스캔 IP 대역과 자산대장 IP 대역을 일치시켜, 가져오기 후 부서/담당/연락처가
IP 매칭으로 자동 연결되도록 설계했다. 서비스는 taxonomy(105종)에 존재하는
이름만 사용해 위험등급(금지/상/중/하/정보)이 골고루 분포하도록 구성.
"""
import random
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# 서비스 팔레트 — (service, product, version_pool, [cpe], [(nse_id, output)])
# taxonomy 에 존재하는 서비스명만 사용(위험등급이 실제로 매겨지도록).
# --------------------------------------------------------------------------
SVC = {
    "ssh":        ("ssh", "OpenSSH", ["7.4", "8.2p1 Ubuntu 4ubuntu0.5", "8.9p1", "9.6p1"],
                   ["cpe:/a:openbsd:openssh"], []),
    "telnet":     ("telnet", "Linux telnetd", ["", ""], [],
                   [("banner", "Login: ")]),
    "ftp":        ("ftp", "vsftpd", ["2.0.8", "3.0.3", "3.0.5"], [],
                   [("ftp-anon", "Anonymous FTP login allowed (FTP code 230)")]),
    "http":       ("http", "nginx", ["1.18.0", "1.20.1", "1.24.0", "1.25.3"],
                   ["cpe:/a:igor_sysoev:nginx"],
                   [("http-title", "사내 포털"), ("http-server-header", "nginx")]),
    "https":      ("https", "Apache httpd", ["2.4.41", "2.4.52", "2.4.58"],
                   ["cpe:/a:apache:http_server"],
                   [("ssl-cert", "Subject: commonName=srv.example.local\nNot valid after: 2026-11-30")]),
    "rdp":        ("ms-wbt-server", "Microsoft Terminal Services", ["", ""], [],
                   [("rdp-ntlm-info", "Target_Name: CORP\nNetBIOS_Domain_Name: CORP")]),
    "smb":        ("microsoft-ds", "Microsoft Windows Server 2019 microsoft-ds", ["", ""],
                   ["cpe:/o:microsoft:windows_server_2019"],
                   [("smb-os-discovery", "OS: Windows Server 2019")]),
    "mysql":      ("mysql", "MySQL", ["5.7.38", "8.0.32", "8.0.35"],
                   ["cpe:/a:mysql:mysql"], []),
    "postgresql": ("postgresql", "PostgreSQL DB", ["12.14", "14.9", "15.4"], [], []),
    "redis":      ("redis", "Redis key-value store", ["6.2.6", "7.0.11", "7.2.3"], [], []),
    "mongodb":    ("mongodb", "MongoDB", ["4.4.18", "5.0.14", "6.0.4"], [], []),
    "elasticsearch": ("elasticsearch", "Elasticsearch REST API", ["7.17.9", "8.6.2"], [], []),
    "vnc":        ("vnc", "VNC (protocol 3.8)", ["", ""], [], []),
    "snmp":       ("snmp", "SNMPv1 server", ["", ""], [],
                   [("snmp-info", "community: public (read)")]),
    "smtp":       ("smtp", "Postfix smtpd", ["", ""], [],
                   [("smtp-commands", "srv.example.local, PIPELINING, SIZE 10240000")]),
    "imap":       ("imap", "Dovecot imapd", ["", ""], [], []),
    "dns":        ("domain", "ISC BIND", ["9.16.1", "9.18.12"], [], []),
    "ntp":        ("ntp", "NTP v4", ["", ""], [], []),
    "grafana":    ("grafana", "Grafana", ["9.3.6", "10.1.5"], [], []),
    "jenkins":    ("jenkins", "Jenkins", ["2.387", "2.414"], [], []),
    "git":        ("git", "Git smart HTTP", ["", ""], [], []),
    "printer":    ("printer", "HP LaserJet", ["", ""], [], []),
    "ipp":        ("ipp", "CUPS", ["2.3", "2.4"], [], []),
    "mqtt":       ("mqtt", "Mosquitto", ["1.6.15", "2.0.15"], [], []),
    "kafka":      ("kafka", "Apache Kafka", ["", ""], [], []),
    "ldap":       ("ldap", "OpenLDAP", ["2.4.57", "2.5.13"], [], []),
    "ajp13":      ("ajp13", "Apache Jserv", ["", ""], [], []),
    "memcached":  ("memcached", "Memcached", ["1.6.18"], [], []),
    "zookeeper":  ("zookeeper", "Apache ZooKeeper", ["3.7.1"], [], []),
}

PORT_OF = {
    "ssh": 22, "telnet": 23, "ftp": 21, "http": 80, "https": 443, "rdp": 3389,
    "smb": 445, "mysql": 3306, "postgresql": 5432, "redis": 6379, "mongodb": 27017,
    "elasticsearch": 9200, "vnc": 5900, "snmp": 161, "smtp": 25, "imap": 143,
    "dns": 53, "ntp": 123, "grafana": 3000, "jenkins": 8080, "git": 9418,
    "printer": 9100, "ipp": 631, "mqtt": 1883, "kafka": 9092, "ldap": 389,
    "ajp13": 8009, "memcached": 11211, "zookeeper": 2181,
}
UDP_SVCS = {"snmp", "ntp", "dns"}

DEPTS = ["정보보안팀", "인프라운영팀", "인사총무팀", "재무회계팀", "연구개발팀",
         "영업본부", "생산관리팀", "IT지원팀", "법무팀", "고객지원센터"]
OWNERS = ["김철수", "이영희", "박민준", "최지우", "정현우", "강서연", "윤도현",
          "임하늘", "한소율", "오세훈", "신유진", "배준호", "서예은", "문가람"]


def make_scan(name, subnet_prefix, host_defs, args_cmd, start_epoch):
    """host_defs: list of (last_octet, hostname, [svc_keys]). nmap -oX XML 생성."""
    root = ET.Element("nmaprun", scanner="nmap",
                      args=args_cmd, start=str(start_epoch),
                      startstr="Mon Jul 20 09:00:00 2026",
                      version="7.94SVN", xmloutputversion="1.05")
    all_tcp = sorted({PORT_OF[s] for _, _, svcs in host_defs for s in svcs if s not in UDP_SVCS})
    ET.SubElement(root, "scaninfo", type="syn", protocol="tcp",
                  numservices=str(len(all_tcp)),
                  services=",".join(str(p) for p in all_tcp))
    ET.SubElement(root, "verbose", level="0")
    ET.SubElement(root, "debugging", level="0")
    for last, hostname, svcs in host_defs:
        ip = f"{subnet_prefix}.{last}"
        h = ET.SubElement(root, "host", starttime=str(start_epoch),
                          endtime=str(start_epoch + 8))
        ET.SubElement(h, "status", state="up", reason="syn-ack", reason_ttl="64")
        ET.SubElement(h, "address", addr=ip, addrtype="ipv4")
        ET.SubElement(h, "address", addr="52:54:00:%02x:%02x:%02x" % (last, last % 7, last % 13),
                      addrtype="mac")
        hns = ET.SubElement(h, "hostnames")
        ET.SubElement(hns, "hostname", name=hostname, type="PTR")
        ports = ET.SubElement(h, "ports")
        for skey in svcs:
            svc_name, product, versions, cpes, scripts = SVC[skey]
            proto = "udp" if skey in UDP_SVCS else "tcp"
            portid = PORT_OF[skey]
            p = ET.SubElement(ports, "port", protocol=proto, portid=str(portid))
            ET.SubElement(p, "state", state="open", reason="syn-ack", reason_ttl="63")
            # 버전 선택은 (호스트옥텟, 포트) 기반 결정론적 — 전역 random 미사용(매 실행 동일 SHA 보장).
            version = versions[(last * 7 + portid) % len(versions)] if versions else ""
            svc = ET.SubElement(p, "service", name=svc_name, method="probed", conf="10")
            if product:
                svc.set("product", product)
            if version:
                svc.set("version", version)
            for c in cpes:
                cc = ET.SubElement(svc, "cpe")
                cc.text = c + (":" + version if version else "")
            for sid, out in scripts:
                ET.SubElement(p, "script", id=sid, output=out)
        ET.SubElement(h, "times", srtt="42000", rttvar="8000", to="120000")
    rs = ET.SubElement(root, "runstats")
    ET.SubElement(rs, "finished", time=str(start_epoch + 300),
                  timestr="Mon Jul 20 09:05:00 2026",
                  summary=f"Nmap done; {len(host_defs)} IP addresses scanned",
                  elapsed="300.00", exit="success")
    ET.SubElement(rs, "hosts", up=str(len(host_defs)), down="0", total=str(len(host_defs)))
    xml = minidom.parseString(ET.tostring(root, encoding="unicode")).toprettyxml(indent="  ")
    xml = "\n".join(l for l in xml.splitlines() if l.strip())
    doctype = ('<?xml version="1.0" encoding="UTF-8"?>\n'
               '<!DOCTYPE nmaprun>\n'
               '<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>\n')
    body = xml.split("\n", 1)[1]  # drop minidom's <?xml ...?>
    (HERE / name).write_text(doctype + body + "\n", encoding="utf-8")
    lines = (doctype + body).count("\n") + 1
    return ip, len(host_defs), lines


def gen_hosts(n, host_prefix, service_menu, seed):
    """n개 호스트 정의 생성. service_menu: [(svc_keys, weight)]."""
    rnd = random.Random(seed)
    out = []
    for i in range(1, n + 1):
        last = i + 9  # .10 부터
        menu = rnd.choices([m[0] for m in service_menu],
                           weights=[m[1] for m in service_menu])[0]
        # 일부 호스트는 서비스 2~4개 조합
        svcs = list(dict.fromkeys(menu))
        out.append((last, f"{host_prefix}-{i:03d}", svcs))
    return out


def make_ledger(name, subnet_prefix, n_rows, dept_pool, host_prefix, seed, note_tag):
    """CSV 자산대장 생성(300행 이상). 프론트 자산 가져오기가 인입."""
    rnd = random.Random(seed)
    # 한국어 헤더 — 프론트 자산 가져오기 위저드의 자동 매핑 별칭(부서/담당자/연락처/자산번호/호스트명)과 일치.
    header = ["IP", "호스트명", "부서", "담당자", "연락처",
              "자산번호", "운영체제", "설치위치", "도입일자", "비고"]
    lines = [",".join(header)]
    for i in range(1, n_rows + 1):
        last = i + 9
        ip = f"{subnet_prefix}.{last}"
        dept = rnd.choice(dept_pool)
        owner = rnd.choice(OWNERS)
        contact = f"010-{rnd.randint(1000,9999)}-{rnd.randint(1000,9999)}"
        asset_no = f"AST-{seed:02d}-{i:04d}"
        os_name = rnd.choice(["Windows Server 2019", "Windows 11", "Ubuntu 22.04",
                              "RHEL 8", "CentOS 7", "AIX 7.2", "Cisco IOS"])
        loc = rnd.choice(["본사 3층 전산실", "본사 IDC", "지점 서버랙", "DR센터", "클라우드 VPC"])
        acquired = f"20{rnd.randint(18,25):02d}-{rnd.randint(1,12):02d}-{rnd.randint(1,28):02d}"
        note = f"{note_tag} {host_prefix}-{i:03d}"
        row = [ip, f"{host_prefix}-{i:03d}", dept, owner, contact,
               asset_no, os_name, loc, acquired, note]
        lines.append(",".join(row))
    # UTF-8 BOM 포함 — Excel 저장본과 동일. SheetJS 가 한글을 올바로 디코드하도록.
    (HERE / name).write_text("\n".join(lines) + "\n", encoding="utf-8-sig")
    return n_rows, len(lines)


def main():
    results = []

    # ---- 5개 스캔 시나리오 (IP 대역별로 서비스 프로필 차등) ----
    # 1) HQ 데이터센터: 웹/DB/모니터링 서버 밀집
    hq = gen_hosts(40, "hq-srv", [
        (["ssh", "http", "mysql"], 3), (["ssh", "https", "postgresql"], 3),
        (["ssh", "http"], 2), (["ssh", "redis"], 2), (["ssh", "grafana", "http"], 1),
        (["ssh", "elasticsearch", "http"], 1), (["ssh", "smtp", "imap"], 1),
        (["ssh", "jenkins", "git"], 1), (["ssh", "mongodb"], 1), (["ssh", "ldap"], 1),
    ], seed=1)
    results.append(make_scan("scan_hq_datacenter.xml", "10.10.10", hq,
                             "nmap -sS -sV -sC -O -oX scan_hq_datacenter.xml 10.10.10.0/24",
                             1752998400))

    # 2) 지점망: 윈도우 엔드포인트(RDP/SMB) + 프린터
    branch = gen_hosts(45, "branch-pc", [
        (["smb", "rdp"], 4), (["smb"], 3), (["rdp"], 2),
        (["printer", "ipp"], 2), (["smb", "http"], 1), (["ssh"], 1),
    ], seed=2)
    results.append(make_scan("scan_branch_office.xml", "10.20.30", branch,
                             "nmap -sS -sV -O -oX scan_branch_office.xml 10.20.30.0/24",
                             1753084800))

    # 3) DMZ 공개서버: 외부 노출 웹/FTP/SSH (고위험 노출)
    dmz = gen_hosts(35, "dmz-pub", [
        (["https", "http", "ssh"], 4), (["http", "ftp"], 2),
        (["https", "ajp13"], 1), (["ssh", "https"], 2), (["ftp", "http"], 1),
        (["https", "http", "git"], 1),
    ], seed=3)
    results.append(make_scan("scan_dmz_public.xml", "203.0.113", dmz,
                             "nmap -sS -sV -sC -oX scan_dmz_public.xml 203.0.113.0/24",
                             1753171200))

    # 4) OT/산업망: 레거시 평문 프로토콜(telnet/ftp/snmp/vnc)
    ot = gen_hosts(38, "ot-node", [
        (["telnet", "snmp"], 4), (["telnet", "ftp"], 3), (["vnc"], 2),
        (["telnet", "http"], 2), (["snmp", "ntp"], 1), (["mqtt"], 1),
        (["telnet", "vnc", "ftp"], 1),
    ], seed=4)
    results.append(make_scan("scan_ot_network.xml", "192.168.50", ot,
                             "nmap -sS -sV -sU -oX scan_ot_network.xml 192.168.50.0/24",
                             1753257600))

    # 5) 클라우드 VPC: 컨테이너/데이터스토어(redis/mongo/elastic/kafka)
    cloud = gen_hosts(42, "vpc-node", [
        (["redis"], 3), (["mongodb"], 2), (["elasticsearch", "http"], 2),
        (["kafka", "zookeeper"], 1), (["memcached"], 1), (["http", "grafana"], 2),
        (["ssh", "http"], 2), (["postgresql"], 1), (["mqtt"], 1),
    ], seed=5)
    results.append(make_scan("scan_cloud_vpc.xml", "172.31.10", cloud,
                             "nmap -sS -sV -oX scan_cloud_vpc.xml 172.31.10.0/24",
                             1753344000))

    print("=== 스캔 결과 XML ===")
    for (name, _), (ip, hosts, lines) in zip(
            [("scan_hq_datacenter.xml", 0), ("scan_branch_office.xml", 0),
             ("scan_dmz_public.xml", 0), ("scan_ot_network.xml", 0),
             ("scan_cloud_vpc.xml", 0)], results):
        print(f"  {name:28s} hosts={hosts:3d}  lines={lines}")

    # ---- 5개 자산대장 (스캔 IP 대역과 일치 → IP 매칭 자동 연결) ----
    ledgers = [
        ("assets_hq.csv", "10.10.10", 320, ["정보보안팀", "인프라운영팀", "IT지원팀", "연구개발팀"], "hq-srv", 11, "HQ데이터센터"),
        ("assets_branch.csv", "10.20.30", 330, ["영업본부", "고객지원센터", "인사총무팀", "재무회계팀"], "branch-pc", 12, "지점PC"),
        ("assets_dmz.csv", "203.0.113", 305, ["정보보안팀", "인프라운영팀"], "dmz-pub", 13, "DMZ공개서버"),
        ("assets_ot.csv", "192.168.50", 310, ["생산관리팀", "인프라운영팀"], "ot-node", 14, "OT산업설비"),
        ("assets_cloud.csv", "172.31.10", 340, ["연구개발팀", "인프라운영팀", "IT지원팀"], "vpc-node", 15, "클라우드자산"),
    ]
    print("=== 자산대장 CSV ===")
    for fname, prefix, rows, depts, hp, seed, tag in ledgers:
        n, lc = make_ledger(fname, prefix, rows, depts, hp, seed, tag)
        print(f"  {fname:22s} rows={n:3d}  lines={lc}")


if __name__ == "__main__":
    main()
