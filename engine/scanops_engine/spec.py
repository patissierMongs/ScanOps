"""Job spec — 엔진의 입력 계약. JSON dict ↔ 검증된 설정 객체.

엔진이 nmap argv 를 이 spec 으로 조립하므로, 임의 플래그 주입을 막기 위해
타겟/포트/타이밍/NSE 를 화이트리스트 패턴으로 검증한다(ScanOps 가 보내든, CLI 든).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field

# argv 옵션 주입을 막는 타겟 계약: 허용 문자여도 '-' 로 시작할 수 없다.
_TARGET_RE = re.compile(r"^(?!-)[A-Za-z0-9_.:/\-]+$")
_PORTS_RE = re.compile(r"^[0-9TUtu:,\-\s]*$")
# 마지막 옥텟 범위(10.0.0.1-10) — 제외 대상이 타겟과 같은 문법을 받도록.
_EXCLUDE_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$")
_PORT_BODY_RE = re.compile(r"^(\d{1,5}-\d{1,5}|\d{1,5}-|-\d{1,5}|\d{1,5})$")
_NSE_RE = re.compile(r"^[A-Za-z0-9._\-]+$")
_TIMINGS = {"-T0", "-T1", "-T2", "-T3", "-T4", "-T5"}

# standalone auto 스캔과 공유하는 기본 발견/동시성 정책.
DISCOVERY_PS = "-PS21,22,23,25,80,110,135,139,143,443,445,993,1433,1521,3306,3389,5432,8080"
DISCOVERY_PA = "-PA80,443,3389"
DEFAULT_MIN_HOSTGROUP = 64
DEFAULT_MAX_PARALLELISM = 100
# NSE 스크립트 인스턴스 하나의 상한. --host-timeout 과 **성질이 다르다** - nmap 문서:
# "Any script instance which exceeds that time will be terminated and no output will be
# shown." 즉 초과한 스크립트만 죽고 포트 표는 그대로 남는다(실측 A/B 로도 확인됐다:
# 상한이 걸려도 rc=0 · 완결 XML · port=open, 스크립트 출력만 생략).
# 그래서 호스트 상한을 뺀 것과 달리 이쪽은 유지한다 - 느린 NSE 꼬리를 관측 손실 없이 자른다.
DEFAULT_TCP_NSE_SCRIPT_TIMEOUT = "2m"
DEFAULT_UDP_NSE_SCRIPT_TIMEOUT = "3m"
# TCP 프로브 재전송 상한.
DEFAULT_MAX_RETRIES = 2
# UDP 재전송 상한. 닫힌 UDP 포트의 ICMP port-unreachable 을 대상 **OS 스택 자체가**
# 율제한한다(흔히 초당 1회). TCP 와 같은 값을 쓰면 그 백오프를 못 기다려 실제로 닫힌 포트가
# open|filtered 로 남는다 - '닫혔다'가 아니라 '못 봤다'가 쌓인다.
DEFAULT_UDP_MAX_RETRIES = 4
# nmap 프로세스 하나가 붙잡을 수 있는 최대 시간(초). 0 = 끔(기본).
#
# --host-timeout 을 되살리는 것이 아니다. 상한에 걸린 호스트의 포트 표를 통째로 버리면서
# 실행은 성공으로 끝내는 그 동작이 문제였다(그 조합이 '살아 있는데 열린 포트가 없다'로
# 읽혀 기존 발견을 전부 닫는다). 워치독은 밖에서 프로세스를 끝내므로 그때까지 -oA 로
# 쓰인 XML 은 남고, 실행은 비정상 종료라 닫힘 권한을 얻지 못한다.
#
# 기본이 0 인 이유: 정상적인 전 포트 스캔이 몇 시간 걸리는 망이 실제로 있고, 여기에
# 섣부른 값을 박으면 '느린 망'을 '실패'로 바꾼다. 켤 때는 그 망에서 관측한 값보다
# 넉넉히 잡는다.
_MAX_WATCHDOG_SECONDS = 24 * 60 * 60
# 재전송 상한의 상한. 손상됐거나 미래 버전이 쓴 spec 의 터무니없는 값이 그대로 argv 에
# 실려 실행이 끝나지 않는 것을 막는다.
_MAX_RETRIES_CAP = 10
# 식별 단계 동시 실행 상한. 프로세스가 늘면 스캔 서버의 소켓·CPU 를 그만큼 쓰므로,
# '느려서 못 쓰는' 문제를 '서버가 죽는' 문제로 바꾸지 않도록 위쪽을 막아 둔다.
_MAX_SERVICE_WORKERS = 32

# nmapParser 기본 UDP 포트 집합(원본 one-liner 계승)
DEFAULT_UDP_PORTS = ("7,53,67,68,69,88,111,123,135,137,138,139,161,162,389,400,500,"
                     "514,520,623,1900,2049,4500,5060,5353,5355,11211")
# 서비스 probe 기본 NSE — 타겟형(portrule 안 맞으면 자동 skip). 원본의 20종 전수 대신 핵심만.
# DB 찌르는 스크립트(redis-info·oracle-tns-version·ms-sql-info 등)는 장애 위험으로 기본 제외.
# spec 이 stages.service.nse 를 지정하지 않았을 때의 **폴백**이다. 운영 경로(웹)는
# engine_runner.build_job_spec 이 scan_options.NSE_DEFAULT_KEYS 를 항상 채워 넣으므로 여기까지
# 오지 않는다. 그래도 목록이 달랐던 탓에 "단계 스캔은 이 스크립트를 안 돌린다"는 잘못된 결론이
# 실제로 나왔다 - 안 쓰이는 기본값이라도 다르면 읽는 사람을 속인다.
#
# 그래서 웹·단독과 **같은 집합**으로 맞춘다. 세 곳이 어긋나지 않는지는 백엔드 계약 테스트가
# 검사한다(tests/test_layer_contracts.py). 엔진은 백엔드를 import 하지 않는 독립 패키지라
# 파생시킬 수 없어서, 사본을 두되 드리프트를 테스트로 막는 방식이다.
#
# 웹 경로는 선택한 목록을 proto 에 따라 nse/udp_nse 로 나눠서 전달한다. 이 목록은 구형 spec 이
# nse 만 보낼 때의 TCP 폴백이며, UDP 는 명시적인 udp_nse 가 있을 때만 스크립트를 실행한다.
DEFAULT_NSE = ["banner", "dns-nsid", "fingerprint-strings", "ftp-anon", "ftp-syst",
               "http-headers", "http-server-header", "http-title", "rdp-ntlm-info",
               "rpcinfo", "sip-methods", "smb-os-discovery", "smb-protocols",
               "ssh-hostkey", "ssl-cert", "telnet-encryption", "tls-alpn", "vnc-info"]


@dataclass
class DiscoveryStage:
    enabled: bool = True
    mode: str = "sn"          # sn=핑 스윕 / pn=발견 생략(타겟 전체 live 취급)
    timing: str = "-T4"
    max_retries: int = DEFAULT_MAX_RETRIES


@dataclass
class TcpStage:
    enabled: bool = True
    scan_type: str = "syn"    # syn=-sS / connect=-sT
    ports: str = "1-65535"
    timing: str = "-T4"
    min_rate: int = 0         # 0=강제 하한 없음; 명시된 경우에만 --min-rate 적용
    max_retries: int = DEFAULT_MAX_RETRIES


@dataclass
class UdpStage:
    enabled: bool = False
    ports: str = DEFAULT_UDP_PORTS
    timing: str = "-T4"
    # TCP 와 **별개 값**이다. UDP 는 무응답을 open|filtered 로 보고하므로, 재전송을 아끼면
    # 그만큼 '못 본 것'이 '열려 있을지도 모르는 것'으로 쌓인다.
    max_retries: int = DEFAULT_UDP_MAX_RETRIES


@dataclass
class ServiceStage:
    enabled: bool = True
    timing: str = "-T4"
    version_all: bool = True
    version_light: bool = False
    nse: list = field(default_factory=lambda: list(DEFAULT_NSE))
    # 열린 UDP 포트 식별에만 붙일 UDP/both 스크립트. 구형 spec 은 이 필드가 없으므로 빈 목록이
    # 안전한 하위호환이고, 웹 build_job_spec 은 사용자가 고른 목록을 proto 별로 나눠 채운다.
    udp_nse: list = field(default_factory=list)
    max_retries: int = DEFAULT_MAX_RETRIES
    # UDP probe 전용 재전송 상한(TCP 와 별개). sweep 과 같은 이유로 더 넉넉하다.
    udp_max_retries: int = DEFAULT_UDP_MAX_RETRIES
    confirm: bool = False      # 2-pass — 1차에 안 잡히면 retries↑ 재확인(재스캔용)
    # UDP의 정확 host×port 묶음과 공통 실행 실패 후 호스트별 격리를 동시에 돌릴 상한.
    # 정상 TCP 전체 스캔은 배치 합집합 한 프로세스에서 Nmap 자체 호스트 병렬화를 사용한다.
    # 재스캔(닫힘 권한이 걸린 경로)은 1 로 강제해 실패 시 즉시 중단하는 의미를 지킨다.
    workers: int = 16


_STAGE_CLASSES = {"discovery": DiscoveryStage, "tcp": TcpStage, "udp": UdpStage, "service": ServiceStage}


def _validate_target(value, label: str) -> None:
    if not isinstance(value, str) or not _TARGET_RE.fullmatch(value):
        raise ValueError(f"허용되지 않는 {label}: {value!r}")
    if ":" in value:
        raise ValueError(f"IPv6 {label}은 아직 지원하지 않습니다: {value!r}")


def _validate_exclude(value) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"제외 대상은 IPv4 주소/CIDR이어야 합니다: {value!r}")
    # 마지막 옥텟 범위(10.0.0.1-10) — 타겟과 같은 문법을 제외에서도 받는다(nmap 이 그대로 해석).
    if match := _EXCLUDE_RANGE_RE.fullmatch(value):
        base, lo, hi = match.group(1), int(match.group(2)), int(match.group(3))
        if any(int(o) > 255 for o in base.split(".")) or lo > 255 or hi > 255 or lo > hi:
            raise ValueError(f"잘못된 제외 IP 범위입니다: {value!r}. 예: 10.0.0.1-10")
        return
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"잘못된 제외 대상 IPv4/CIDR입니다: {value!r}") from exc
    if network.version != 4:
        raise ValueError(f"IPv6 제외 대상은 아직 지원하지 않습니다: {value!r}")


def _validate_ports(value: str, label: str) -> None:
    if not isinstance(value, str) or not _PORTS_RE.fullmatch(value):
        raise ValueError(f"허용되지 않는 {label} 포트 스펙: {value!r}")
    if not value:
        return
    for segment in value.replace(" ", "").split(","):
        if not segment:
            raise ValueError(f"{label} 포트 목록에 빈 항목이 있습니다.")
        body = segment
        if ":" in segment:
            prefix, body = segment.split(":", 1)
            if prefix.upper() not in ("T", "U"):
                raise ValueError(f"알 수 없는 프로토콜 접두사: {segment!r}")
        if not body or not _PORT_BODY_RE.fullmatch(body):
            raise ValueError(f"잘못된 {label} 포트/범위: {segment!r}")
        numbers = [int(item) for item in re.findall(r"\d+", body)]
        if any(not 1 <= item <= 65535 for item in numbers):
            raise ValueError(f"{label} 포트는 1-65535 범위여야 합니다: {segment!r}")
        if "-" in body and len(numbers) == 2 and numbers[0] > numbers[1]:
            raise ValueError(f"{label} 포트 범위가 거꾸로입니다: {segment!r}")


def _build(cls, d):
    """알 수 없는 키는 무시하고 알려진 필드만으로 stage 생성(상위호환)."""
    fields = cls.__dataclass_fields__
    return cls(**{k: v for k, v in (d or {}).items() if k in fields})


@dataclass
class JobSpec:
    job_id: str = "job"
    # nmap 프로세스당 상한(초). 0 = 끔. 단계가 아니라 실행 단위라 job 수준에 둔다.
    watchdog_seconds: int = 0
    targets: list = field(default_factory=list)
    exclude: list = field(default_factory=list)
    # 모든 단계에서 뺄 포트(nmap --exclude-ports). 프린터처럼 스캔에 반응해 문제를
    # 일으키는 포트를 제외하는 안전 컨트롤이라 한 단계라도 새면 의미가 없다.
    exclude_ports: str = ""
    out_dir: str = "."
    batch_size: int = 256
    sudo: str = "auto"        # auto(POSIX 비root면 sudo) / always / never
    discovery: DiscoveryStage = field(default_factory=DiscoveryStage)
    tcp: TcpStage = field(default_factory=TcpStage)
    udp: UdpStage = field(default_factory=UdpStage)
    service: ServiceStage = field(default_factory=ServiceStage)
    # 타겟 재스캔: 발견·찾기 생략하고 지정 포트로 바로 서비스 probe. {ip: [ports]}
    targets_ports: dict | None = None
    # 발견(IP:포트)별 개별 재스캔: 각 항목 1개 nmap 명령(그 ip·그 포트만). [{ip, port, proto}]
    rescan_units: list | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "JobSpec":
        d = dict(d or {})
        spec = cls(
            job_id=d.get("job_id", "job"),
            targets=list(d.get("targets", [])),
            exclude=list(d.get("exclude", [])),
            exclude_ports=str(d.get("exclude_ports", "") or ""),
            out_dir=d.get("out_dir", "."),
            batch_size=int(d.get("batch_size", 256)),
            sudo=d.get("sudo", "auto"),
            watchdog_seconds=d.get("watchdog_seconds", 0),
            targets_ports=d.get("targets_ports"),
            rescan_units=d.get("rescan_units"),
        )
        for name, st in (d.get("stages") or {}).items():
            if name in _STAGE_CLASSES:
                setattr(spec, name, _build(_STAGE_CLASSES[name], st))
        return spec

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id, "targets": self.targets, "exclude": self.exclude,
            "exclude_ports": self.exclude_ports,
            "out_dir": self.out_dir, "batch_size": self.batch_size, "sudo": self.sudo,
            "watchdog_seconds": self.watchdog_seconds,
            "targets_ports": self.targets_ports,
            "rescan_units": self.rescan_units,
            "stages": {
                "discovery": asdict(self.discovery), "tcp": asdict(self.tcp),
                "udp": asdict(self.udp), "service": asdict(self.service),
            },
        }

    def validate(self) -> "JobSpec":
        for t in self.targets:
            _validate_target(t, "타겟 형식")
        for t in self.exclude:
            _validate_exclude(t)
        for label, p in (("tcp", self.tcp.ports), ("udp", self.udp.ports)):
            _validate_ports(p, label)
        if self.exclude_ports.strip():
            _validate_ports(self.exclude_ports, "제외 포트")
        if self.tcp.enabled and not self.tcp.ports.strip():
            raise ValueError("TCP 단계가 활성화되었지만 포트가 비어 있습니다.")
        if self.udp.enabled and not self.udp.ports.strip():
            raise ValueError("UDP 단계가 활성화되었지만 포트가 비어 있습니다.")
        if self.tcp.scan_type not in ("syn", "connect"):
            raise ValueError(f"tcp.scan_type 은 syn/connect: {self.tcp.scan_type!r}")
        for label, tm in (("discovery", self.discovery.timing),
                          ("tcp", self.tcp.timing), ("udp", self.udp.timing),
                          ("service", self.service.timing)):
            if tm not in _TIMINGS:
                raise ValueError(f"허용되지 않는 {label} 타이밍: {tm!r}")
        # 상한은 단계마다 별개 값이다. 여기서 정규화까지 해 두면 pipeline 은 문자열이
        # 비었는지만 보면 된다.
        for label, stage, field_name in (
                ("discovery", self.discovery, "max_retries"),
                ("tcp", self.tcp, "max_retries"),
                ("udp", self.udp, "max_retries"),
                ("service", self.service, "max_retries"),
                ("service", self.service, "udp_max_retries")):
            value = getattr(stage, field_name)
            try:
                value = int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{label}.{field_name} 는 정수여야 합니다: {value!r}") from exc
            if not 0 <= value <= _MAX_RETRIES_CAP:
                raise ValueError(
                    f"{label}.{field_name} 는 0-{_MAX_RETRIES_CAP} 여야 합니다: {value}")
            setattr(stage, field_name, value)
        try:
            self.service.workers = int(self.service.workers)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"service.workers 는 정수여야 합니다: {self.service.workers!r}") from exc
        if not 1 <= self.service.workers <= _MAX_SERVICE_WORKERS:
            raise ValueError(
                f"service.workers 는 1-{_MAX_SERVICE_WORKERS} 여야 합니다: {self.service.workers}")
        for label, scripts in (("service.nse", self.service.nse),
                               ("service.udp_nse", self.service.udp_nse)):
            if not isinstance(scripts, list):
                raise ValueError(f"{label} 는 스크립트명 배열이어야 합니다: {scripts!r}")
            for n in scripts:
                if not isinstance(n, str) or not _NSE_RE.fullmatch(n):
                    raise ValueError(f"허용되지 않는 NSE 스크립트명: {n!r}")
        try:
            self.watchdog_seconds = int(self.watchdog_seconds or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"watchdog_seconds 는 정수여야 합니다: {self.watchdog_seconds!r}") from exc
        if not 0 <= self.watchdog_seconds <= _MAX_WATCHDOG_SECONDS:
            raise ValueError(
                f"watchdog_seconds 는 0-{_MAX_WATCHDOG_SECONDS} 여야 합니다: "
                f"{self.watchdog_seconds}")
        if self.sudo not in ("auto", "always", "never"):
            raise ValueError(f"sudo 는 auto/always/never: {self.sudo!r}")
        if self.discovery.mode not in ("sn", "pn"):
            raise ValueError(f"discovery.mode 는 sn/pn: {self.discovery.mode!r}")
        for ip in (self.targets_ports or {}):
            _validate_target(ip, "재스캔 타겟")
        for u in (self.rescan_units or []):
            try:
                _validate_target(u.get("ip", ""), "재스캔 단위 IP")
            except ValueError as exc:
                raise ValueError(f"{exc} ({u!r})") from exc
            if not (1 <= int(u.get("port", 0)) <= 65535):
                raise ValueError(f"허용되지 않는 재스캔 단위 포트: {u!r}")
            if u.get("proto", "tcp") not in ("tcp", "udp"):
                raise ValueError(f"재스캔 단위 proto 는 tcp/udp: {u!r}")
        return self
