"""Job spec — 엔진의 입력 계약. JSON dict ↔ 검증된 설정 객체.

엔진이 nmap argv 를 이 spec 으로 조립하므로, 임의 플래그 주입을 막기 위해
타겟/포트/타이밍/NSE 를 화이트리스트 패턴으로 검증한다(ScanOps 가 보내든, CLI 든).
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

_TARGET_RE = re.compile(r"^[A-Za-z0-9_.:/\-]+$")
_PORTS_RE = re.compile(r"^[0-9TUtu:,\-\s]*$")
_NSE_RE = re.compile(r"^[A-Za-z0-9._\-]+$")
_TIMINGS = {"-T0", "-T1", "-T2", "-T3", "-T4", "-T5"}

# nmapParser 기본 UDP 포트 집합(원본 one-liner 계승)
DEFAULT_UDP_PORTS = ("7,53,67,68,69,88,123,135,137,138,139,161,162,389,400,500,"
                     "514,520,623,1900,2049,4500,5060,5353,5355,11211")
# 서비스 probe 기본 NSE — 타겟형(portrule 안 맞으면 자동 skip). 원본의 20종 전수 대신 핵심만.
DEFAULT_NSE = ["banner", "http-headers", "http-title", "http-server-header",
               "ssl-cert", "ssh-hostkey", "ftp-anon", "redis-info",
               "smb-os-discovery", "snmp-info"]


@dataclass
class DiscoveryStage:
    enabled: bool = True
    mode: str = "sn"          # sn=핑 스윕 / pn=발견 생략(타겟 전체 live 취급)


@dataclass
class TcpStage:
    enabled: bool = True
    ports: str = "1-65535"
    timing: str = "-T4"
    min_rate: int = 1000      # 찾기: 빠르고 느슨
    max_retries: int = 2


@dataclass
class UdpStage:
    enabled: bool = False
    ports: str = DEFAULT_UDP_PORTS
    timing: str = "-T3"


@dataclass
class ServiceStage:
    enabled: bool = True
    version_all: bool = False
    version_light: bool = False
    nse: list = field(default_factory=lambda: list(DEFAULT_NSE))
    max_retries: int = 4      # 확인: 좁혀서 정밀
    confirm: bool = False      # 2-pass — 1차에 안 잡히면 retries↑ 재확인(재스캔용)


_STAGE_CLASSES = {"discovery": DiscoveryStage, "tcp": TcpStage, "udp": UdpStage, "service": ServiceStage}


def _build(cls, d):
    """알 수 없는 키는 무시하고 알려진 필드만으로 stage 생성(상위호환)."""
    fields = cls.__dataclass_fields__
    return cls(**{k: v for k, v in (d or {}).items() if k in fields})


@dataclass
class JobSpec:
    job_id: str = "job"
    targets: list = field(default_factory=list)
    exclude: list = field(default_factory=list)
    out_dir: str = "."
    batch_size: int = 256
    sudo: str = "auto"        # auto(POSIX 비root면 sudo) / always / never
    discovery: DiscoveryStage = field(default_factory=DiscoveryStage)
    tcp: TcpStage = field(default_factory=TcpStage)
    udp: UdpStage = field(default_factory=UdpStage)
    service: ServiceStage = field(default_factory=ServiceStage)
    # 타겟 재스캔: 발견·찾기 생략하고 지정 포트로 바로 서비스 probe. {ip: [ports]}
    targets_ports: dict | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "JobSpec":
        d = dict(d or {})
        spec = cls(
            job_id=d.get("job_id", "job"),
            targets=list(d.get("targets", [])),
            exclude=list(d.get("exclude", [])),
            out_dir=d.get("out_dir", "."),
            batch_size=int(d.get("batch_size", 256)),
            sudo=d.get("sudo", "auto"),
            targets_ports=d.get("targets_ports"),
        )
        for name, st in (d.get("stages") or {}).items():
            if name in _STAGE_CLASSES:
                setattr(spec, name, _build(_STAGE_CLASSES[name], st))
        return spec

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id, "targets": self.targets, "exclude": self.exclude,
            "out_dir": self.out_dir, "batch_size": self.batch_size, "sudo": self.sudo,
            "targets_ports": self.targets_ports,
            "stages": {
                "discovery": asdict(self.discovery), "tcp": asdict(self.tcp),
                "udp": asdict(self.udp), "service": asdict(self.service),
            },
        }

    def validate(self) -> "JobSpec":
        for t in self.targets + self.exclude:
            if not _TARGET_RE.match(t):
                raise ValueError(f"허용되지 않는 타겟 형식: {t!r}")
        for label, p in (("tcp", self.tcp.ports), ("udp", self.udp.ports)):
            if p and not _PORTS_RE.match(p):
                raise ValueError(f"허용되지 않는 {label} 포트 스펙: {p!r}")
        for label, tm in (("tcp", self.tcp.timing), ("udp", self.udp.timing)):
            if tm not in _TIMINGS:
                raise ValueError(f"허용되지 않는 {label} 타이밍: {tm!r}")
        for n in self.service.nse:
            if not _NSE_RE.match(n):
                raise ValueError(f"허용되지 않는 NSE 스크립트명: {n!r}")
        if self.sudo not in ("auto", "always", "never"):
            raise ValueError(f"sudo 는 auto/always/never: {self.sudo!r}")
        if self.discovery.mode not in ("sn", "pn"):
            raise ValueError(f"discovery.mode 는 sn/pn: {self.discovery.mode!r}")
        for ip in (self.targets_ports or {}):
            if not _TARGET_RE.match(ip):
                raise ValueError(f"허용되지 않는 재스캔 타겟: {ip!r}")
        return self
