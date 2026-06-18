"""Pydantic I/O 스키마 — 필요한 것만, 단계별로 추가."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


# ---- auth / user ----
class LoginIn(BaseModel):
    username: str
    password: str


class TokenOut(BaseModel):
    token: str
    role: str
    display_name: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: str
    display_name: str
    is_active: int


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    display_name: str = ""


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class PasswordReset(BaseModel):
    new_password: str


# ---- scan ----
class ScanRunIn(BaseModel):
    name: str = ""
    preset: str = "quick"          # 옵션 미지정 시 사용(하위호환)
    options: list[str] = []        # 스캔 옵션 키(화이트리스트) — 지정 시 우선
    ports: str = ""                # 포트 스펙(예: 22,80,443 또는 1-1024)
    nse: list[str] = []            # NSE 스크립트 키(화이트리스트) — 선택 시 --script 조립
    targets: list[str]
    batch_size: int = 256          # 청킹 배치당 호스트 수(중지/이어가기 단위)


class RawCommandIn(BaseModel):
    name: str = ""
    command: str          # 사용자가 직접 입력한 nmap 명령(출력 플래그는 서버가 -oA 로 강제 교체)


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    targets: str
    command: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    host_count: int
    port_count: int


class IngestSummary(BaseModel):
    scan_id: int
    counts: dict


# ---- audit ----
class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    actor_name: str
    action: str
    target: str
    detail: str
    ok: int
    created_at: datetime


# ---- finding ----
class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    finding_key: str
    host_ip: str
    hostname: str
    port: int
    proto: str
    state: str
    service: str
    product: str
    version: str
    banner: str
    cpe: str
    rtt: str
    identification: str
    category: str
    usage: str
    risk_level: str
    remarks: str
    compliance_json: list | None
    status: str
    reopened: int
    owner_user_id: int | None
    deadline: datetime | None
    dept: str
    contact: str
    owner: str
    manual_note: str
    first_seen: datetime
    last_seen: datetime


class FindingPatch(BaseModel):
    status: str | None = None
    owner_user_id: int | None = None
    deadline: datetime | None = None
    dept: str | None = None
    manual_note: str | None = None


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    type: str
    detail: str
    actor_user_id: int | None
    scan_id: int | None
    created_at: datetime


class EventFeedItem(BaseModel):
    """전역 이력 피드 항목 — FindingEvent + Finding(host/port/service) 조인."""
    id: int
    finding_id: int
    type: str
    detail: str
    host_ip: str
    port: int
    service: str
    actor_user_id: int | None
    scan_id: int | None
    created_at: datetime


class EventFeed(BaseModel):
    total: int
    items: list[EventFeedItem]


# ---- risk rule ----
class RuleIn(BaseModel):
    kind: str  # banned_service / port_rule
    service: str = ""
    port: int | None = None
    risk_level: str = "high"
    note: str = ""


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    kind: str
    service: str
    port: int | None
    risk_level: str
    note: str
    created_at: datetime
    match_count: int = 0


# ---- rescan command ----
class RescanIn(BaseModel):
    finding_ids: list[int]
    preset_flags: str = "-sV -Pn"  # 명령 미리보기용 기본 플래그


class RescanOut(BaseModel):
    command: str
    hosts: list[str]
    ports: list[int]
    finding_count: int


class RescanRunIn(BaseModel):
    finding_ids: list[int]
    options: list[str] = []
    ports: str = ""  # 빈값이면 선택 발견의 포트 자동


class RescanRunOut(BaseModel):
    scan_id: int
    command: str
    counts: dict
    hosts: list[str]
    ports: list[int]


# ---- asset ----
class AssetIn(BaseModel):
    ip: str
    hostname: str = ""
    dept: str = ""
    owner: str = ""
    contact: str = ""
    asset_no: str = ""
    note: str = ""
    extra: dict = {}


class AssetOut(AssetIn):
    model_config = ConfigDict(from_attributes=True)
    id: int


# ---- notification ----
class NotifyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    dept: str
    body: str
    channel: str
    sent_at: datetime


class NotifyPreview(BaseModel):
    dept: str
    finding_count: int
    body: str


class NotifySend(BaseModel):
    """통보 기록 — 프론트가 템플릿으로 렌더한 문구/대상을 보낼 수 있음(없으면 서버 기본)."""
    dept: str = ""
    body: str = ""
    finding_ids: list[int] = []
