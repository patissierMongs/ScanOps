"""ORM 모델 — finding 라이프사이클의 단일 진실원천.

안정 finding 키 = ``host_ip|port|proto`` : 서비스/버전이 바뀌어도 같은 포트면
같은 발견으로 본다. 이 키가 상태·담당·마감·이력을 스캔 간에 이어주는 등뼈.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---- 역할/상태 상수 (자유 문자열이지만 의미 고정) ----
ROLES = ("admin", "auditor", "viewer")
FINDING_STATUSES = ("미조치", "처리중", "정상처리", "재발")
# banned(금지) = 조직이 명시 금지한 서비스. 상(high)/중(medium)/하(low)/정보(info)는 KISA·NIS 기준.
RISK_LEVELS = ("banned", "high", "medium", "low", "info")
RISK_LABELS_KO = {"banned": "금지", "high": "상", "medium": "중", "low": "하", "info": "정보"}
IDENTIFICATIONS = ("확인", "추측", "tcpwrapped", "미확인")


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    display_name: Mapped[str] = mapped_column(String(64), default="")
    is_active: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Asset(Base):
    """자산대장 — finding 의 dept/owner 자동 매칭 소스."""
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str] = mapped_column(String(128), default="")
    dept: Mapped[str] = mapped_column(String(128), default="")
    owner: Mapped[str] = mapped_column(String(128), default="")
    contact: Mapped[str] = mapped_column(String(128), default="")
    asset_no: Mapped[str] = mapped_column(String(64), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    # 조직별 임의 컬럼(종류/제조사/OS/사번 등) — 고정 스키마를 늘리지 않고 보존.
    extra: Mapped[dict | None] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class ScanRun(Base):
    __tablename__ = "scan_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    targets: Mapped[str] = mapped_column(Text, default="")
    command: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="running")  # running/done/failed/canceled
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    raw_xml_path: Mapped[str] = mapped_column(Text, default="")
    log_path: Mapped[str] = mapped_column(Text, default="")
    host_count: Mapped[int] = mapped_column(Integer, default=0)
    port_count: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("finding_key", name="uq_finding_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_key: Mapped[str] = mapped_column(String(96), index=True)  # host_ip|port|proto

    # --- 관측 데이터(스캔이 갱신) ---
    host_ip: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str] = mapped_column(String(128), default="")
    port: Mapped[int] = mapped_column(Integer)
    proto: Mapped[str] = mapped_column(String(8))
    state: Mapped[str] = mapped_column(String(16), default="open")  # open/closed/filtered
    service: Mapped[str] = mapped_column(String(64), default="")
    product: Mapped[str] = mapped_column(String(128), default="")
    version: Mapped[str] = mapped_column(String(128), default="")
    banner: Mapped[str] = mapped_column(Text, default="")
    cpe: Mapped[str] = mapped_column(Text, default="")
    rtt: Mapped[str] = mapped_column(String(32), default="")
    identification: Mapped[str] = mapped_column(String(16), default="미확인")
    nse_json: Mapped[list | None] = mapped_column(JSON, default=list)  # [{"id":..,"output":..}]

    # --- 분류/근거(taxonomy + 컴플라이언스가 채움) ---
    category: Mapped[str] = mapped_column(String(64), default="")
    usage: Mapped[str] = mapped_column(String(64), default="")
    risk_level: Mapped[str] = mapped_column(String(16), default="info")
    remarks: Mapped[str] = mapped_column(Text, default="")
    compliance_json: Mapped[list | None] = mapped_column(JSON, default=list)  # [{"std":"KISA","ref":..}]

    # --- 시간적 정체성 ---
    first_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id"), nullable=True)
    last_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id"), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)

    # --- 운영 상태(사람이 갱신, 스캔 간 영속) ---
    status: Mapped[str] = mapped_column(String(16), default="미조치", index=True)
    owner_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    deadline: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    dept: Mapped[str] = mapped_column(String(128), default="")
    contact: Mapped[str] = mapped_column(String(128), default="")  # 자산대장 IP 매칭으로 채움
    owner: Mapped[str] = mapped_column(String(128), default="")    # 자산대장 담당자명(IP 매칭)
    manual_note: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    events: Mapped[list["FindingEvent"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingEvent.created_at"
    )


class FindingEvent(Base):
    """이력 타임라인 + 감사 추적 (누가·언제·무엇을)."""
    __tablename__ = "finding_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id"), nullable=True)
    # NEW_OPEN/CLOSED/REOPENED/SERVICE_CHANGED/VERSION_CHANGED/STATUS_CHANGE/ASSIGN/DEADLINE/NOTE/EXCEPTION
    type: Mapped[str] = mapped_column(String(24), index=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    finding: Mapped[Finding] = relationship(back_populates="events")


class RiskRule(Base):
    """taxonomy 위에 얹는 조직 커스텀 위험 규칙."""
    __tablename__ = "risk_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # banned_service / port_rule
    service: Mapped[str] = mapped_column(String(64), default="")
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(16), default="high")
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Category(Base):
    """포팅한 서비스 taxonomy (시드). 서비스명 → 분류/용도/위험/근거."""
    __tablename__ = "categories"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_name: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # lower
    category: Mapped[str] = mapped_column(String(64), default="")
    usage: Mapped[str] = mapped_column(String(64), default="")
    risk_level: Mapped[str] = mapped_column(String(16), default="info")
    encryption: Mapped[str] = mapped_column(String(64), default="")
    auth: Mapped[str] = mapped_column(String(64), default="")
    exposure: Mapped[str] = mapped_column(String(64), default="")
    compliance_json: Mapped[list | None] = mapped_column(JSON, default=list)
    desc: Mapped[str] = mapped_column(Text, default="")


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    dept: Mapped[str] = mapped_column(String(128), default="")
    finding_ids_json: Mapped[list | None] = mapped_column(JSON, default=list)
    body: Mapped[str] = mapped_column(Text, default="")
    channel: Mapped[str] = mapped_column(String(16), default="file")  # clipboard/file/log
    sent_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    sent_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
