"""ORM 모델 — finding 라이프사이클의 단일 진실원천.

안정 finding 키 = ``host_ip|port|proto`` : 서비스/버전이 바뀌어도 같은 포트면
같은 발견으로 본다. 이 키가 상태·담당·마감·이력을 스캔 간에 이어주는 등뼈.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Index,
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
# 재발은 더 이상 별도 상태가 아니다 — 재발한 발견은 미조치로 되돌리고 reopened 플래그(태그)로만 표시.
FINDING_STATUSES = ("미조치", "처리중", "정상처리")
# banned(금지) = 조직이 명시 금지한 서비스. 상(high)/중(medium)/하(low)/정보(info)는 KISA·NIS 기준.
RISK_LEVELS = ("banned", "high", "medium", "low", "info")
RISK_LABELS_KO = {"banned": "금지", "high": "상", "medium": "중", "low": "하", "info": "정보"}
IDENTIFICATIONS = ("확인", "추측", "tcpwrapped", "미확인")
ACTIVE_FINDING_STATES = ("open", "open|filtered")


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    display_name: Mapped[str] = mapped_column(String(64), default="")
    is_active: Mapped[int] = mapped_column(Integer, default=1)
    # Incremented on every password change/reset so already issued tokens become invalid.
    auth_version: Mapped[int] = mapped_column(Integer, default=0)
    # 남이 정해 준 비밀번호를 쓰고 있는 계정. 최초 관리자(INITIAL_ADMIN.txt)와 admin 이 만들거나
    # 재설정한 계정이 여기 해당한다. 그 비밀번호는 파일이나 사람의 기억에 남아 있으므로,
    # 본인이 바꾸기 전까지는 로그인해도 아무것도 하지 못하게 막는다.
    must_change_password: Mapped[int] = mapped_column(Integer, default=0)
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
    # running/done/failed/canceling/canceled/interrupted
    # interrupted = 서버 재시작 등으로 워커가 사라져 고아가 된 실행(자동 복구 안 함, 수동 이어하기 가능)
    status: Mapped[str] = mapped_column(String(16), default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    raw_xml_path: Mapped[str] = mapped_column(Text, default="")
    log_path: Mapped[str] = mapped_column(Text, default="")
    host_count: Mapped[int] = mapped_column(Integer, default=0)
    port_count: Mapped[int] = mapped_column(Integer, default=0)
    # 대역을 몇 덩어리로 나눠 돌렸는가. 끝난 뒤에도 '이 스캔이 어떻게 돌았는지'를 말할 수
    # 있어야 한다 - 실행 중에만 보이면 이력을 나중에 읽는 사람에게는 없는 정보다.
    batch_total: Mapped[int] = mapped_column(Integer, default=0)
    batch_size: Mapped[int] = mapped_column(Integer, default=0)
    # 단계분리 엔진 스캔의 단계별 요약(상태/소요/카운트/에러) — 진행 타임라인·이력용. 청킹 스캔은 빈 값.
    stages_json: Mapped[list | None] = mapped_column(JSON, default=list)
    # 사용자에게 노출 가능한 안정적 실패 분류/메시지. 원시 경로·명령·traceback은 로그에만 남긴다.
    failure_code: Mapped[str] = mapped_column(String(64), default="")
    failure_message: Mapped[str] = mapped_column(String(256), default="")
    # 가져온 원본 XML 내용의 지문(SHA-256). 단독 스캐너가 도킹할 때마다 같은 결과를 다시 올려
    # 스캔 이력이 불어나고 닫힘 판정이 재실행되는 것을 막는다. 직접 실행한 스캔은 빈 값.
    source_fingerprint: Mapped[str] = mapped_column(String(64), default="", index=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class ScanExecution(Base):
    """종료된 staged 실행의 명령 단위 조회 인덱스.

    실행 중 재개·중지의 원천은 계속 events.ndjson/run-state.json 이고, 이 행은 실행이
    끝난 뒤에도 실제 명령과 결과를 조회할 수 있게 materialize 한 사본이다.
    """

    __tablename__ = "scan_executions"
    __table_args__ = (
        UniqueConstraint("scan_id", "execution_key", name="uq_scan_execution_key"),
        Index("ix_scan_executions_scan_stage", "scan_id", "stage"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE")
    )
    execution_key: Mapped[str] = mapped_column(String(256))
    stage: Mapped[str] = mapped_column(String(32), default="")
    group_kind: Mapped[str] = mapped_column(String(16), default="common")
    role: Mapped[str] = mapped_column(String(16), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    artifact: Mapped[str] = mapped_column(String(256), default="")
    argv_json: Mapped[list | None] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="running")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    return_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # 실행 진단값(watchdog_seconds · timeout_count · timed_out · retransmission_cap_*).
    # 컬럼을 다섯 개 만들지 않고 JSON 하나로 모은다 - 이 값들은 함께 읽히고, 나중에 항목이
    # 늘어도 마이그레이션이 더 필요하지 않다. 없으면 None 이고 화면은 기본값으로 그린다.
    diagnostics_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class ScanQualityIssue(Base):
    """실행 품질 문제 한 건. 정상 호스트에는 행을 만들지 않는다."""

    __tablename__ = "scan_quality_issues"
    __table_args__ = (
        UniqueConstraint("scan_id", "issue_key", name="uq_scan_quality_issue_key"),
        Index("ix_scan_quality_issues_scan_kind_stage", "scan_id", "kind", "stage"),
        Index("ix_scan_quality_issues_host_kind", "host_ip", "kind"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE")
    )
    execution_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_executions.id", ondelete="SET NULL"), nullable=True
    )
    issue_key: Mapped[str] = mapped_column(String(384))
    kind: Mapped[str] = mapped_column(String(32))
    stage: Mapped[str] = mapped_column(String(32), default="")
    host_ip: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    retry_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True
    )
    resolved_by_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    @property
    def resolved(self) -> bool:
        return self.resolved_by_scan_id is not None


class ScanHostObservation(Base):
    """한 scan에서 대상 host가 각 단계 어디까지 실제로 도달했는지의 compact projection."""

    __tablename__ = "scan_host_observations"
    __table_args__ = (
        UniqueConstraint("scan_id", "host_ip", name="uq_scan_host_observation"),
        Index("ix_scan_host_observations_host_scan", "host_ip", "scan_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE")
    )
    host_ip: Mapped[str] = mapped_column(String(64))
    discovery_status: Mapped[str] = mapped_column(String(16), default="unknown")
    tcp_sweep_status: Mapped[str] = mapped_column(String(16), default="unknown")
    tcp_service_status: Mapped[str] = mapped_column(String(16), default="unknown")
    udp_sweep_status: Mapped[str] = mapped_column(String(16), default="unknown")
    udp_service_status: Mapped[str] = mapped_column(String(16), default="unknown")


class EndpointObservation(Base):
    """scan별 endpoint 상태 snapshot.

    열린 endpoint와 기존 finding 후보의 권위 있는 부재만 저장한다. 포트 범위 전체의 closed
    cartesian product를 저장하는 테이블이 아니다.
    """

    __tablename__ = "endpoint_observations"
    __table_args__ = (
        UniqueConstraint("scan_id", "finding_key", name="uq_endpoint_observation"),
        Index("ix_endpoint_observations_key_time", "finding_key", "observed_at"),
        Index("ix_endpoint_observations_scan_host_proto", "scan_id", "host_ip", "proto"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE")
    )
    finding_key: Mapped[str] = mapped_column(String(96))
    host_ip: Mapped[str] = mapped_column(String(64))
    port: Mapped[int] = mapped_column(Integer)
    proto: Mapped[str] = mapped_column(String(8))
    state: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(String(32), default="")
    evidence_kind: Mapped[str] = mapped_column(String(16))
    identity_observed: Mapped[int] = mapped_column(Integer, default=1)
    applied_to_current: Mapped[int] = mapped_column(Integer, default=1)
    hostname: Mapped[str] = mapped_column(String(128), default="")
    service: Mapped[str] = mapped_column(String(64), default="")
    product: Mapped[str] = mapped_column(String(128), default="")
    version: Mapped[str] = mapped_column(String(128), default="")
    server: Mapped[str] = mapped_column(String(256), default="")
    identification: Mapped[str] = mapped_column(String(16), default="미확인")
    observed_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


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
    # nmap 이 그 상태를 정한 근거(syn-ack·conn-refused·no-response…). --reason 이 이미 붙어 있어
    # XML 에 늘 있던 값이다. 빈 문자열은 '미관측'(이 컬럼 이전에 인입된 건)이며 no-response 와 다르다.
    reason: Mapped[str] = mapped_column(String(32), default="")
    service: Mapped[str] = mapped_column(String(64), default="")
    product: Mapped[str] = mapped_column(String(128), default="")
    version: Mapped[str] = mapped_column(String(128), default="")
    # HTTP/NSE가 관측한 Server 응답. Nmap service는 taxonomy 키이므로 덮어쓰지 않는다.
    server: Mapped[str] = mapped_column(String(256), default="")
    banner: Mapped[str] = mapped_column(Text, default="")
    cpe: Mapped[str] = mapped_column(Text, default="")
    rtt: Mapped[str] = mapped_column(String(32), default="")
    identification: Mapped[str] = mapped_column(String(16), default="미확인")
    nse_json: Mapped[list | None] = mapped_column(JSON, default=list)  # [{"id":..,"output":..}]

    # --- 분류/근거(taxonomy + 컴플라이언스가 채움) ---
    category: Mapped[str] = mapped_column(String(64), default="")
    usage: Mapped[str] = mapped_column(String(64), default="")
    risk_level: Mapped[str] = mapped_column(String(16), default="info")
    # 조직 규칙이 '허용'으로 정한 발견. risk_level=info 는 '미분류'와 값이 같아 등급만으로는
    # 구분되지 않는다 - 이 플래그가 있어야 허용만 접고 미분류는 계속 보여줄 수 있다.
    allowed: Mapped[int] = mapped_column(Integer, default=0)
    remarks: Mapped[str] = mapped_column(Text, default="")
    compliance_json: Mapped[list | None] = mapped_column(JSON, default=list)  # [{"std":"KISA","ref":..}]
    # NSE 가 관측한 노출 사실 [{"kind","detail"}] — 익명 접근·평문·레거시·인증서 문제 등.
    # 관측이지 판단이 아니다(등급은 taxonomy 가 이 값을 보고 올린다).
    exposure_json: Mapped[list | None] = mapped_column(JSON, default=list)

    # --- 시간적 정체성 ---
    first_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id"), nullable=True)
    last_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id"), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)

    # --- 운영 상태(사람이 갱신, 스캔 간 영속) ---
    status: Mapped[str] = mapped_column(String(16), default="미조치", index=True)
    # 재발 태그 — 정상처리됐다가 다시 열린 적이 있으면 1(상태는 미조치로 되돌아감). 닫히면 0으로 해제.
    reopened: Mapped[int] = mapped_column(Integer, default=0, index=True)
    owner_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    deadline: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    dept: Mapped[str] = mapped_column(String(128), default="")
    contact: Mapped[str] = mapped_column(String(128), default="")  # 자산대장 IP 매칭으로 채움
    owner: Mapped[str] = mapped_column(String(128), default="")    # 자산대장 담당자명(IP 매칭)
    manual_note: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    # 배정된 담당자(ScanOps 사용자). 자산대장에서 온 owner/contact 와는 다른 축이다 -
    # owner 는 '이 자산의 관리 부서가 적어 둔 사람', assignee 는 '이 발견을 조치할 사람'.
    assignee: Mapped["User | None"] = relationship(lazy="joined")

    @property
    def assignee_name(self) -> str:
        user = self.assignee
        if user is None:
            return ""
        return user.display_name or user.username

    events: Mapped[list["FindingEvent"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingEvent.created_at"
    )

    @property
    def fingerprint(self) -> str:
        """-sV 가 식별 못 한 서비스의 원시 응답(fingerprint-strings NSE).

        nmap 이 포트표로만 추측(예: 8770→apple-iphoto)하고 시그니처 매칭에 실패한 경우,
        실제 응답(예: 'server: uvicorn')이 여기 남는다 — service 컬럼엔 안 드러나는 식별 단서.
        """
        for s in (self.nse_json or []):
            if isinstance(s, dict) and (s.get("id") or "") == "fingerprint-strings":
                return s.get("output") or ""
        return ""

    @property
    def state_evidence(self) -> str:
        """이 상태를 응답으로 확인했는지, 무응답으로 추정했는지(nmap --reason 해석)."""
        from .observation import state_evidence

        return state_evidence(self.state, self.reason)

    @property
    def needs_confirmation(self) -> bool:
        """열림 여부를 말하려면 재확인이 필요한 건인가(open|filtered 또는 무응답 추정)."""
        from .observation import needs_confirmation

        return needs_confirmation(self.state, self.reason)

    @property
    def display_identity(self) -> str:
        """User-facing identity; the normalized service remains the taxonomy key."""
        from .identity import display_identity

        return display_identity(
            server=self.server, product=self.product, version=self.version,
            service=self.service, identification=self.identification,
        )


class FindingEvent(Base):
    """이력 타임라인 + 감사 추적 (누가·언제·무엇을)."""
    __tablename__ = "finding_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id"), nullable=True)
    # NEW_OPEN/CLOSED/REOPENED/SERVICE_CHANGED/VERSION_CHANGED/SERVER_CHANGED/STATUS_CHANGE/ASSIGN/DEADLINE/NOTE/EXCEPTION
    type: Mapped[str] = mapped_column(String(24), index=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    finding: Mapped[Finding] = relationship(back_populates="events")


class RiskRule(Base):
    """taxonomy 위에 얹는 조직 커스텀 규칙."""
    __tablename__ = "risk_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    # service_rule / banned_service / port_rule / product_rule / cpe_rule
    kind: Mapped[str] = mapped_column(String(16))
    service: Mapped[str] = mapped_column(String(64), default="")
    # nmap 의 service 는 저신뢰 추측일 때가 많아(uniconv 등) 제품/CPE 로도 규칙을 걸 수 있어야 한다.
    # product 는 서술 접미사(Samba smbd 등)가 붙으므로 부분일치, CPE 는 여러 개가 ';' 로 이어져
    # 저장되므로 역시 부분일치로 본다. 매칭 건수를 UI 가 미리 보여주므로 과매칭은 확인 가능하다.
    product: Mapped[str] = mapped_column(String(128), default="")
    cpe: Mapped[str] = mapped_column(String(128), default="")
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


class AuditLog(Base):
    """전역 감사 로그 — 민감 행위(스캔 실행/중지, 규칙 변경, 로그인)를 '누가·언제·무엇'으로 기록.

    FindingEvent 가 발견 단위 이력이라면, 이건 시스템 행위 단위 추적. 스캐너는 그 자체로
    민감 도구이므로 누가 어떤 대역을 스캔했는지 남기는 게 운영·감사의 기본.
    """
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    actor_name: Mapped[str] = mapped_column(String(64), default="")  # 사용자 삭제 후에도 보존
    action: Mapped[str] = mapped_column(String(32), index=True)      # SCAN_RUN/SCAN_STOP/.../LOGIN
    target: Mapped[str] = mapped_column(String(256), default="")     # 대상(타겟 대역·규칙·계정)
    detail: Mapped[str] = mapped_column(Text, default="")
    ok: Mapped[int] = mapped_column(Integer, default=1)              # 성공/실패(로그인 실패 추적)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)
