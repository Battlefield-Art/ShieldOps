"""AI Security Control Plane database models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from shieldops.db.models import Base

# ---------------------------------------------------------------------------
# Situation Awareness
# ---------------------------------------------------------------------------


class Situation(Base):
    """Correlated security situation aggregating findings from multiple vendors."""

    __tablename__ = "situations"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"sit-{uuid4().hex[:12]}"
    )
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(32), index=True)  # critical/high/medium/low/info
    status: Mapped[str] = mapped_column(
        String(32), default="open", index=True
    )  # open/acknowledged/investigating/resolved/closed
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    vendor_sources: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    mitre_techniques: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    affected_entities: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mttd_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mtta_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mttr_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Relationships
    findings: Mapped[list[SituationFinding]] = relationship(
        "SituationFinding", back_populates="situation", cascade="all, delete-orphan"
    )
    actions: Mapped[list[SituationAction]] = relationship(
        "SituationAction", back_populates="situation", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_situations_severity_status", "severity", "status"),
        Index("ix_situations_risk_score", "risk_score"),
    )


class SituationFinding(Base):
    """Individual finding from a vendor detection, linked to a situation."""

    __tablename__ = "situation_findings"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"sfn-{uuid4().hex[:12]}"
    )
    situation_id: Mapped[str] = mapped_column(String(64), index=True)
    vendor: Mapped[str] = mapped_column(String(128), index=True)
    detection_id: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Relationship
    situation: Mapped[Situation] = relationship("Situation", back_populates="findings")

    __table_args__ = (Index("ix_situation_findings_vendor_ts", "vendor", "timestamp"),)


class SituationAction(Base):
    """Action taken (or proposed) as part of a situation response."""

    __tablename__ = "situation_actions"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"sac-{uuid4().hex[:12]}"
    )
    situation_id: Mapped[str] = mapped_column(String(64), index=True)
    action_type: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(
        String(32), default="proposed"
    )  # proposed/approved/executing/completed/failed
    executed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # Relationship
    situation: Mapped[Situation] = relationship("Situation", back_populates="actions")


# ---------------------------------------------------------------------------
# Non-Human Identity (NHI) Management
# ---------------------------------------------------------------------------


class NHIdentity(Base):
    """Non-human identity tracked for least-privilege governance."""

    __tablename__ = "nhi_identities"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"nhi-{uuid4().hex[:12]}"
    )
    name: Mapped[str] = mapped_column(String(256), index=True)
    nhi_type: Mapped[str] = mapped_column(
        String(64), index=True
    )  # ai_agent/service_account/api_key/bot/pipeline
    provider: Mapped[str] = mapped_column(String(128), index=True)
    permissions: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    owner: Mapped[str | None] = mapped_column(String(256), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(
        String(32), default="active", index=True
    )  # active/inactive/revoked/expired
    last_active_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_nhi_type_provider", "nhi_type", "provider"),
        Index("ix_nhi_risk_score", "risk_score"),
    )


# ---------------------------------------------------------------------------
# Shadow AI Detection
# ---------------------------------------------------------------------------


class ShadowAIDetection(Base):
    """Detected unauthorized / unregistered AI API usage."""

    __tablename__ = "shadow_ai_detections"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"sha-{uuid4().hex[:12]}"
    )
    provider: Mapped[str] = mapped_column(String(128), index=True)
    api_endpoint: Mapped[str] = mapped_column(String(512))
    calling_service: Mapped[str] = mapped_column(String(256), index=True)
    detection_source: Mapped[str] = mapped_column(String(128))
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    estimated_cost: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(
        String(32), default="detected", index=True
    )  # detected/investigating/approved/blocked
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    __table_args__ = (Index("ix_shadow_ai_provider_service", "provider", "calling_service"),)


# ---------------------------------------------------------------------------
# AI Firewall Events
# ---------------------------------------------------------------------------


class FirewallEvent(Base):
    """Event logged by the AI agent firewall (rate limits, blocks, anomalies)."""

    __tablename__ = "firewall_events"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"fwe-{uuid4().hex[:12]}"
    )
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    tool_name: Mapped[str] = mapped_column(String(256))
    action_taken: Mapped[str] = mapped_column(
        String(32), index=True
    )  # allowed/blocked/rate_limited/quarantined
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    anomaly_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    policy_rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    data_bytes: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )

    __table_args__ = (
        Index("ix_firewall_agent_ts", "agent_id", "timestamp"),
        Index("ix_firewall_action_ts", "action_taken", "timestamp"),
    )


# ---------------------------------------------------------------------------
# MCP Server Registry
# ---------------------------------------------------------------------------


class MCPServer(Base):
    """Registered MCP (Model Context Protocol) server for zero-trust governance."""

    __tablename__ = "mcp_servers"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"mcp-{uuid4().hex[:12]}"
    )
    name: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    endpoint: Mapped[str] = mapped_column(String(512))
    transport: Mapped[str] = mapped_column(String(32))  # https/wss/stdio
    auth_type: Mapped[str] = mapped_column(String(64))  # oauth2/mtls/jwt/api_key
    tools_exposed: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    downstream_resources: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    trust_level: Mapped[str] = mapped_column(String(32), default="untrusted")
    owner: Mapped[str | None] = mapped_column(String(256), nullable=True)
    zero_trust_compliant: Mapped[bool] = mapped_column(Boolean, default=False)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (Index("ix_mcp_servers_trust_level", "trust_level"),)
