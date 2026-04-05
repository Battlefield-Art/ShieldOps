"""SQLAlchemy models for agent execution persistence and audit trail."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from shieldops.db.models import Base


class AgentRunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AgentRun(Base):
    """Persisted agent execution run with timing and token usage."""

    __tablename__ = "agent_runs"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=lambda: f"run-{uuid4().hex[:16]}",
    )
    agent_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=AgentRunStatus.PENDING, index=True
    )
    input_data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    output_data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    token_usage: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    )
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_agent_runs_name_org", "agent_name", "org_id"),
        Index("ix_agent_runs_created", "created_at"),
        Index("ix_agent_runs_org_created", "org_id", "created_at"),
    )


class AuditEntry(Base):
    """Immutable audit trail — APPEND-ONLY, never UPDATE or DELETE.

    Records every significant action taken by agents or users across
    the platform for compliance, forensics, and accountability.
    """

    __tablename__ = "audit_entries"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=lambda: f"ae-{uuid4().hex[:16]}",
    )
    action: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    result: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_audit_entries_org_created", "org_id", "created_at"),
        Index("ix_audit_entries_actor_action", "actor", "action"),
    )
