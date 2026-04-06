"""SQLAlchemy model for fitness-gated agent status records.

Tracks the promotion lifecycle of each agent (beta → ga → disabled) backed
by composite fitness scores from the self-evolution framework.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, Float, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from shieldops.db.models import Base


class AgentLifecycleStatus(StrEnum):
    """Lifecycle states for a fitness-gated agent."""

    BETA = "beta"
    GA = "ga"
    DISABLED = "disabled"


class AgentStatusRecord(Base):
    """Persisted fitness-gated status for a single agent within an org."""

    __tablename__ = "agent_status_records"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=lambda: f"ast-{uuid4().hex[:16]}",
    )
    agent_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=AgentLifecycleStatus.BETA,
        index=True,
    )
    current_fitness: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    fitness_history: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    demoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_evaluated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_agent_status_name_org", "agent_name", "org_id", unique=True),
        Index("ix_agent_status_org_status", "org_id", "status"),
    )
