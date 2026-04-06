"""SQLAlchemy model for the unified tenant-aware audit log (#6)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from shieldops.db.models import Base


class AuditLogRecord(Base):
    """Append-only audit log shared across all subsystems.

    Any subsystem (firewall, policy, persistence, tenant signup, etc.) can
    persist events here via :class:`AuditLogRepository`. Never updated or
    deleted — only appended.
    """

    __tablename__ = "shieldops_audit_log"
    __table_args__ = (
        Index("ix_audit_org_created", "org_id", "created_at"),
        Index("ix_audit_org_action", "org_id", "action"),
        {"extend_existing": True},
    )

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"al-{uuid4().hex[:12]}"
    )
    org_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), default="")
    target: Mapped[str] = mapped_column(String(256), default="")
    result: Mapped[str] = mapped_column(String(32), default="")
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
