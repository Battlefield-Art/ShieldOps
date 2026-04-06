"""SQLAlchemy model for NL Query audit trail persistence (#5)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from shieldops.db.models import Base


class NLQueryAuditRecord(Base):
    """Persistent audit trail for every NL query execution.

    Append-only. Tenant-scoped via ``org_id``. Contains only query metadata
    (question, generated SQL, timing, result count) — never raw result rows.
    """

    __tablename__ = "nl_query_audit"
    __table_args__ = (
        Index("ix_nlq_audit_org_created", "org_id", "created_at"),
        {"extend_existing": True},
    )

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"nlq-{uuid4().hex[:12]}"
    )
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(64), default="")
    question: Mapped[str] = mapped_column(Text, nullable=False)
    generated_sql: Mapped[str] = mapped_column(Text, default="")
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    cache_hit: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(32), default="llm")  # llm | heuristic | cache
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC), nullable=False)
