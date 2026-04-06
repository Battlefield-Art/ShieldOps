"""SQLAlchemy ORM model for tenant connector configurations.

Stores per-org connector credentials encrypted at rest. Decryption
happens on demand inside the connector setup API.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Index, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from shieldops.db.models import Base


class ConnectorConfig(Base):
    """Per-organization connector configuration with encrypted credentials.

    Credentials are Fernet-encrypted using ``SHIELDOPS_ENCRYPTION_KEY``
    and MUST NOT be returned in API responses in plaintext.
    """

    __tablename__ = "connector_configs"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"con-{uuid4().hex[:12]}"
    )
    org_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    encrypted_credentials: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), default="active", index=True
    )  # active | error | disabled
    last_health_check: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("org_id", "provider", name="uq_connector_configs_org_provider"),
        Index("ix_connector_configs_org_status", "org_id", "status"),
    )
