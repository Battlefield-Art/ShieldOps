"""Tenant signup + billing ORM models (issue #216).

These models support self-service signup: an ``Organization`` owns a Stripe
customer/subscription, ``User`` rows represent people who can log in, and
``EmailVerificationToken`` rows gate the verify-email flow.

The models are intentionally standalone (separate ``__tablename__`` values
prefixed with ``tenant_``) so they can coexist with the pre-existing
``OrganizationRecord``/``UserRecord`` in ``models.py`` without conflict.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from shieldops.db.models import Base


def _uuid() -> str:
    return uuid4().hex


def _default_verification_expiry() -> datetime:
    return datetime.now(UTC) + timedelta(hours=24)


class Organization(Base):
    """Self-service tenant — owns a Stripe subscription."""

    __tablename__ = "tenant_organizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    owner_email: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    stripe_customer_id: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(
        String(256), nullable=True, index=True
    )
    plan: Mapped[str] = mapped_column(String(32), default="starter", nullable=False)
    # active | past_due | canceled | trialing | incomplete
    status: Mapped[str] = mapped_column(String(32), default="trialing", nullable=False, index=True)
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (Index("ix_tenant_org_status_plan", "status", "plan"),)


class User(Base):
    """Platform user — belongs to an ``Organization``."""

    __tablename__ = "tenant_users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(256), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    org_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenant_organizations.id"), index=True, nullable=False
    )
    role: Mapped[str] = mapped_column(String(32), default="owner", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class EmailVerificationToken(Base):
    """One-time token emailed to users to verify their address."""

    __tablename__ = "tenant_email_verification_tokens"

    token: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenant_users.id"), index=True, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_default_verification_expiry, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


__all__ = ["Organization", "User", "EmailVerificationToken"]
