"""Shared fixtures for db.services contract tests (RFC #245 PR-4 / #273).

Each service test file uses the isolated-test-model pattern: we declare
SQLite-compatible test replicas of the production models (no JSONB, no
``server_default``) and monkeypatch them into the service module so the
service's queries hit our in-memory tables.

This keeps the tests:

- Independent of Postgres (CI runs them in <1s with sqlite+aiosqlite).
- Isolated from the production model graph (no ``Base.metadata`` cross-talk).
- Identical in shape to the existing ``tests/unit/db/test_fetch.py`` and
  ``tests/unit/db/test_audit_log_repository.py`` patterns.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class _SvcTestBase(DeclarativeBase):
    """Local Base for service contract tests — underscored to avoid pytest collection."""

    pass


# Public alias used by service test files (re-exports keep imports stable
# without tripping pytest's `Test*` collection rule).
SvcBase = _SvcTestBase


class FakeInvestigation(SvcBase):
    __tablename__ = "investigations_test"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(128), default="")
    alert_name: Mapped[str] = mapped_column(String(256), default="")
    severity: Mapped[str] = mapped_column(String(32), default="warning")
    status: Mapped[str] = mapped_column(String(32), default="init")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class FakeRemediation(SvcBase):
    __tablename__ = "remediations_test"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    action_type: Mapped[str] = mapped_column(String(128), default="")
    target_resource: Mapped[str] = mapped_column(String(256), default="")
    environment: Mapped[str] = mapped_column(String(32), default="prod")
    risk_level: Mapped[str] = mapped_column(String(32), default="low")
    status: Mapped[str] = mapped_column(String(32), default="init")
    validation_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    investigation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class FakeAuditLog(SvcBase):
    __tablename__ = "audit_log_test_svc"
    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"aud-{uuid4().hex[:12]}"
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    agent_type: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(128), default="")
    target_resource: Mapped[str] = mapped_column(String(256), default="")
    environment: Mapped[str] = mapped_column(String(32), default="prod")
    risk_level: Mapped[str] = mapped_column(String(32), default="low")
    policy_evaluation: Mapped[str] = mapped_column(String(32), default="allowed")
    approval_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), default="success")
    reasoning: Mapped[str] = mapped_column(Text, default="")
    actor: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class FakeIncidentOutcome(SvcBase):
    __tablename__ = "incident_outcomes_test"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_type: Mapped[str] = mapped_column(String(128), default="")
    environment: Mapped[str] = mapped_column(String(32), default="prod")
    root_cause: Mapped[str] = mapped_column(Text, default="")
    resolution_action: Mapped[str] = mapped_column(String(128), default="")
    investigation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remediation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    investigation_duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    remediation_duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    was_automated: Mapped[bool] = mapped_column(Boolean, default=False)
    was_correct: Mapped[bool] = mapped_column(Boolean, default=True)
    feedback: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class FakeOnboardingProgress(SvcBase):
    __tablename__ = "onboarding_progress_test"
    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"onb-{uuid4().hex[:12]}"
    )
    org_id: Mapped[str] = mapped_column(String(64))
    step_name: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    step_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
