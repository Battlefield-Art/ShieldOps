"""Security Event Logger -- SIEM-compatible audit events.

Produces structured security events compatible with:
- CEF (Common Event Format)
- OCSF (Open Cybersecurity Schema Framework)
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class SecurityEventType(StrEnum):
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    POLICY_VIOLATION = "policy_violation"
    AGENT_ACTION = "agent_action"
    CONFIG_CHANGE = "config_change"


class SecurityEvent(BaseModel):
    """A single security-relevant event."""

    event_id: str = Field(default_factory=lambda: uuid4().hex)
    event_type: SecurityEventType
    severity: int  # 0-10
    actor: str
    target: str
    action: str
    outcome: str  # success / failure
    source_ip: str = ""
    details: dict[str, Any] = {}
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    correlation_id: str = ""
    compliance_frameworks: list[str] = []


class SecurityEventLogger:
    """In-memory security event logger with CEF export."""

    def __init__(self) -> None:
        self._events: list[SecurityEvent] = []

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def log_event(self, event: SecurityEvent) -> None:
        """Record a security event and emit a structured log."""
        self._events.append(event)
        logger.info(
            "security_event",
            event_type=event.event_type,
            severity=event.severity,
            actor=event.actor,
            target=event.target,
            action=event.action,
            outcome=event.outcome,
        )

    def to_cef(self, event: SecurityEvent) -> str:
        """Convert a SecurityEvent to CEF (Common Event Format) string.

        Format::

            CEF:0|ShieldOps|SRE-Platform|1.0|<event_type>|<action>|<severity>|
            src=<ip> act=<action> duser=<actor> dst=<target> outcome=<outcome>
            cs1=<frameworks>
        """
        extensions = (
            f"src={event.source_ip} "
            f"act={event.action} "
            f"duser={event.actor} "
            f"dst={event.target} "
            f"outcome={event.outcome} "
            f"cs1={','.join(event.compliance_frameworks)}"
        )
        return (
            f"CEF:0|ShieldOps|SRE-Platform|1.0"
            f"|{event.event_type}"
            f"|{event.action}"
            f"|{event.severity}"
            f"|{extensions}"
        )

    def get_events(
        self,
        event_type: SecurityEventType | None = None,
        actor: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[SecurityEvent]:
        """Query stored events with optional filters."""
        results = self._events
        if event_type is not None:
            results = [e for e in results if e.event_type == event_type]
        if actor is not None:
            results = [e for e in results if e.actor == actor]
        if since is not None:
            results = [e for e in results if e.timestamp >= since]
        # Most recent first, capped at *limit*
        return sorted(results, key=lambda e: e.timestamp, reverse=True)[:limit]
