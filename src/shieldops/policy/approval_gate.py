"""Lightweight approval workflow for policy-gated actions.

Provides in-memory request tracking with Slack/PagerDuty notification
placeholders.  Designed to be replaced by a durable store (Postgres)
before GA.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_EXPIRY_MINUTES = 30


class ApprovalStatus(StrEnum):
    """Lifecycle status of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class ApprovalRequest(BaseModel):
    """A single approval request tied to a policy evaluation."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    agent_name: str
    action: str
    context: dict[str, Any] = Field(default_factory=dict)
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC) + timedelta(minutes=DEFAULT_EXPIRY_MINUTES)
    )
    approver: str | None = None
    decided_at: datetime | None = None

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# In-memory store (will be swapped for DB in production)
# ---------------------------------------------------------------------------
_requests: dict[str, ApprovalRequest] = {}


def _expire_if_needed(req: ApprovalRequest) -> ApprovalRequest:
    """Transparently expire a request that has passed its TTL."""
    if req.status == ApprovalStatus.PENDING and datetime.now(UTC) >= req.expires_at:
        req.status = ApprovalStatus.EXPIRED
        logger.info("approval_expired", request_id=req.id)
    return req


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_approval_request(
    agent_name: str,
    action: str,
    context: dict[str, Any] | None = None,
) -> ApprovalRequest:
    """Create a new approval request and notify stakeholders.

    Args:
        agent_name: Name of the agent requesting approval.
        action: Description of the action to be approved.
        context: Serialised ``PolicyContext`` or equivalent metadata.

    Returns:
        The newly created ``ApprovalRequest``.
    """
    req = ApprovalRequest(
        agent_name=agent_name,
        action=action,
        context=context or {},
    )
    _requests[req.id] = req

    logger.info(
        "approval_request_created",
        request_id=req.id,
        agent_name=agent_name,
        action=action,
        expires_at=req.expires_at.isoformat(),
    )

    # --- Notification placeholder ---
    # TODO: integrate with Slack / PagerDuty via messaging module
    _notify_stakeholders(req)

    return req


def check_approval_status(request_id: str) -> ApprovalRequest | None:
    """Return the current state of an approval request, or ``None`` if not found."""
    req = _requests.get(request_id)
    if req is None:
        return None
    return _expire_if_needed(req)


def approve_request(request_id: str, approver: str) -> ApprovalRequest | None:
    """Mark a pending request as approved.

    Returns ``None`` if the request does not exist or is no longer pending.
    """
    req = _requests.get(request_id)
    if req is None:
        return None
    _expire_if_needed(req)
    if req.status != ApprovalStatus.PENDING:
        logger.warning(
            "approval_action_on_non_pending",
            request_id=request_id,
            current_status=req.status.value,
        )
        return req

    req.status = ApprovalStatus.APPROVED
    req.approver = approver
    req.decided_at = datetime.now(UTC)

    logger.info("approval_granted", request_id=request_id, approver=approver)
    return req


def deny_request(request_id: str, approver: str) -> ApprovalRequest | None:
    """Mark a pending request as denied.

    Returns ``None`` if the request does not exist or is no longer pending.
    """
    req = _requests.get(request_id)
    if req is None:
        return None
    _expire_if_needed(req)
    if req.status != ApprovalStatus.PENDING:
        logger.warning(
            "denial_action_on_non_pending",
            request_id=request_id,
            current_status=req.status.value,
        )
        return req

    req.status = ApprovalStatus.DENIED
    req.approver = approver
    req.decided_at = datetime.now(UTC)

    logger.info("approval_denied", request_id=request_id, approver=approver)
    return req


def clear_requests() -> None:
    """Remove all stored requests (useful for tests)."""
    _requests.clear()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _notify_stakeholders(req: ApprovalRequest) -> None:
    """Placeholder — send Slack / PagerDuty notification for a new request."""
    logger.info(
        "approval_notification_placeholder",
        request_id=req.id,
        agent_name=req.agent_name,
        action=req.action,
    )
