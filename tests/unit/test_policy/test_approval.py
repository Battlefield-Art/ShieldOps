"""Tests for the approval workflow lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from shieldops.policy.approval_gate import (
    ApprovalStatus,
    approve_request,
    check_approval_status,
    clear_requests,
    create_approval_request,
    deny_request,
)


@pytest.fixture(autouse=True)
def _clean():
    """Ensure a clean store for every test."""
    clear_requests()
    yield
    clear_requests()


def test_create_request() -> None:
    req = create_approval_request("agent-a", "restart-svc", {"env": "prod"})
    assert req.status == ApprovalStatus.PENDING
    assert req.agent_name == "agent-a"
    assert req.action == "restart-svc"
    assert req.context == {"env": "prod"}
    assert req.id  # non-empty


def test_check_status_returns_request() -> None:
    req = create_approval_request("agent-a", "action")
    found = check_approval_status(req.id)
    assert found is not None
    assert found.id == req.id


def test_check_status_not_found() -> None:
    assert check_approval_status("nonexistent") is None


def test_approve_request_lifecycle() -> None:
    req = create_approval_request("agent-a", "action")
    result = approve_request(req.id, approver="admin@co.com")
    assert result is not None
    assert result.status == ApprovalStatus.APPROVED
    assert result.approver == "admin@co.com"
    assert result.decided_at is not None


def test_deny_request_lifecycle() -> None:
    req = create_approval_request("agent-a", "action")
    result = deny_request(req.id, approver="admin@co.com")
    assert result is not None
    assert result.status == ApprovalStatus.DENIED
    assert result.approver == "admin@co.com"


def test_approve_nonexistent_returns_none() -> None:
    assert approve_request("no-such-id", "admin") is None


def test_deny_nonexistent_returns_none() -> None:
    assert deny_request("no-such-id", "admin") is None


def test_cannot_approve_already_denied() -> None:
    req = create_approval_request("agent-a", "action")
    deny_request(req.id, "admin")
    result = approve_request(req.id, "other-admin")
    assert result is not None
    assert result.status == ApprovalStatus.DENIED  # stays denied


def test_cannot_deny_already_approved() -> None:
    req = create_approval_request("agent-a", "action")
    approve_request(req.id, "admin")
    result = deny_request(req.id, "other-admin")
    assert result is not None
    assert result.status == ApprovalStatus.APPROVED  # stays approved


def test_expired_request_auto_transitions() -> None:
    req = create_approval_request("agent-a", "action")
    # Force expiry
    req.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    found = check_approval_status(req.id)
    assert found is not None
    assert found.status == ApprovalStatus.EXPIRED


def test_cannot_approve_expired() -> None:
    req = create_approval_request("agent-a", "action")
    req.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    result = approve_request(req.id, "admin")
    assert result is not None
    assert result.status == ApprovalStatus.EXPIRED


def test_clear_requests() -> None:
    create_approval_request("agent-a", "action")
    clear_requests()
    assert check_approval_status("anything") is None
