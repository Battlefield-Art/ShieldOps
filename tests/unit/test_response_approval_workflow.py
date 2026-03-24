"""Tests for ResponseApprovalWorkflow engine."""

import time

import pytest

from shieldops.security.response_approval_workflow import (
    ApprovalPolicy,
    ApprovalReport,
    ApprovalStatus,
    ApprovalTier,
    ResponseApprovalWorkflow,
)


@pytest.fixture
def engine():
    policy = ApprovalPolicy(min_confidence_auto=0.85, min_confidence_tier1=0.7, max_wait_minutes=30)
    return ResponseApprovalWorkflow(max_records=100, policy=policy)


def test_request_approval_auto(engine):
    rec = engine.request_approval(
        situation_id="sit-1",
        action_id="act-1",
        action_description="Scale pods",
        confidence=0.9,
        severity="low",
    )
    assert rec.status == ApprovalStatus.AUTO_APPROVED
    assert rec.required_tier == ApprovalTier.AUTO_EXECUTE


def test_request_approval_tier1(engine):
    rec = engine.request_approval(
        situation_id="sit-1",
        action_id="act-1",
        action_description="Restart service",
        confidence=0.75,
        severity="medium",
    )
    assert rec.status == ApprovalStatus.PENDING
    assert rec.required_tier == ApprovalTier.TIER_1


def test_request_approval_tier2(engine):
    rec = engine.request_approval(
        situation_id="sit-1",
        action_id="act-1",
        action_description="Failover DB",
        confidence=0.55,
        severity="medium",
    )
    assert rec.status == ApprovalStatus.PENDING
    assert rec.required_tier == ApprovalTier.TIER_2


def test_request_approval_critical(engine):
    rec = engine.request_approval(
        situation_id="sit-1",
        action_id="act-1",
        action_description="Delete cluster",
        confidence=0.95,
        severity="critical",
    )
    assert rec.status == ApprovalStatus.PENDING
    # Critical severity forces tier_3 floor regardless of confidence
    assert rec.required_tier in (ApprovalTier.TIER_3, ApprovalTier.CISO)


def test_approve(engine):
    rec = engine.request_approval(
        situation_id="sit-1",
        action_id="act-1",
        action_description="Fix",
        confidence=0.75,
        severity="medium",
    )
    approved = engine.approve(rec.id, responder="analyst-1")
    assert approved is not None
    assert approved.status == ApprovalStatus.APPROVED
    assert approved.responder == "analyst-1"


def test_approve_nonexistent(engine):
    result = engine.approve("nonexistent", responder="analyst-1")
    assert result is None


def test_reject(engine):
    rec = engine.request_approval(
        situation_id="sit-1",
        action_id="act-1",
        action_description="Risky action",
        confidence=0.6,
        severity="medium",
    )
    rejected = engine.reject(rec.id, responder="analyst-1", reason="Too risky")
    assert rejected is not None
    assert rejected.status == ApprovalStatus.REJECTED
    assert rejected.rejection_reason == "Too risky"


def test_check_expirations(engine):
    rec = engine.request_approval(
        situation_id="sit-1",
        action_id="act-1",
        action_description="Waiting too long",
        confidence=0.75,
        severity="medium",
    )
    # Force the request to be old
    rec.requested_at = time.time() - 3600  # 1 hour ago (> 30 min max)
    escalated = engine.check_expirations()
    assert rec.status == ApprovalStatus.EXPIRED
    assert len(escalated) >= 1


def test_get_pending(engine):
    engine.request_approval("sit-1", "act-1", "action a", confidence=0.75, severity="medium")
    engine.request_approval("sit-2", "act-2", "action b", confidence=0.55, severity="medium")
    pending = engine.get_pending()
    assert len(pending) == 2
    pending_t1 = engine.get_pending(tier=ApprovalTier.TIER_1)
    assert all(r.required_tier == ApprovalTier.TIER_1 for r in pending_t1)


def test_generate_report(engine):
    engine.request_approval("sit-1", "act-1", "auto", confidence=0.9, severity="low")
    engine.request_approval("sit-2", "act-2", "manual", confidence=0.75, severity="medium")
    report = engine.generate_approval_report()
    assert isinstance(report, ApprovalReport)
    assert report.total_requests == 2
    assert report.auto_approved == 1


def test_get_stats(engine):
    engine.request_approval("sit-1", "act-1", "test", confidence=0.9, severity="low")
    stats = engine.get_stats()
    assert "total_requests" in stats
    assert "pending" in stats
    assert "auto_approved" in stats
    assert "tier_distribution" in stats
    assert "policy" in stats


def test_clear_data(engine):
    engine.request_approval("sit-1", "act-1", "test", confidence=0.5, severity="medium")
    engine.clear_data()
    assert len(engine._records) == 0
