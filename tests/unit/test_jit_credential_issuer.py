"""Tests for JITCredentialIssuer engine."""

import time

import pytest

from shieldops.security.jit_credential_issuer import (
    CredentialScope,
    CredentialStatus,
    JITCredentialIssuer,
    JITCredentialReport,
    JITPolicy,
)


@pytest.fixture
def engine():
    return JITCredentialIssuer(max_records=100)


def test_request_credential(engine):
    rec = engine.request_credential("agent-1", scope=CredentialScope.READ_ONLY, ttl_seconds=1800)
    assert rec.agent_id == "agent-1"
    assert rec.status == CredentialStatus.ISSUED
    assert rec.scope == CredentialScope.READ_ONLY
    assert rec.expires_at > rec.issued_at


def test_request_credential_denied(engine):
    policy = JITPolicy(max_scope=CredentialScope.READ_ONLY)
    engine.set_policy("agent-1", policy)
    rec = engine.request_credential("agent-1", scope=CredentialScope.ADMIN)
    assert rec.status == CredentialStatus.DENIED
    assert "exceeds" in rec.reason


def test_revoke_credential(engine):
    rec = engine.request_credential("agent-1")
    revoked = engine.revoke_credential(rec.id)
    assert revoked is not None
    assert revoked.status == CredentialStatus.REVOKED
    assert revoked.revoked_at is not None


def test_revoke_credential_not_found(engine):
    result = engine.revoke_credential("nonexistent")
    assert result is None


def test_rotate_credential(engine):
    rec = engine.request_credential("agent-1", scope=CredentialScope.READ_WRITE)
    result = engine.rotate_credential(rec.id)
    assert result["status"] == "rotated"
    assert result["old_id"] == rec.id
    assert result["new_id"] != rec.id
    # old should be revoked
    old = [r for r in engine._records if r.id == rec.id][0]
    assert old.status == CredentialStatus.REVOKED


def test_enforce_policy_allowed(engine):
    policy = JITPolicy(max_scope=CredentialScope.READ_WRITE)
    engine.set_policy("agent-1", policy)
    result = engine.enforce_policy("agent-1", CredentialScope.READ_ONLY)
    assert result["allowed"] is True


def test_enforce_policy_denied(engine):
    policy = JITPolicy(max_scope=CredentialScope.READ_ONLY)
    engine.set_policy("agent-1", policy)
    result = engine.enforce_policy("agent-1", CredentialScope.ADMIN)
    assert result["allowed"] is False
    assert "exceeds" in result["reason"]


def test_enforce_policy_no_policy(engine):
    result = engine.enforce_policy("agent-no-policy", CredentialScope.ADMIN)
    assert result["allowed"] is True


def test_detect_over_privileged(engine):
    rec = engine.request_credential("agent-1", scope=CredentialScope.ADMIN)
    # usage_count=0 by default, so admin with 0 usage is over-privileged
    over = engine.detect_over_privileged()
    assert len(over) >= 1
    assert rec.id in [r.id for r in over]


def test_expire_stale(engine):
    rec = engine.request_credential("agent-1", ttl_seconds=0)
    # Force expires_at to be in the past
    rec.expires_at = time.time() - 10
    expired = engine.expire_stale()
    assert len(expired) == 1
    assert expired[0].status == CredentialStatus.EXPIRED


def test_generate_report(engine):
    engine.request_credential("agent-1", scope=CredentialScope.READ_ONLY)
    engine.request_credential("agent-2", scope=CredentialScope.ADMIN)
    report = engine.generate_report()
    assert isinstance(report, JITCredentialReport)
    assert report.total_issued == 2


def test_get_stats(engine):
    engine.request_credential("agent-1")
    stats = engine.get_stats()
    assert "total_records" in stats
    assert "total_policies" in stats
    assert "status_distribution" in stats
    assert "unique_agents" in stats
    assert stats["total_records"] == 1


def test_clear_data(engine):
    engine.request_credential("agent-1")
    engine.set_policy("agent-1", JITPolicy())
    engine.clear_data()
    assert len(engine._records) == 0
    assert len(engine._policies) == 0
