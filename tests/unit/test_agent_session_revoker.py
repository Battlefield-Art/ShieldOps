"""Tests for AgentSessionRevoker engine."""

import pytest

from shieldops.security.agent_session_revoker import (
    AgentSessionRevoker,
    CredentialType,
    RevocationPolicy,
    RevocationReport,
    RevocationStatus,
)


@pytest.fixture
def engine():
    return AgentSessionRevoker(max_records=100)


def test_revoke_single(engine):
    rec = engine.revoke("agent-1", credential_type=CredentialType.API_KEY, credential_id="key-123")
    assert rec.agent_id == "agent-1"
    assert rec.status == RevocationStatus.REVOKED
    assert rec.credential_type == CredentialType.API_KEY
    assert len(engine._records) == 1


def test_revoke_all(engine):
    results = engine.revoke_all("agent-1")
    assert len(results) == len(CredentialType)
    for r in results:
        assert r.agent_id == "agent-1"
        assert r.status == RevocationStatus.REVOKED


def test_set_policy(engine):
    policy = RevocationPolicy(agent_id="agent-1", auto_revoke_on_trip=True)
    engine.set_policy("agent-1", policy)
    assert "agent-1" in engine._policies
    assert engine._policies["agent-1"].auto_revoke_on_trip is True


def test_check_revocation_status(engine):
    rec = engine.revoke("agent-1")
    found = engine.check_revocation_status(rec.id)
    assert found is not None
    assert found.id == rec.id
    assert found.status == RevocationStatus.REVOKED

    not_found = engine.check_revocation_status("nonexistent-id")
    assert not_found is None


def test_detect_lingering_sessions(engine):
    engine.revoke("agent-1", credential_type=CredentialType.API_KEY)
    lingering = engine.detect_lingering_sessions("agent-1")
    # Should find types that were NOT revoked
    assert len(lingering) > 0
    types_found = {item.get("credential_type") for item in lingering}
    assert CredentialType.API_KEY.value not in types_found


def test_generate_report(engine):
    engine.revoke("agent-1", credential_type=CredentialType.API_KEY)
    engine.revoke("agent-2", credential_type=CredentialType.JWT_SESSION)
    report = engine.generate_revocation_report()
    assert isinstance(report, RevocationReport)
    assert report.total_revocations == 2
    assert "api_key" in report.by_type


def test_get_stats(engine):
    engine.revoke("agent-1")
    stats = engine.get_stats()
    assert "total_revocations" in stats
    assert "total_policies" in stats
    assert "status_distribution" in stats
    assert "unique_agents" in stats
    assert stats["total_revocations"] == 1


def test_clear_data(engine):
    engine.revoke("agent-1")
    engine.set_policy("agent-1", RevocationPolicy())
    engine.clear_data()
    assert len(engine._records) == 0
    assert len(engine._policies) == 0
    assert len(engine._revocation_times) == 0
