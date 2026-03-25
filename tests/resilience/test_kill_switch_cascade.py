"""Resilience tests for the kill switch with session revocation cascade."""

from __future__ import annotations

from shieldops.security.agent_session_revoker import (
    AgentSessionRevoker,
    CredentialType,
    RevocationPolicy,
    RevocationRecord,
    RevocationStatus,
)


class TestKillSwitchCascade:
    """Verify session revoker behaves correctly under normal and edge-case scenarios."""

    def test_revoke_single_credential(self) -> None:
        revoker = AgentSessionRevoker()
        record = revoker.revoke("agent-1", CredentialType.JWT_SESSION, "cred-123")
        assert isinstance(record, RevocationRecord)
        assert record.status == RevocationStatus.REVOKED
        assert record.agent_id == "agent-1"

    def test_revoke_all_for_agent(self) -> None:
        revoker = AgentSessionRevoker()
        records = revoker.revoke_all("agent-2")
        assert isinstance(records, list)
        assert len(records) == len(CredentialType)
        assert all(r.status == RevocationStatus.REVOKED for r in records)

    def test_revoke_nonexistent(self) -> None:
        revoker = AgentSessionRevoker()
        # Revoking for an agent with no prior state should still succeed gracefully
        record = revoker.revoke("ghost-agent", CredentialType.API_KEY, "nonexistent-cred")
        assert record.status == RevocationStatus.REVOKED

    def test_set_and_check_policy(self) -> None:
        revoker = AgentSessionRevoker()
        policy = RevocationPolicy(
            agent_id="agent-3",
            auto_revoke_on_trip=True,
            credential_types_to_revoke=["api_key", "jwt_session"],
        )
        revoker.set_policy("agent-3", policy)
        # revoke_all should now only revoke the 2 types specified in policy
        records = revoker.revoke_all("agent-3")
        types_revoked = {r.credential_type for r in records}
        assert types_revoked == {CredentialType.API_KEY, CredentialType.JWT_SESSION}

    def test_detect_lingering_sessions(self) -> None:
        revoker = AgentSessionRevoker()
        # Revoke a single type, so others remain as "potentially_active"
        revoker.revoke("agent-4", CredentialType.API_KEY)
        lingering = revoker.detect_lingering_sessions("agent-4")
        assert isinstance(lingering, list)
        # At least some credential types should show as potentially active
        statuses = {entry.get("status") for entry in lingering}
        assert "potentially_active" in statuses

    def test_revocation_report(self) -> None:
        revoker = AgentSessionRevoker()
        revoker.revoke("agent-5", CredentialType.OAUTH_TOKEN)
        revoker.revoke("agent-5", CredentialType.MCP_CONNECTION)
        report = revoker.generate_revocation_report()
        assert report.total_revocations == 2
        assert "agent-5" in report.by_agent

    def test_stats_after_revocations(self) -> None:
        revoker = AgentSessionRevoker()
        revoker.revoke("agent-6", CredentialType.API_KEY)
        revoker.revoke("agent-7", CredentialType.API_KEY)
        stats = revoker.get_stats()
        assert stats["total_revocations"] == 2
        assert stats["unique_agents"] == 2

    def test_clear_data(self) -> None:
        revoker = AgentSessionRevoker()
        revoker.revoke("agent-8", CredentialType.API_KEY)
        revoker.set_policy("agent-8", RevocationPolicy(agent_id="agent-8"))
        result = revoker.clear_data()
        assert result == {"status": "cleared"}
        stats = revoker.get_stats()
        assert stats["total_revocations"] == 0
        assert stats["total_policies"] == 0
