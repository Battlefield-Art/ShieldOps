"""Tests for shieldops.agents.nhi_registry."""

from __future__ import annotations

from shieldops.agents.nhi_registry.models import (
    NHIRegistryState,
    NHIRisk,
    NHIStatus,
    NHIType,
)


class TestEnums:
    def test_nhitype_service_account(self):
        assert NHIType.SERVICE_ACCOUNT == "service_account"

    def test_nhitype_ai_agent(self):
        assert NHIType.AI_AGENT == "ai_agent"

    def test_nhitype_ci_cd_token(self):
        assert NHIType.CI_CD_TOKEN == "ci_cd_token"  # noqa: S105

    def test_nhitype_oauth_app(self):
        assert NHIType.OAUTH_APP == "oauth_app"

    def test_nhistatus_active(self):
        assert NHIStatus.ACTIVE == "active"

    def test_nhistatus_dormant(self):
        assert NHIStatus.DORMANT == "dormant"

    def test_nhistatus_orphaned(self):
        assert NHIStatus.ORPHANED == "orphaned"

    def test_nhistatus_compromised(self):
        assert NHIStatus.COMPROMISED == "compromised"

    def test_nhirisk_minimal(self):
        assert NHIRisk.MINIMAL == "minimal"

    def test_nhirisk_low(self):
        assert NHIRisk.LOW == "low"

    def test_nhirisk_medium(self):
        assert NHIRisk.MEDIUM == "medium"

    def test_nhirisk_high(self):
        assert NHIRisk.HIGH == "high"


class TestModels:
    def test_state_defaults(self):
        s = NHIRegistryState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.nhi_registry.graph import (
            create_nhi_registry_graph,
        )

        sg = create_nhi_registry_graph()
        assert sg.compile() is not None
