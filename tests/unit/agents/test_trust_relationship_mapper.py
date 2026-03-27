"""Tests for shieldops.agents.trust_relationship_mapper."""

from __future__ import annotations

import pytest

from shieldops.agents.trust_relationship_mapper.models import (
    AbuseIndicator,
    DelegationChain,
    FederationMapping,
    ReasoningStep,
    TrustAbuse,
    TrustBoundary,
    TrustRelationshipMapperState,
    TrustRiskAssessment,
    TrustStage,
    TrustType,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_trust_stage_values(self) -> None:
        assert TrustStage.DISCOVER_TRUST_BOUNDARIES == "discover_trust_boundaries"
        assert TrustStage.MAP_FEDERATION == "map_federation"
        assert TrustStage.ANALYZE_DELEGATION_CHAINS == "analyze_delegation_chains"
        assert TrustStage.DETECT_TRUST_ABUSE == "detect_trust_abuse"
        assert TrustStage.ASSESS_RISK == "assess_risk"
        assert TrustStage.REPORT == "report"
        assert len(TrustStage) == 6

    def test_trust_type_values(self) -> None:
        assert TrustType.FEDERATION == "federation"
        assert TrustType.DELEGATION == "delegation"
        assert TrustType.CROSS_ACCOUNT_ROLE == "cross_account_role"
        assert TrustType.API_TRUST == "api_trust"
        assert TrustType.AI_AGENT_DELEGATION == "ai_agent_delegation"
        assert TrustType.MCP_TRUST_CHAIN == "mcp_trust_chain"
        assert len(TrustType) == 6

    def test_abuse_indicator_values(self) -> None:
        assert AbuseIndicator.STALE_FEDERATION == "stale_federation"
        assert AbuseIndicator.EXCESSIVE_DELEGATION == "excessive_delegation"
        assert AbuseIndicator.CROSS_ACCOUNT_PIVOT == "cross_account_pivot"
        assert AbuseIndicator.TRUST_CHAIN_BYPASS == "trust_chain_bypass"
        assert AbuseIndicator.ORPHANED_TRUST == "orphaned_trust"
        assert len(AbuseIndicator) == 5


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_state_defaults(self) -> None:
        state = TrustRelationshipMapperState()
        assert state.tenant_id == ""
        assert state.scope == "all"
        assert state.trust_boundaries == []
        assert state.federation_mappings == []
        assert state.delegation_chains == []
        assert state.trust_abuses == []
        assert state.risk_assessments == []
        assert state.total_boundaries == 0
        assert state.total_abuses_detected == 0
        assert state.avg_risk_score == 0.0
        assert state.current_stage == TrustStage.DISCOVER_TRUST_BOUNDARIES
        assert state.error == ""

    def test_trust_boundary_defaults(self) -> None:
        tb = TrustBoundary()
        assert tb.trust_type == TrustType.FEDERATION
        assert tb.is_bidirectional is False
        assert tb.metadata == {}

    def test_federation_mapping_defaults(self) -> None:
        fm = FederationMapping()
        assert fm.claims_mapped == []
        assert fm.token_count_30d == 0
        assert fm.risk_score == 0.0

    def test_delegation_chain_defaults(self) -> None:
        dc = DelegationChain()
        assert dc.chain_depth == 0
        assert dc.principals == []
        assert dc.permissions == []
        assert dc.is_transitive is False

    def test_trust_abuse_defaults(self) -> None:
        ta = TrustAbuse()
        assert ta.indicator == AbuseIndicator.STALE_FEDERATION
        assert ta.severity == ""
        assert ta.evidence == []

    def test_trust_risk_assessment_defaults(self) -> None:
        tra = TrustRiskAssessment()
        assert tra.overall_risk == 0.0
        assert tra.risk_factors == []
        assert tra.abuse_indicators == []

    def test_reasoning_step_defaults(self) -> None:
        step = ReasoningStep()
        assert step.step_number == 0
        assert step.action == ""
        assert step.tool_used is None


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.trust_relationship_mapper.tools import (
            TrustRelationshipMapperToolkit,
        )

        return TrustRelationshipMapperToolkit()

    @pytest.mark.asyncio
    async def test_discover_trust_boundaries_no_client(self, toolkit) -> None:
        result = await toolkit.discover_trust_boundaries("tenant-1")
        # Without identity_sources client, returns empty list
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_map_federation(self, toolkit) -> None:
        boundaries = [
            TrustBoundary(
                id="tb-1",
                trust_type=TrustType.FEDERATION,
                source_domain="corp.example.com",
                target_domain="partner.example.com",
                protocol="saml",
            )
        ]
        result = await toolkit.map_federation(boundaries)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_analyze_delegation_chains(self, toolkit) -> None:
        boundaries = [
            TrustBoundary(
                id="tb-1",
                trust_type=TrustType.DELEGATION,
                source_domain="admin",
                target_domain="app-service",
            )
        ]
        result = await toolkit.analyze_delegation_chains(boundaries)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_detect_trust_abuse(self, toolkit) -> None:
        boundaries = [TrustBoundary(id="tb-1")]
        federations = [FederationMapping(id="fm-1")]
        chains = [DelegationChain(id="dc-1")]
        result = await toolkit.detect_trust_abuse(boundaries, federations, chains)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_assess_trust_risk(self, toolkit) -> None:
        boundaries = [TrustBoundary(id="tb-1")]
        abuses = [TrustAbuse(id="ta-1", trust_boundary_id="tb-1")]
        result = await toolkit.assess_trust_risk(boundaries, abuses)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.trust_relationship_mapper.graph import (
            create_trust_relationship_mapper_graph,
        )

        graph = create_trust_relationship_mapper_graph()
        compiled = graph.compile()
        assert compiled is not None

    def test_has_boundaries_routes_to_federation(self) -> None:
        from shieldops.agents.trust_relationship_mapper.graph import _has_boundaries

        state = TrustRelationshipMapperState(
            trust_boundaries=[TrustBoundary(id="tb-1")],
        )
        assert _has_boundaries(state) == "map_federation"

    def test_has_boundaries_routes_to_report_empty(self) -> None:
        from shieldops.agents.trust_relationship_mapper.graph import _has_boundaries

        state = TrustRelationshipMapperState()
        assert _has_boundaries(state) == "generate_report"

    def test_has_abuses_routes_to_assess(self) -> None:
        from shieldops.agents.trust_relationship_mapper.graph import _has_abuses

        state = TrustRelationshipMapperState()
        assert _has_abuses(state) == "assess_risk"
