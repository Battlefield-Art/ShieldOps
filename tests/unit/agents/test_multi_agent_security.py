"""Tests for shieldops.agents.multi_agent_security."""

from __future__ import annotations

import pytest

from shieldops.agents.multi_agent_security.models import (
    AgentInteraction,
    CommunicationVerification,
    InteractionAnomaly,
    InteractionVerdict,
    MultiAgentSecurityState,
    ReasoningStep,
    SecurityStage,
    TrustChain,
    TrustLevel,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_security_stage_values(self) -> None:
        assert SecurityStage.DISCOVER == "discover_interactions"
        assert SecurityStage.MAP_TRUST == "map_trust_chains"
        assert SecurityStage.VERIFY == "verify_communications"
        assert SecurityStage.DETECT == "detect_anomalies"
        assert SecurityStage.ENFORCE == "enforce_policies"
        assert SecurityStage.REPORT == "report"
        assert len(SecurityStage) == 6

    def test_trust_level_values(self) -> None:
        assert TrustLevel.VERIFIED == "verified"
        assert TrustLevel.PROVISIONAL == "provisional"
        assert TrustLevel.UNTRUSTED == "untrusted"
        assert TrustLevel.COMPROMISED == "compromised"
        assert len(TrustLevel) == 4

    def test_interaction_verdict_values(self) -> None:
        assert InteractionVerdict.SAFE == "safe"
        assert InteractionVerdict.SUSPICIOUS == "suspicious"
        assert InteractionVerdict.BLOCKED == "blocked"
        assert InteractionVerdict.QUARANTINED == "quarantined"
        assert len(InteractionVerdict) == 4


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_state_defaults(self) -> None:
        state = MultiAgentSecurityState()
        assert state.tenant_id == ""
        assert state.scan_scope == {}
        assert state.agent_registry == []
        assert state.interactions == []
        assert state.trust_chains == []
        assert state.verification_results == []
        assert state.anomalies == []
        assert state.enforcement_actions == []
        assert state.blocked_interactions == 0
        assert state.quarantined_agents == []
        assert state.report == {}
        assert state.risk_score == 0.0
        assert state.threats_detected is False
        assert state.current_step == "init"
        assert state.error == ""

    def test_agent_interaction_defaults(self) -> None:
        ix = AgentInteraction()
        assert ix.interaction_id == ""
        assert ix.tools_requested == []
        assert ix.data_labels == []
        assert ix.verdict == InteractionVerdict.SAFE

    def test_trust_chain_defaults(self) -> None:
        tc = TrustChain()
        assert tc.trust_level == TrustLevel.PROVISIONAL
        assert tc.delegation_depth == 0
        assert tc.privilege_escalation_detected is False

    def test_communication_verification_defaults(self) -> None:
        cv = CommunicationVerification()
        assert cv.hash_valid is True
        assert cv.identity_verified is True
        assert cv.replay_detected is False
        assert cv.impersonation_risk == 0.0

    def test_interaction_anomaly_defaults(self) -> None:
        ia = InteractionAnomaly()
        assert ia.severity == "low"
        assert ia.confidence == 0.0
        assert ia.evidence == []

    def test_reasoning_step_requires_fields(self) -> None:
        step = ReasoningStep(
            step_number=1,
            action="discover",
            input_summary="in",
            output_summary="out",
        )
        assert step.step_number == 1
        assert step.tool_used is None


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.multi_agent_security.tools import MultiAgentSecurityToolkit

        return MultiAgentSecurityToolkit()

    @pytest.mark.asyncio
    async def test_discover_interactions_returns_simulated(self, toolkit) -> None:
        result = await toolkit.discover_interactions({}, ["agent_a"])
        assert isinstance(result, list)
        assert len(result) >= 1
        assert "interaction_id" in result[0]
        assert "source_agent" in result[0]

    @pytest.mark.asyncio
    async def test_map_trust_chains_builds_chains(self, toolkit) -> None:
        interactions = await toolkit.discover_interactions({}, [])
        chains = await toolkit.map_trust_chains(interactions)
        assert isinstance(chains, list)
        assert len(chains) >= 1
        assert "chain_id" in chains[0]
        assert "trust_level" in chains[0]

    @pytest.mark.asyncio
    async def test_map_trust_chains_detects_priv_escalation(self, toolkit) -> None:
        interactions = [
            {
                "source_agent": "evil_agent",
                "target_agent": "remediation_agent",
                "tools_requested": ["drop_table"],
                "data_labels": [],
            }
        ]
        chains = await toolkit.map_trust_chains(interactions)
        compromised = [c for c in chains if c.get("privilege_escalation_detected")]
        assert len(compromised) >= 1

    @pytest.mark.asyncio
    async def test_verify_communications_detects_unknown(self, toolkit) -> None:
        interactions = [
            {
                "interaction_id": "ix-1",
                "payload_hash": "abc123",
                "source_agent": "unknown_agent_x",
                "channel": "external_api",
            }
        ]
        results = await toolkit.verify_communications(interactions)
        assert len(results) == 1
        assert results[0]["identity_verified"] is False
        assert results[0]["impersonation_risk"] > 0.0

    @pytest.mark.asyncio
    async def test_verify_communications_detects_replay(self, toolkit) -> None:
        interactions = [
            {
                "interaction_id": "ix-1",
                "payload_hash": "same_hash",
                "source_agent": "agent_a",
                "channel": "internal_bus",
            },
            {
                "interaction_id": "ix-2",
                "payload_hash": "same_hash",
                "source_agent": "agent_b",
                "channel": "internal_bus",
            },
        ]
        results = await toolkit.verify_communications(interactions)
        replays = [r for r in results if r["replay_detected"]]
        assert len(replays) == 1

    @pytest.mark.asyncio
    async def test_detect_anomalies_finds_impersonation(self, toolkit) -> None:
        verifications = [
            {
                "interaction_id": "ix-1",
                "identity_verified": False,
                "impersonation_risk": 0.85,
                "tampering_indicators": ["unregistered_agent_identity"],
                "replay_detected": False,
            }
        ]
        anomalies = await toolkit.detect_anomalies([], [], verifications)
        assert len(anomalies) >= 1
        assert anomalies[0]["anomaly_type"] == "agent_impersonation"

    @pytest.mark.asyncio
    async def test_detect_anomalies_unauthorized_tools(self, toolkit) -> None:
        interactions = [
            {
                "source_agent": "bad_agent",
                "target_agent": "remediation",
                "tools_requested": ["delete_bucket"],
                "data_labels": [],
                "channel": "internal_bus",
            }
        ]
        anomalies = await toolkit.detect_anomalies(interactions, [], [])
        tool_anomalies = [a for a in anomalies if a["anomaly_type"] == "unauthorised_tool_proxy"]
        assert len(tool_anomalies) >= 1

    @pytest.mark.asyncio
    async def test_enforce_policies_blocks_critical(self, toolkit) -> None:
        anomalies = [
            {
                "anomaly_id": "a1",
                "severity": "critical",
                "anomaly_type": "privilege_escalation_via_delegation",
                "source_agent": "bad_agent",
            }
        ]
        result = await toolkit.enforce_policies(anomalies, [])
        assert result["blocked_interactions"] >= 1
        assert "bad_agent" in result["quarantined_agents"]

    @pytest.mark.asyncio
    async def test_enforce_policies_alerts_low_severity(self, toolkit) -> None:
        anomalies = [
            {
                "anomaly_id": "a1",
                "severity": "low",
                "anomaly_type": "minor_issue",
                "source_agent": "agent_x",
            }
        ]
        result = await toolkit.enforce_policies(anomalies, [])
        assert result["blocked_interactions"] == 0
        assert result["actions"][0]["action"] == "alert"


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.multi_agent_security.graph import (
            create_multi_agent_security_graph,
        )

        graph = create_multi_agent_security_graph()
        compiled = graph.compile()
        assert compiled is not None

    def test_graph_with_no_clients(self) -> None:
        from shieldops.agents.multi_agent_security.graph import build_graph
        from shieldops.agents.multi_agent_security.tools import MultiAgentSecurityToolkit

        toolkit = MultiAgentSecurityToolkit()
        graph = build_graph(toolkit)
        compiled = graph.compile()
        assert compiled is not None
