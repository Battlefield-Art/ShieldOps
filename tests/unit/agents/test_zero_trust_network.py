"""Tests for shieldops.agents.zero_trust_network."""

from __future__ import annotations

import pytest

from shieldops.agents.zero_trust_network.models import (
    AccessPoint,
    DevicePosture,
    IdentityTrustScore,
    IdentityType,
    PolicyEnforcement,
    SessionMonitor,
    TrustDecision,
    ZeroTrustNetworkState,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_ztna_stage_values(self) -> None:
        from shieldops.agents.zero_trust_network.models import ZTNAStage

        assert ZTNAStage.DISCOVER_ACCESS_POINTS == "discover_access_points"
        assert ZTNAStage.ASSESS_IDENTITY_TRUST == "assess_identity_trust"
        assert ZTNAStage.EVALUATE_DEVICE_POSTURE == "evaluate_device_posture"
        assert ZTNAStage.ENFORCE_POLICIES == "enforce_policies"
        assert ZTNAStage.MONITOR_SESSIONS == "monitor_sessions"
        assert ZTNAStage.REPORT == "report"
        assert len(ZTNAStage) == 6

    def test_identity_type_values(self) -> None:
        assert IdentityType.HUMAN == "human"
        assert IdentityType.SERVICE_ACCOUNT == "service_account"
        assert IdentityType.AI_AGENT == "ai_agent"
        assert IdentityType.API_KEY == "api_key"
        assert IdentityType.MCP_CLIENT == "mcp_client"
        assert len(IdentityType) == 5

    def test_trust_decision_values(self) -> None:
        assert TrustDecision.ALLOW == "allow"
        assert TrustDecision.CHALLENGE == "challenge"
        assert TrustDecision.RESTRICT == "restrict"
        assert TrustDecision.DENY == "deny"
        assert TrustDecision.QUARANTINE == "quarantine"
        assert len(TrustDecision) == 5


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_state_defaults(self) -> None:
        state = ZeroTrustNetworkState()
        assert state.tenant_id == ""
        assert state.scope == "full"
        assert state.identity_filter == ""
        assert state.access_points == []
        assert state.identity_scores == []
        assert state.device_postures == []
        assert state.enforcements == []
        assert state.active_sessions == []
        assert state.zero_trust_score == 0.0
        assert state.denied_count == 0
        assert state.challenged_count == 0
        assert state.quarantined_count == 0
        assert state.error == ""

    def test_access_point_defaults(self) -> None:
        ap = AccessPoint()
        assert ap.access_point_id == ""
        assert ap.exposed is False
        assert ap.risk_score == 0.0
        assert ap.identity_types_allowed == []

    def test_identity_trust_score_defaults(self) -> None:
        its = IdentityTrustScore()
        assert its.identity_type == IdentityType.HUMAN
        assert its.trust_score == 0.0
        assert its.mfa_enabled is False
        assert its.decision == TrustDecision.DENY
        assert its.anomalies == []

    def test_device_posture_defaults(self) -> None:
        dp = DevicePosture()
        assert dp.os_patched is False
        assert dp.encryption_enabled is False
        assert dp.compliant is False
        assert dp.issues == []

    def test_policy_enforcement_defaults(self) -> None:
        pe = PolicyEnforcement()
        assert pe.decision == TrustDecision.DENY
        assert pe.conditions == []

    def test_session_monitor_defaults(self) -> None:
        sm = SessionMonitor()
        assert sm.identity_type == IdentityType.HUMAN
        assert sm.requests_count == 0
        assert sm.anomaly_count == 0
        assert sm.status == "active"


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.zero_trust_network.tools import ZeroTrustNetworkToolkit

        return ZeroTrustNetworkToolkit()

    @pytest.mark.asyncio
    async def test_discover_access_points(self, toolkit) -> None:
        points = await toolkit.discover_access_points("tenant-1")
        assert isinstance(points, list)
        assert len(points) >= 1
        assert all(isinstance(p, AccessPoint) for p in points)

    @pytest.mark.asyncio
    async def test_assess_identity_trust(self, toolkit) -> None:
        result = await toolkit.assess_identity_trust("id-1", IdentityType.HUMAN)
        assert isinstance(result, IdentityTrustScore)
        assert result.identity_id == "id-1"

    @pytest.mark.asyncio
    async def test_evaluate_device_posture(self, toolkit) -> None:
        result = await toolkit.evaluate_device_posture("dev-1", "id-1")
        assert isinstance(result, DevicePosture)
        assert result.device_id == "dev-1"

    @pytest.mark.asyncio
    async def test_enforce_policy(self, toolkit) -> None:
        result = await toolkit.enforce_policy(
            identity_id="id-1",
            access_point_id="ap-1",
            trust_score=0.9,
            device_compliant=True,
        )
        assert isinstance(result, PolicyEnforcement)
        assert result.identity_id == "id-1"

    @pytest.mark.asyncio
    async def test_enforce_policy_low_trust_denies(self, toolkit) -> None:
        result = await toolkit.enforce_policy(
            identity_id="id-1",
            access_point_id="ap-1",
            trust_score=0.1,
            device_compliant=False,
        )
        assert result.decision in (TrustDecision.DENY, TrustDecision.QUARANTINE)

    @pytest.mark.asyncio
    async def test_monitor_session(self, toolkit) -> None:
        result = await toolkit.monitor_session(
            session_id="sess-1",
            identity_id="id-1",
            identity_type=IdentityType.HUMAN,
            access_point_id="ap-1",
        )
        assert isinstance(result, SessionMonitor)
        assert result.session_id == "sess-1"

    @pytest.mark.asyncio
    async def test_get_session_summary(self, toolkit) -> None:
        summary = await toolkit.get_session_summary()
        assert isinstance(summary, dict)


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.zero_trust_network.graph import build_graph
        from shieldops.agents.zero_trust_network.tools import ZeroTrustNetworkToolkit

        toolkit = ZeroTrustNetworkToolkit()
        graph = build_graph(toolkit)
        compiled = graph.compile()
        assert compiled is not None

    def test_create_factory(self) -> None:
        from shieldops.agents.zero_trust_network.graph import create_zero_trust_network_graph

        graph = create_zero_trust_network_graph()
        compiled = graph.compile()
        assert compiled is not None
