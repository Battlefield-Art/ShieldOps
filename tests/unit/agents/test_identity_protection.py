"""Tests for shieldops.agents.identity_protection — multi-provider identity threat detection."""

from __future__ import annotations

import pytest

from shieldops.agents.identity_protection.models import (
    AttackPattern,
    ContainmentVerification,
    IdentityProtectionState,
    IdentitySignal,
    IdentitySource,
    IdentityThreat,
    ProtectionStage,
    ReasoningStep,
    ThreatDetection,
    ThreatResponse,
)


def _state(**kw) -> IdentityProtectionState:
    return IdentityProtectionState(**kw)


class TestEnums:
    def test_protection_stage_values(self):
        assert ProtectionStage.COLLECT_SIGNALS == "collect_identity_signals"
        assert ProtectionStage.DETECT_THREATS == "detect_threats"
        assert ProtectionStage.ANALYZE_PATTERNS == "analyze_attack_patterns"
        assert ProtectionStage.RESPOND == "respond_to_threats"
        assert ProtectionStage.VERIFY == "verify_containment"
        assert ProtectionStage.REPORT == "report"

    def test_identity_threat_values(self):
        assert IdentityThreat.CREDENTIAL_THEFT == "credential_theft"
        assert IdentityThreat.BRUTE_FORCE == "brute_force"
        assert IdentityThreat.PRIVILEGE_ESCALATION == "privilege_escalation"
        assert IdentityThreat.IMPOSSIBLE_TRAVEL == "impossible_travel"
        assert IdentityThreat.MFA_BYPASS == "mfa_bypass"
        assert IdentityThreat.TOKEN_THEFT == "token_theft"  # noqa: S105
        assert IdentityThreat.SESSION_HIJACK == "session_hijack"

    def test_identity_source_values(self):
        assert IdentitySource.OKTA == "okta"
        assert IdentitySource.ENTRA_ID == "entra_id"
        assert IdentitySource.AWS_IAM == "aws_iam"
        assert IdentitySource.GCP_IAM == "gcp_iam"
        assert IdentitySource.K8S_RBAC == "k8s_rbac"
        assert IdentitySource.AI_AGENT_REGISTRY == "ai_agent_registry"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.tenant_id == ""
        assert s.providers == [
            "okta",
            "entra_id",
            "aws_iam",
            "gcp_iam",
            "k8s_rbac",
            "ai_agent_registry",
        ]
        assert s.time_window_minutes == 60
        assert s.scope == {}
        assert s.signals_collected == []
        assert s.threats_detected == []
        assert s.attack_patterns == []
        assert s.responses_executed == []
        assert s.containment_verified == []
        assert s.identities_protected == []
        assert s.reasoning_chain == []
        assert s.current_step == "init"
        assert s.session_start is None
        assert s.session_duration_ms == 0
        assert s.error == ""

    def test_state_with_custom_providers(self):
        s = _state(providers=["okta", "entra_id"])
        assert s.providers == ["okta", "entra_id"]

    def test_identity_signal_required_fields(self):
        sig = IdentitySignal(signal_id="sig-1")
        assert sig.signal_id == "sig-1"
        assert sig.source == ""
        assert sig.identity_type == "human"
        assert sig.risk_score == 0.0
        assert sig.metadata == {}

    def test_threat_detection_required_fields(self):
        td = ThreatDetection(detection_id="det-1")
        assert td.detection_id == "det-1"
        assert td.threat_type == ""
        assert td.confidence == 0.0
        assert td.severity == "medium"
        assert td.evidence == []

    def test_attack_pattern_required_fields(self):
        ap = AttackPattern(pattern_id="pat-1")
        assert ap.pattern_id == "pat-1"
        assert ap.pattern_type == ""
        assert ap.identities_involved == []
        assert ap.risk_score == 0.0

    def test_threat_response_required_fields(self):
        tr = ThreatResponse(response_id="resp-1")
        assert tr.response_id == "resp-1"
        assert tr.status == "pending"
        assert tr.rollback_available is True
        assert tr.executed_at is None

    def test_containment_verification_required_fields(self):
        cv = ContainmentVerification(verification_id="ver-1")
        assert cv.verification_id == "ver-1"
        assert cv.is_contained is False
        assert cv.residual_risk == 0.0
        assert cv.verification_checks == []

    def test_reasoning_step_required_fields(self):
        step = ReasoningStep(
            step_number=1,
            action="collect",
            input_summary="in",
            output_summary="out",
            duration_ms=100,
        )
        assert step.step_number == 1
        assert step.duration_ms == 100
        assert step.tool_used is None


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.identity_protection.tools import IdentityProtectionToolkit

        return IdentityProtectionToolkit()

    @pytest.mark.asyncio
    async def test_collect_signals(self, toolkit):
        result = await toolkit.collect_signals(tenant_id="t-01", providers=["okta", "entra_id"])
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_detect_impossible_travel(self, toolkit):
        signals = [
            {"identity_id": "user-1", "geo_location": "US", "timestamp": "2026-01-01T00:00:00Z"},
            {"identity_id": "user-1", "geo_location": "RU", "timestamp": "2026-01-01T00:05:00Z"},
        ]
        result = await toolkit.detect_impossible_travel(signals)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_disable_account(self, toolkit):
        result = await toolkit.disable_account(identity_id="user-1", provider="okta")
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_verify_containment(self, toolkit):
        result = await toolkit.verify_containment(
            identity_id="user-1", provider="okta", action_type="disable_account"
        )
        assert isinstance(result, dict)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.identity_protection.graph import create_identity_protection_graph

        sg = create_identity_protection_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.identity_protection.graph import create_identity_protection_graph

        sg = create_identity_protection_graph()
        compiled = sg.compile()
        assert compiled is not None
