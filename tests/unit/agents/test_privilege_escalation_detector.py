"""Tests for shieldops.agents.privilege_escalation_detector."""

from __future__ import annotations

import pytest

from shieldops.agents.privilege_escalation_detector.models import (
    EscalationEvent,
    EscalationFinding,
    EscalationStage,
    EscalationType,
    PrivilegeEscalationDetectorState,
    ResponseAction,
    RiskAssessment,
    ThreatSeverity,
)
from shieldops.agents.privilege_escalation_detector.tools import (
    PrivilegeEscalationToolkit,
)

# -------------------------------------------------------------------
# Enum tests
# -------------------------------------------------------------------


class TestEnums:
    def test_stage_collect_events(self):
        assert EscalationStage.COLLECT_EVENTS == "collect_events"

    def test_stage_classify_escalations(self):
        assert EscalationStage.CLASSIFY_ESCALATIONS == "classify_escalations"

    def test_stage_correlate_identities(self):
        assert EscalationStage.CORRELATE_IDENTITIES == "correlate_identities"

    def test_stage_assess_risk(self):
        assert EscalationStage.ASSESS_RISK == "assess_risk"

    def test_stage_respond(self):
        assert EscalationStage.RESPOND == "respond"

    def test_stage_report(self):
        assert EscalationStage.REPORT == "report"

    def test_type_sudo_abuse(self):
        assert EscalationType.SUDO_ABUSE == "sudo_abuse"

    def test_type_role_change(self):
        assert EscalationType.ROLE_CHANGE == "role_change"

    def test_type_iam_policy_modification(self):
        assert EscalationType.IAM_POLICY_MODIFICATION == "iam_policy_modification"

    def test_type_service_account_elevation(self):
        assert EscalationType.SERVICE_ACCOUNT_ELEVATION == "service_account_elevation"

    def test_type_privilege_boundary_bypass(self):
        assert EscalationType.PRIVILEGE_BOUNDARY_BYPASS == "privilege_boundary_bypass"

    def test_type_token_privilege_escalation(self):
        assert EscalationType.TOKEN_PRIVILEGE_ESCALATION == "token_privilege_escalation"  # noqa: S105

    def test_severity_critical(self):
        assert ThreatSeverity.CRITICAL == "critical"

    def test_severity_high(self):
        assert ThreatSeverity.HIGH == "high"

    def test_severity_medium(self):
        assert ThreatSeverity.MEDIUM == "medium"

    def test_severity_low(self):
        assert ThreatSeverity.LOW == "low"

    def test_severity_info(self):
        assert ThreatSeverity.INFO == "info"


# -------------------------------------------------------------------
# Model defaults
# -------------------------------------------------------------------


class TestModels:
    def test_state_defaults(self):
        s = PrivilegeEscalationDetectorState(tenant_id="t-01")
        assert s.error == ""
        assert s.request_id == ""
        assert s.stage == EscalationStage.COLLECT_EVENTS
        assert s.escalation_events == []
        assert s.escalation_findings == []
        assert s.risk_assessments == []
        assert s.response_actions == []
        assert s.reasoning_chain == []

    def test_escalation_event_defaults(self):
        e = EscalationEvent()
        assert e.id == ""
        assert e.principal_id == ""
        assert e.risk_indicators == []

    def test_escalation_finding_defaults(self):
        f = EscalationFinding()
        assert f.id == ""
        assert f.escalation_type == EscalationType.SUDO_ABUSE
        assert f.confidence == 0.0
        assert f.timeline == []

    def test_risk_assessment_defaults(self):
        r = RiskAssessment()
        assert r.severity == ThreatSeverity.LOW
        assert r.affected_resources == []
        assert r.blast_radius == 0

    def test_response_action_defaults(self):
        a = ResponseAction()
        assert a.auto_executed is False
        assert a.success is False


# -------------------------------------------------------------------
# Toolkit tests
# -------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        return PrivilegeEscalationToolkit()

    @pytest.mark.asyncio()
    async def test_collect_generates_synthetic(self, toolkit):
        events = await toolkit.collect_escalation_events(tenant_id="test-tenant")
        assert len(events) == 3
        assert events[0].source_system == "linux"

    @pytest.mark.asyncio()
    async def test_classify_detects_sudo(self, toolkit):
        events = [
            EscalationEvent(
                id=f"e-{i}",
                principal_id="user-1",
                principal_type="user",
                source_system="linux",
                action="sudo_failed",
                target_resource="/usr/bin/passwd",
                timestamp=float(1000 + i),
            )
            for i in range(6)
        ]
        findings = await toolkit.classify_escalations(events)
        sudo_findings = [f for f in findings if f.escalation_type == EscalationType.SUDO_ABUSE]
        assert len(sudo_findings) >= 1

    @pytest.mark.asyncio()
    async def test_classify_detects_role_changes(self, toolkit):
        events = [
            EscalationEvent(
                id=f"e-{i}",
                principal_id="user-admin",
                principal_type="user",
                source_system="aws",
                action="assign_role",
                target_resource="role/Admin",
                timestamp=float(1000 + i * 10),
            )
            for i in range(3)
        ]
        findings = await toolkit.classify_escalations(events)
        role_findings = [f for f in findings if f.escalation_type == EscalationType.ROLE_CHANGE]
        assert len(role_findings) >= 1

    @pytest.mark.asyncio()
    async def test_classify_detects_boundary_bypass(self, toolkit):
        events = [
            EscalationEvent(
                id="e-bypass-1",
                principal_id="attacker",
                principal_type="user",
                source_system="aws",
                action="delete_permission_boundary",
                target_resource="arn:boundary",
                timestamp=1000.0,
            )
        ]
        findings = await toolkit.classify_escalations(events)
        bypass_findings = [
            f for f in findings if f.escalation_type == EscalationType.PRIVILEGE_BOUNDARY_BYPASS
        ]
        assert len(bypass_findings) == 1
        assert bypass_findings[0].confidence == 0.90

    @pytest.mark.asyncio()
    async def test_assess_risk_returns_assessments(self, toolkit):
        finding = EscalationFinding(
            id="f-1",
            escalation_type=EscalationType.SUDO_ABUSE,
            principal_id="user-1",
            confidence=0.92,
            timeline=[
                {
                    "principal_id": "user-1",
                    "target_resource": "/etc/shadow",
                }
            ],
        )
        assessments = await toolkit.assess_risk([finding])
        assert len(assessments) == 1
        assert assessments[0].severity == ThreatSeverity.CRITICAL

    @pytest.mark.asyncio()
    async def test_execute_response_no_engine(self, toolkit):
        finding = EscalationFinding(
            id="f-1",
            confidence=0.95,
        )
        assessment = RiskAssessment(
            finding_id="f-1",
            containment_actions=["Revoke sessions"],
        )
        actions = await toolkit.execute_response([finding], [assessment])
        assert len(actions) == 1
        assert actions[0].auto_executed is False


# -------------------------------------------------------------------
# Graph compilation
# -------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.privilege_escalation_detector.graph import (
            create_privilege_escalation_detector_graph,
        )

        sg = create_privilege_escalation_detector_graph()
        assert sg.compile() is not None
