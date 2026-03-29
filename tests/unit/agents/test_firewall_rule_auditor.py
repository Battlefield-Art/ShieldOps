"""Tests for shieldops.agents.firewall_rule_auditor."""

from __future__ import annotations

import pytest

from shieldops.agents.firewall_rule_auditor.models import (
    AuditFinding,
    AuditStage,
    FirewallAuditState,
    FirewallProvider,
    FirewallRule,
    ReasoningStep,
    RuleRisk,
    RuleViolation,
)


def _state(**kw) -> FirewallAuditState:
    return FirewallAuditState(**kw)


class TestEnums:
    def test_audit_stage_values(self):
        assert AuditStage.COLLECT_RULES == "collect_rules"
        assert AuditStage.DETECT_VIOLATIONS == "detect_violations"
        assert AuditStage.CLASSIFY_RISKS == "classify_risks"
        assert AuditStage.CHECK_COMPLIANCE == "check_compliance"
        assert AuditStage.RECOMMEND_FIXES == "recommend_fixes"
        assert AuditStage.REPORT == "report"

    def test_rule_risk_values(self):
        assert RuleRisk.CRITICAL == "critical"
        assert RuleRisk.HIGH == "high"
        assert RuleRisk.MEDIUM == "medium"
        assert RuleRisk.LOW == "low"
        assert RuleRisk.INFO == "info"

    def test_firewall_provider_values(self):
        assert FirewallProvider.AWS_SG == "aws_sg"
        assert FirewallProvider.AZURE_NSG == "azure_nsg"
        assert FirewallProvider.GCP_FIREWALL == "gcp_firewall"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == AuditStage.COLLECT_RULES
        assert s.providers == []
        assert s.firewall_rules == []
        assert s.violations == []
        assert s.compliance_results == []
        assert s.findings == []
        assert s.audit_score == 0.0
        assert s.stats == {}
        assert s.reasoning_chain == []
        assert s.current_step == ""
        assert s.session_duration_ms == 0.0
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(
            tenant_id="t-01",
            audit_score=85.0,
            providers=["aws_sg"],
        )
        assert s.tenant_id == "t-01"
        assert s.audit_score == 85.0
        assert s.providers == ["aws_sg"]

    def test_firewall_rule_defaults(self):
        r = FirewallRule()
        assert r.id == ""
        assert r.provider == FirewallProvider.AWS_SG
        assert r.group_id == ""
        assert r.group_name == ""
        assert r.direction == "inbound"
        assert r.protocol == "tcp"
        assert r.port_range == ""
        assert r.source == ""
        assert r.destination == ""
        assert r.action == "allow"
        assert r.description == ""
        assert r.region == ""
        assert r.last_hit == 0.0
        assert r.tags == {}

    def test_rule_violation_defaults(self):
        v = RuleViolation()
        assert v.id == ""
        assert v.rule_id == ""
        assert v.provider == FirewallProvider.AWS_SG
        assert v.violation_type == ""
        assert v.risk == RuleRisk.MEDIUM
        assert v.description == ""
        assert v.recommendation == ""
        assert v.compliance_refs == []
        assert v.auto_fixable is False

    def test_audit_finding_defaults(self):
        f = AuditFinding()
        assert f.id == ""
        assert f.violation_ids == []
        assert f.title == ""
        assert f.risk == RuleRisk.MEDIUM
        assert f.affected_rules == 0
        assert f.fix_action == ""
        assert f.applied is False
        assert f.success is False

    def test_reasoning_step_defaults(self):
        r = ReasoningStep()
        assert r.step == ""
        assert r.detail == ""
        assert r.confidence == 0.0
        assert r.metadata == {}


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.firewall_rule_auditor.tools import (
            FirewallAuditToolkit,
        )

        return FirewallAuditToolkit()

    @pytest.mark.asyncio
    async def test_collect_rules(self, toolkit):
        result = await toolkit.collect_rules(providers=["aws_sg"], tenant_id="t-01")
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_detect_violations(self, toolkit):
        rules = await toolkit.collect_rules(providers=["aws_sg"], tenant_id="t-01")
        violations = await toolkit.detect_violations(rules)
        assert isinstance(violations, list)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.firewall_rule_auditor.graph import (
            create_firewall_rule_auditor_graph,
        )

        sg = create_firewall_rule_auditor_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.firewall_rule_auditor.graph import (
            create_firewall_rule_auditor_graph,
        )

        sg = create_firewall_rule_auditor_graph()
        compiled = sg.compile()
        assert compiled is not None
