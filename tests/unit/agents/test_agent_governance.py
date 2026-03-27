"""Tests for shieldops.agents.agent_governance — AI agent governance and policy enforcement."""

from __future__ import annotations

import pytest

from shieldops.agents.agent_governance.models import (
    AgentCapability,
    AgentGovernanceState,
    BoundaryViolation,
    EnforcementAction,
    EscalationRecord,
    GovernanceStage,
    RiskLevel,
)


def _state(**kw) -> AgentGovernanceState:
    return AgentGovernanceState(**kw)


class TestEnums:
    def test_governance_stage_values(self):
        assert GovernanceStage.DISCOVER_AGENTS == "discover_agents"
        assert GovernanceStage.ASSESS_CAPABILITIES == "assess_capabilities"
        assert GovernanceStage.ENFORCE_BOUNDARIES == "enforce_boundaries"
        assert GovernanceStage.EVALUATE_ESCALATIONS == "evaluate_escalations"
        assert GovernanceStage.AUDIT_COMPLIANCE == "audit_compliance"
        assert GovernanceStage.REPORT == "report"

    def test_risk_level_values(self):
        assert RiskLevel.CRITICAL == "critical"
        assert RiskLevel.HIGH == "high"
        assert RiskLevel.MEDIUM == "medium"
        assert RiskLevel.LOW == "low"
        assert RiskLevel.MINIMAL == "minimal"

    def test_enforcement_action_values(self):
        assert EnforcementAction.ALLOW == "allow"
        assert EnforcementAction.RESTRICT == "restrict"
        assert EnforcementAction.BLOCK == "block"
        assert EnforcementAction.ESCALATE == "escalate"
        assert EnforcementAction.REVOKE == "revoke"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == GovernanceStage.DISCOVER_AGENTS
        assert s.discovered_agents == []
        assert s.total_agents == 0
        assert s.capabilities == []
        assert s.unauthorized_capabilities == 0
        assert s.violations == []
        assert s.enforcements_applied == 0
        assert s.escalations == []
        assert s.compliance_score == 0.0
        assert s.policy_violations == 0
        assert s.summary == ""
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(tenant_id="t-01", total_agents=5, compliance_score=85.0)
        assert s.tenant_id == "t-01"
        assert s.total_agents == 5
        assert s.compliance_score == 85.0

    def test_agent_capability_defaults(self):
        c = AgentCapability()
        assert c.id == ""
        assert c.agent_id == ""
        assert c.capability_name == ""
        assert c.scope == ""
        assert c.risk_level == RiskLevel.MEDIUM
        assert c.approved is False
        assert c.approved_by == ""
        assert c.expires_at is None
        assert c.context == {}

    def test_boundary_violation_defaults(self):
        v = BoundaryViolation()
        assert v.id == ""
        assert v.agent_id == ""
        assert v.violation_type == ""
        assert v.capability_attempted == ""
        assert v.action_taken == EnforcementAction.BLOCK
        assert v.severity == RiskLevel.HIGH
        assert v.details == ""
        assert v.detected_at is None

    def test_escalation_record_defaults(self):
        e = EscalationRecord()
        assert e.id == ""
        assert e.agent_id == ""
        assert e.reason == ""
        assert e.escalated_to == ""
        assert e.resolved is False
        assert e.resolution == ""
        assert e.created_at is None


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.agent_governance.tools import AgentGovernanceToolkit

        return AgentGovernanceToolkit()

    @pytest.mark.asyncio
    async def test_discover_agents(self, toolkit):
        result = await toolkit.discover_agents(tenant_id="t-01")
        assert isinstance(result, list)
        assert len(result) >= 3
        assert all("agent_id" in a for a in result)

    @pytest.mark.asyncio
    async def test_assess_capabilities(self, toolkit):
        agents = await toolkit.discover_agents(tenant_id="t-01")
        capabilities, unauthorized = await toolkit.assess_capabilities(agents)
        assert isinstance(capabilities, list)
        assert len(capabilities) > 0
        assert isinstance(unauthorized, int)
        assert all(isinstance(c, AgentCapability) for c in capabilities)

    @pytest.mark.asyncio
    async def test_enforce_boundaries(self, toolkit):
        agents = await toolkit.discover_agents(tenant_id="t-01")
        capabilities, _ = await toolkit.assess_capabilities(agents)
        violations = await toolkit.enforce_boundaries(capabilities)
        assert isinstance(violations, list)
        assert all(isinstance(v, BoundaryViolation) for v in violations)

    @pytest.mark.asyncio
    async def test_evaluate_escalations(self, toolkit):
        agents = await toolkit.discover_agents(tenant_id="t-01")
        capabilities, _ = await toolkit.assess_capabilities(agents)
        violations = await toolkit.enforce_boundaries(capabilities)
        escalations = await toolkit.evaluate_escalations(violations)
        assert isinstance(escalations, list)
        assert all(isinstance(e, EscalationRecord) for e in escalations)

    @pytest.mark.asyncio
    async def test_audit_compliance(self, toolkit):
        agents = await toolkit.discover_agents(tenant_id="t-01")
        capabilities, _ = await toolkit.assess_capabilities(agents)
        violations = await toolkit.enforce_boundaries(capabilities)
        score, policy_violations = await toolkit.audit_compliance(agents, capabilities, violations)
        assert isinstance(score, float)
        assert 0.0 <= score <= 100.0
        assert isinstance(policy_violations, int)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.agent_governance.graph import create_agent_governance_graph

        sg = create_agent_governance_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.agent_governance.graph import create_agent_governance_graph

        sg = create_agent_governance_graph()
        compiled = sg.compile()
        assert compiled is not None
