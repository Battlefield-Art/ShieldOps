"""Tests for shieldops.agents.agent_firewall."""

from __future__ import annotations

from shieldops.agents.agent_firewall.models import (
    AgentFirewallState,
    CallAction,
    CircuitBreakerStatus,
    MonitoringMode,
)


class TestEnums:
    def test_monitoringmode_audit(self):
        assert MonitoringMode.AUDIT == "audit"

    def test_monitoringmode_enforce(self):
        assert MonitoringMode.ENFORCE == "enforce"

    def test_circuitbreakerstatus_closed(self):
        assert CircuitBreakerStatus.CLOSED == "closed"

    def test_circuitbreakerstatus_open(self):
        assert CircuitBreakerStatus.OPEN == "open"

    def test_circuitbreakerstatus_half_open(self):
        assert CircuitBreakerStatus.HALF_OPEN == "half_open"

    def test_callaction_allowed(self):
        assert CallAction.ALLOWED == "allowed"

    def test_callaction_blocked(self):
        assert CallAction.BLOCKED == "blocked"

    def test_callaction_flagged(self):
        assert CallAction.FLAGGED == "flagged"


class TestModels:
    def test_state_defaults(self):
        s = AgentFirewallState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.agent_firewall.graph import (
            create_agent_firewall_graph,
        )

        sg = create_agent_firewall_graph()
        assert sg.compile() is not None
