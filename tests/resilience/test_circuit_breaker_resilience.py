"""Resilience tests for the circuit breaker (AgentKillSwitch) and FirewallKillSwitchBridge."""

from __future__ import annotations

from shieldops.security.agent_behavioral_firewall import (
    AgentBehavioralFirewall,
    FirewallAction,
)
from shieldops.security.agent_kill_switch import (
    AgentKillSwitch,
    CircuitBreakerConfig,
    CircuitState,
    TripReason,
)
from shieldops.security.firewall_kill_switch_bridge import (
    EscalationConfig,
    EscalationLevel,
    FirewallKillSwitchBridge,
)

# ---------------------------------------------------------------------------
# Circuit breaker core
# ---------------------------------------------------------------------------


class TestCircuitBreakerResilience:
    """Verify kill-switch circuit breaker under failure conditions."""

    def test_circuit_trips_on_high_risk(self) -> None:
        ks = AgentKillSwitch()
        event = ks.trip("agent-x", reason=TripReason.BEHAVIORAL_ANOMALY, risk_score=0.95)
        assert event.new_state == CircuitState.OPEN
        assert ks.get_state("agent-x") == CircuitState.OPEN

    def test_circuit_recovers_via_reset(self) -> None:
        ks = AgentKillSwitch()
        ks.trip("agent-x")
        ev1 = ks.reset("agent-x")
        assert ev1.new_state == CircuitState.HALF_OPEN
        ev2 = ks.reset("agent-x")
        assert ev2.new_state == CircuitState.CLOSED

    def test_multiple_agents_independent(self) -> None:
        ks = AgentKillSwitch()
        ks.trip("agent-1")
        assert ks.get_state("agent-1") == CircuitState.OPEN
        assert ks.get_state("agent-2") == CircuitState.CLOSED

    def test_auto_trip_above_threshold(self) -> None:
        ks = AgentKillSwitch()
        ks.configure("agent-a", CircuitBreakerConfig(agent_id="agent-a", auto_trip_threshold=0.85))
        tripped = ks.check_auto_trip("agent-a", current_risk_score=0.9)
        assert tripped is True
        assert ks.get_state("agent-a") == CircuitState.OPEN

    def test_auto_trip_below_threshold(self) -> None:
        ks = AgentKillSwitch()
        ks.configure("agent-b", CircuitBreakerConfig(agent_id="agent-b", auto_trip_threshold=0.85))
        tripped = ks.check_auto_trip("agent-b", current_risk_score=0.5)
        assert tripped is False
        assert ks.get_state("agent-b") == CircuitState.CLOSED

    def test_double_trip_idempotent(self) -> None:
        ks = AgentKillSwitch()
        ks.trip("agent-d", risk_score=0.9)
        ks.trip("agent-d", risk_score=0.95)
        assert ks.get_state("agent-d") == CircuitState.OPEN
        # Two events recorded, no crash
        assert len(ks._events) == 2

    def test_reset_closed_no_crash(self) -> None:
        ks = AgentKillSwitch()
        # Reset an agent that was never tripped (already CLOSED)
        event = ks.reset("agent-clean")
        assert event.new_state == CircuitState.CLOSED
        assert ks.get_state("agent-clean") == CircuitState.CLOSED

    def test_list_open_circuits(self) -> None:
        ks = AgentKillSwitch()
        for i in range(3):
            ks.trip(f"agent-{i}")
        open_circuits = ks.list_open_circuits()
        agent_ids = {c["agent_id"] for c in open_circuits}
        assert agent_ids == {"agent-0", "agent-1", "agent-2"}

    def test_report_under_load(self) -> None:
        ks = AgentKillSwitch()
        for i in range(50):
            ks.trip(f"load-agent-{i}", risk_score=0.8 + (i % 10) * 0.01)
        report = ks.generate_kill_switch_report()
        assert report.total_events == 50
        assert report.agents_currently_open == 50

    def test_bridge_escalation(self) -> None:
        """Send increasing risk through the bridge and verify escalation climbs."""
        firewall = AgentBehavioralFirewall()
        _kill_switch = AgentKillSwitch()  # noqa: F841
        bridge = FirewallKillSwitchBridge(
            config=EscalationConfig(
                monitor_threshold=0.2,
                warn_threshold=0.4,
                restrict_threshold=0.6,
                kill_threshold=0.8,
                min_anomalies_to_escalate=3,
                window_minutes=10,
            ),
        )

        # Record escalating firewall events so get_agent_risk_summary returns rising risk
        risk_levels = [0.3, 0.5, 0.7, 0.9, 0.95]
        for risk in risk_levels:
            firewall.record_event(
                "agent-e", "dangerous_tool", action=FirewallAction.FLAG, risk_score=risk
            )
            # Also feed the bridge anomaly tracker so anomaly count grows
            bridge.on_anomaly_detected("agent-e", "rate_spike", risk)

        # After 5 anomalies at high risk the level should have escalated past MONITOR
        level = bridge.get_escalation_level("agent-e")
        assert level in (EscalationLevel.RESTRICT, EscalationLevel.KILL)
