"""Tests for AgentKillSwitch engine."""

import pytest

from shieldops.security.agent_kill_switch import (
    AgentKillSwitch,
    CircuitBreakerConfig,
    CircuitState,
    KillSwitchReport,
    TripReason,
)


@pytest.fixture
def engine():
    return AgentKillSwitch(max_records=100)


def test_trip(engine):
    event = engine.trip("agent-1", reason=TripReason.POLICY_VIOLATION)
    assert event.new_state == CircuitState.OPEN
    assert event.agent_id == "agent-1"
    assert engine.get_state("agent-1") == CircuitState.OPEN


def test_reset_to_half_open(engine):
    engine.trip("agent-1")
    event = engine.reset("agent-1")
    assert event.new_state == CircuitState.HALF_OPEN
    assert engine.get_state("agent-1") == CircuitState.HALF_OPEN


def test_reset_to_closed(engine):
    engine.trip("agent-1")
    engine.reset("agent-1")  # OPEN -> HALF_OPEN
    event = engine.reset("agent-1")  # HALF_OPEN -> CLOSED
    assert event.new_state == CircuitState.CLOSED
    assert engine.get_state("agent-1") == CircuitState.CLOSED


def test_get_state_default(engine):
    assert engine.get_state("unregistered") == CircuitState.CLOSED


def test_configure(engine):
    config = CircuitBreakerConfig(agent_id="agent-1", auto_trip_threshold=0.7)
    engine.configure("agent-1", config)
    assert "agent-1" in engine._configs
    assert engine._configs["agent-1"].auto_trip_threshold == 0.7


def test_check_auto_trip_below_threshold(engine):
    config = CircuitBreakerConfig(agent_id="agent-1", auto_trip_threshold=0.85)
    engine.configure("agent-1", config)
    tripped = engine.check_auto_trip("agent-1", current_risk_score=0.5)
    assert tripped is False
    assert engine.get_state("agent-1") == CircuitState.CLOSED


def test_check_auto_trip_above_threshold(engine):
    config = CircuitBreakerConfig(agent_id="agent-1", auto_trip_threshold=0.85)
    engine.configure("agent-1", config)
    tripped = engine.check_auto_trip("agent-1", current_risk_score=0.9)
    assert tripped is True
    assert engine.get_state("agent-1") == CircuitState.OPEN


def test_list_open_circuits(engine):
    engine.trip("agent-1")
    engine.trip("agent-2")
    open_circuits = engine.list_open_circuits()
    assert len(open_circuits) == 2
    agent_ids = {c["agent_id"] for c in open_circuits}
    assert "agent-1" in agent_ids
    assert "agent-2" in agent_ids


def test_generate_report(engine):
    engine.trip("agent-1", reason=TripReason.BEHAVIORAL_ANOMALY)
    engine.reset("agent-1")
    engine.reset("agent-1")
    report = engine.generate_kill_switch_report()
    assert isinstance(report, KillSwitchReport)
    assert report.total_events == 3
    assert report.agents_currently_open == 0


def test_get_stats(engine):
    engine.trip("agent-1")
    stats = engine.get_stats()
    assert "total_events" in stats
    assert "total_configured_agents" in stats
    assert "state_distribution" in stats
    assert "unique_agents" in stats
    assert stats["total_events"] == 1


def test_clear_data(engine):
    engine.trip("agent-1")
    engine.configure("agent-1", CircuitBreakerConfig())
    engine.clear_data()
    assert len(engine._events) == 0
    assert len(engine._configs) == 0
    assert len(engine._states) == 0
