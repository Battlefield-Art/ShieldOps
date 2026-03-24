"""Tests for AgentBehavioralFirewall engine."""

import pytest

from shieldops.security.agent_behavioral_firewall import (
    AgentBehavioralFirewall,
    FirewallAction,
    FirewallReport,
)


@pytest.fixture
def engine():
    return AgentBehavioralFirewall(max_records=50, default_rate_limit=60.0)


def test_record_event(engine):
    rec = engine.record_event("agent-1", "kubectl_exec", action=FirewallAction.ALLOW)
    assert rec.agent_id == "agent-1"
    assert rec.tool_name == "kubectl_exec"
    assert rec.action_taken == FirewallAction.ALLOW
    assert len(engine._records) == 1


def test_build_baseline(engine):
    for _ in range(10):
        engine.record_event("agent-1", "read_logs")
    profile = engine.build_baseline("agent-1", window_hours=24)
    assert profile.agent_id == "agent-1"
    assert profile.sample_count == 10
    assert "read_logs" in profile.normal_tools
    assert profile.normal_rate_per_minute > 0


def test_evaluate_call_normal(engine):
    for _ in range(5):
        engine.record_event("agent-1", "read_logs")
    engine.build_baseline("agent-1")
    result = engine.evaluate_call("agent-1", "read_logs")
    assert result["action"] == FirewallAction.ALLOW.value


def test_evaluate_call_anomalous(engine):
    for _ in range(5):
        engine.record_event("agent-1", "read_logs")
    engine.build_baseline("agent-1")
    result = engine.evaluate_call("agent-1", "delete_database", data_volume=2_000_000.0)
    assert result["risk_score"] > 0.3
    assert "unusual_tool:delete_database" in result["reasons"]


def test_evaluate_call_no_baseline(engine):
    result = engine.evaluate_call("unknown-agent", "read_logs")
    assert result["action"] == FirewallAction.ALLOW.value
    assert "no_baseline" in result["reasons"]


def test_detect_rate_anomaly(engine):
    result = engine.detect_rate_anomaly("agent-1", window_minutes=1)
    assert "anomaly" in result
    assert result["agent_id"] == "agent-1"


def test_detect_scope_violation(engine):
    result = engine.detect_scope_violation(
        "agent-1", "rm_rf", allowed_tools=["read_logs", "get_pods"]
    )
    assert result["violation"] is True

    result2 = engine.detect_scope_violation(
        "agent-1", "read_logs", allowed_tools=["read_logs", "get_pods"]
    )
    assert result2["violation"] is False


def test_generate_report(engine):
    engine.record_event("agent-1", "tool_a", action=FirewallAction.BLOCK, risk_score=0.9)
    engine.record_event("agent-2", "tool_b", action=FirewallAction.ALLOW)
    report = engine.generate_report()
    assert isinstance(report, FirewallReport)
    assert report.total_events == 2
    assert report.blocked_count == 1


def test_generate_report_empty(engine):
    report = engine.generate_report()
    assert report.total_events == 0
    assert "All agent tool calls within normal parameters" in report.recommendations


def test_get_stats(engine):
    engine.record_event("agent-1", "tool_a")
    stats = engine.get_stats()
    assert "total_events" in stats
    assert "total_profiles" in stats
    assert "action_distribution" in stats
    assert "unique_agents" in stats
    assert stats["total_events"] == 1


def test_clear_data(engine):
    engine.record_event("agent-1", "tool_a")
    engine.build_baseline("agent-1")
    engine.clear_data()
    assert len(engine._records) == 0
    assert len(engine._profiles) == 0


def test_ring_buffer_eviction(engine):
    for i in range(60):
        engine.record_event(f"agent-{i}", "tool")
    assert len(engine._records) == 50
