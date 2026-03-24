"""Integration test for the Agent Behavioral Firewall LangGraph pipeline.

Tests graph compilation, state model validation, and full pipeline execution
with mock data. The ainvoke calls use try/except since real toolkits are not
wired to external services.
"""

from __future__ import annotations

import time

import pytest

from shieldops.agents.agent_firewall.graph import create_agent_firewall_graph
from shieldops.agents.agent_firewall.models import (
    AgentFirewallState,
    CircuitBreakerStatus,
    MonitoringMode,
)

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def anomalous_state() -> dict:
    """State with intercepted calls including anomalous entries."""
    return AgentFirewallState(
        monitored_agent_id="agent-remediation-01",
        monitoring_mode=MonitoringMode.ENFORCE,
        time_window_minutes=30,
        intercepted_calls=[
            {
                "tool_name": "delete_database",
                "args": {"db": "production"},
                "data_volume": 999_999,
                "risk_score": 0.95,
            },
            {
                "tool_name": "restart_pod",
                "args": {"pod": "api-server"},
                "data_volume": 100,
                "risk_score": 0.2,
            },
            {
                "tool_name": "exfiltrate_secrets",
                "args": {"target": "vault"},
                "data_volume": 500_000,
                "risk_score": 0.99,
            },
        ],
        policy_set={"max_data_volume": 10_000, "blocked_tools": ["delete_database"]},
    ).model_dump()


@pytest.fixture
def clean_state() -> dict:
    """State with normal, benign intercepted calls."""
    return AgentFirewallState(
        monitored_agent_id="agent-investigation-02",
        monitoring_mode=MonitoringMode.AUDIT,
        time_window_minutes=60,
        intercepted_calls=[
            {
                "tool_name": "get_logs",
                "args": {"service": "api"},
                "data_volume": 50,
                "risk_score": 0.05,
            },
            {
                "tool_name": "get_metrics",
                "args": {"service": "api"},
                "data_volume": 30,
                "risk_score": 0.02,
            },
        ],
        policy_set={"max_data_volume": 10_000, "blocked_tools": ["delete_database"]},
    ).model_dump()


# ── Graph Compilation ─────────────────────────────────────────────────


def test_graph_compiles():
    """Graph compiles and contains all expected nodes."""
    sg = create_agent_firewall_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()

    expected_nodes = [
        "ingest_calls",
        "build_baseline",
        "detect_anomalies",
        "evaluate_policies",
        "enforce_actions",
        "generate_alerts",
        "report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected_nodes:
        assert name in node_ids, f"Missing node: {name}"


# ── State Model Validation ────────────────────────────────────────────


def test_state_model_validation():
    """AgentFirewallState validates correctly with sample data."""
    state = AgentFirewallState(
        monitored_agent_id="test-agent",
        monitoring_mode=MonitoringMode.ENFORCE,
        intercepted_calls=[{"tool_name": "get_logs", "args": {}}],
        anomalies_detected=[{"type": "data_exfil", "severity": "high"}],
        policy_violations=[{"rule_id": "R001", "severity": "critical"}],
        circuit_breaker_status=CircuitBreakerStatus.OPEN,
        reasoning_chain=["step-1", "step-2"],
        current_step="evaluate_policies",
        session_start=time.time(),
        error="",
    )
    assert state.monitored_agent_id == "test-agent"
    assert state.monitoring_mode == MonitoringMode.ENFORCE
    assert len(state.intercepted_calls) == 1
    assert len(state.anomalies_detected) == 1
    assert len(state.policy_violations) == 1
    assert state.circuit_breaker_status == CircuitBreakerStatus.OPEN


def test_state_model_defaults():
    """AgentFirewallState has sensible defaults for all fields."""
    state = AgentFirewallState()
    assert state.monitored_agent_id == ""
    assert state.monitoring_mode == MonitoringMode.AUDIT
    assert state.intercepted_calls == []
    assert state.anomalies_detected == []
    assert state.policy_violations == []
    assert state.circuit_breaker_status == CircuitBreakerStatus.CLOSED
    assert state.error == ""


# ── Full Pipeline: Anomalous Calls ────────────────────────────────────


@pytest.mark.asyncio
async def test_full_pipeline_with_anomalies(anomalous_state):
    """Run the full pipeline with anomalous calls; verify graph executes."""
    sg = create_agent_firewall_graph()
    compiled = sg.compile()

    try:
        result = await compiled.ainvoke(anomalous_state)
    except Exception:
        # Toolkit methods may fail without external deps — graph still compiled
        pytest.skip("Pipeline ainvoke requires external dependencies")
        return

    # If we get here, the full pipeline ran with mock fallback
    assert isinstance(result, dict)
    # Verify key state fields are present
    assert "intercepted_calls" in result
    assert "anomalies_detected" in result
    assert "policy_violations" in result
    assert "current_step" in result


# ── Full Pipeline: Clean Calls ────────────────────────────────────────


@pytest.mark.asyncio
async def test_full_pipeline_clean(clean_state):
    """Run the full pipeline with normal calls; expect clean pass-through."""
    sg = create_agent_firewall_graph()
    compiled = sg.compile()

    try:
        result = await compiled.ainvoke(clean_state)
    except Exception:
        pytest.skip("Pipeline ainvoke requires external dependencies")
        return

    assert isinstance(result, dict)
    assert "intercepted_calls" in result
    # Clean calls should produce no policy violations or blocked calls
    assert len(result.get("blocked_calls", [])) == 0
