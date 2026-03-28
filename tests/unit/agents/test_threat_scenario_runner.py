"""Tests for threat_scenario_runner."""

from __future__ import annotations

from shieldops.agents.threat_scenario_runner.models import ThreatScenarioRunnerState


def test_graph_compiles():
    from shieldops.agents.threat_scenario_runner.graph import create_threat_scenario_runner_graph

    assert create_threat_scenario_runner_graph().compile() is not None


def test_state_defaults():
    s = ThreatScenarioRunnerState(tenant_id="t")
    assert s.error == ""
