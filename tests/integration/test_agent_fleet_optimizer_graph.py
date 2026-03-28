"""Tests for agent_fleet_optimizer."""

from __future__ import annotations

from shieldops.agents.agent_fleet_optimizer.models import AgentFleetOptimizerState


def test_graph_compiles():
    from shieldops.agents.agent_fleet_optimizer.graph import create_agent_fleet_optimizer_graph

    assert create_agent_fleet_optimizer_graph().compile() is not None


def test_state_defaults():
    s = AgentFleetOptimizerState(tenant_id="t")
    assert s.error == ""
