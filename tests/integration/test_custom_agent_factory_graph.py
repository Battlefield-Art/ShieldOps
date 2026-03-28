"""Tests for custom_agent_factory."""

from __future__ import annotations

from shieldops.agents.custom_agent_factory.models import CustomAgentFactoryState


def test_graph_compiles():
    from shieldops.agents.custom_agent_factory.graph import create_custom_agent_factory_graph

    assert create_custom_agent_factory_graph().compile() is not None


def test_state_defaults():
    s = CustomAgentFactoryState(tenant_id="t")
    assert s.error == ""
