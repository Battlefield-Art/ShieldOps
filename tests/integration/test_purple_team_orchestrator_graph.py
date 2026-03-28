"""Tests for purple_team_orchestrator."""

from __future__ import annotations

from shieldops.agents.purple_team_orchestrator.models import PurpleTeamOrchestratorState


def test_graph_compiles():
    from shieldops.agents.purple_team_orchestrator.graph import (
        create_purple_team_orchestrator_graph,
    )

    assert create_purple_team_orchestrator_graph().compile() is not None


def test_state_defaults():
    s = PurpleTeamOrchestratorState(tenant_id="t")
    assert s.error == ""
