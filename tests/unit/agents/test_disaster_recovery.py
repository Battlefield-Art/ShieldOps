"""Tests for shieldops.agents.disaster_recovery."""

from __future__ import annotations

from shieldops.agents.disaster_recovery.models import (
    DisasterRecoveryState,
)


class TestModels:
    def test_state_defaults(self):
        s = DisasterRecoveryState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.disaster_recovery.graph import (
            create_disaster_recovery_graph,
        )

        sg = create_disaster_recovery_graph()
        assert sg.compile() is not None
