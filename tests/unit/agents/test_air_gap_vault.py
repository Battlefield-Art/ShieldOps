"""Tests for shieldops.agents.air_gap_vault."""

from __future__ import annotations

from shieldops.agents.air_gap_vault.models import (
    AirGapVaultState,
)


class TestModels:
    def test_state_defaults(self):
        s = AirGapVaultState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.air_gap_vault.graph import (
            create_air_gap_vault_graph,
        )

        sg = create_air_gap_vault_graph()
        assert sg.compile() is not None
