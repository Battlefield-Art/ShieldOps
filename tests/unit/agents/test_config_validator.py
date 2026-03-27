"""Tests for shieldops.agents.config_validator."""

from __future__ import annotations

from shieldops.agents.config_validator.models import (
    ConfigValidatorState,
)


class TestModels:
    def test_state_defaults(self):
        s = ConfigValidatorState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.config_validator.graph import (
            create_config_validator_graph,
        )

        sg = create_config_validator_graph()
        assert sg.compile() is not None
