"""Tests for shieldops.agents.digital_twin_security."""

from __future__ import annotations

from shieldops.agents.digital_twin_security.models import (
    DigitalTwinSecurityState,
)


class TestModels:
    def test_state_defaults(self):
        s = DigitalTwinSecurityState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.digital_twin_security.graph import (
            create_digital_twin_security_graph,
        )

        sg = create_digital_twin_security_graph()
        assert sg.compile() is not None
