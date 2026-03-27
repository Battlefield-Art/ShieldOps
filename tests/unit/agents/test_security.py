"""Tests for shieldops.agents.security."""

from __future__ import annotations

from shieldops.agents.security.models import (
    SecurityScanState,
)


class TestModels:
    def test_state_defaults(self):
        s = SecurityScanState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.security.graph import (
            create_security_graph,
        )

        sg = create_security_graph()
        assert sg.compile() is not None
