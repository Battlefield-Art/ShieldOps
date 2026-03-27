"""Tests for shieldops.agents.xdr."""

from __future__ import annotations

from shieldops.agents.xdr.models import (
    XDRState,
)


class TestModels:
    def test_state_defaults(self):
        s = XDRState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.xdr.graph import (
            create_xdr_graph,
        )

        sg = create_xdr_graph()
        assert sg.compile() is not None
