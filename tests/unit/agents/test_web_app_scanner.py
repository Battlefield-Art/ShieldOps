"""Tests for shieldops.agents.web_app_scanner."""

from __future__ import annotations

from shieldops.agents.web_app_scanner.models import (
    WebAppScannerState,
)


class TestModels:
    def test_state_defaults(self):
        s = WebAppScannerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.web_app_scanner.graph import (
            create_web_app_scanner_graph,
        )

        sg = create_web_app_scanner_graph()
        assert sg.compile() is not None
