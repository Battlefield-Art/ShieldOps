"""Tests for shieldops.agents.file_integrity_monitor."""

from __future__ import annotations

from shieldops.agents.file_integrity_monitor.models import (
    FileIntegrityMonitorState,
)


class TestModels:
    def test_state_defaults(self):
        s = FileIntegrityMonitorState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.file_integrity_monitor.graph import (
            create_file_integrity_monitor_graph,
        )

        sg = create_file_integrity_monitor_graph()
        assert sg.compile() is not None
