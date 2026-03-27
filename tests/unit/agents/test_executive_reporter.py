"""Tests for executive_reporter."""

from __future__ import annotations

from shieldops.agents.executive_reporter.models import (
    ExecutiveReporterState,
)


class TestModels:
    def test_state_defaults(self):
        s = ExecutiveReporterState(tenant_id="t")
        assert s.error == ""


class TestGraph:
    def test_compiles(self):
        from shieldops.agents.executive_reporter.graph import create_executive_reporter_graph

        assert create_executive_reporter_graph().compile() is not None
