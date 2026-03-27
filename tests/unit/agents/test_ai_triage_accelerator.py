"""Tests for shieldops.agents.ai_triage_accelerator."""

from __future__ import annotations

from shieldops.agents.ai_triage_accelerator.models import (
    AITriageAcceleratorState,
)


class TestModels:
    def test_state_defaults(self):
        s = AITriageAcceleratorState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.ai_triage_accelerator.graph import (
            create_ai_triage_accelerator_graph,
        )

        sg = create_ai_triage_accelerator_graph()
        assert sg.compile() is not None
