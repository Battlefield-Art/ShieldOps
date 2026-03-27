"""Tests for shieldops.agents.adversarial_validation."""

from __future__ import annotations

from shieldops.agents.adversarial_validation.models import (
    AdversarialValidationState,
)


class TestModels:
    def test_state_defaults(self):
        s = AdversarialValidationState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.adversarial_validation.graph import (
            create_adversarial_validation_graph,
        )

        sg = create_adversarial_validation_graph()
        assert sg.compile() is not None
