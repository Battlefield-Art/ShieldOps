"""Tests for attack_readiness_assessor."""

from __future__ import annotations

from shieldops.agents.attack_readiness_assessor.models import (
    AttackReadinessAssessorState,
)


class TestModels:
    def test_state_defaults(self):
        s = AttackReadinessAssessorState(tenant_id="t")
        assert s.error == ""


class TestGraph:
    def test_compiles(self):
        from shieldops.agents.attack_readiness_assessor.graph import (
            create_attack_readiness_assessor_graph,
        )

        assert create_attack_readiness_assessor_graph().compile() is not None
