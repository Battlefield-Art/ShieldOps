"""Tests for postmortem_generator."""

from __future__ import annotations

from shieldops.agents.postmortem_generator.models import (
    ActionPriority,
    IncidentCategory,
    PMGStage,
    PostmortemGeneratorState,
)


class TestEnums:
    def test_stage(self) -> None:
        assert PMGStage.COLLECT_TIMELINE == "collect_timeline"
        assert len(PMGStage) >= 3

    def test_incident_category(self) -> None:
        assert IncidentCategory.AVAILABILITY == "availability"
        assert len(IncidentCategory) >= 3

    def test_action_priority(self) -> None:
        assert ActionPriority.P0_IMMEDIATE == "p0_immediate"
        assert len(ActionPriority) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = PostmortemGeneratorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = PostmortemGeneratorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
