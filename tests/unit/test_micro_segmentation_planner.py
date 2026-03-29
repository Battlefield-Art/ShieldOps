"""Tests for micro_segmentation_planner."""

from __future__ import annotations

from shieldops.agents.micro_segmentation_planner.models import (
    MicroSegmentationPlannerState,
    PlanningStage,
    PolicyAction,
    SegmentType,
)


class TestEnums:
    def test_planningstage(self) -> None:
        assert PlanningStage.MAP_TRAFFIC == "map_traffic"
        assert len(PlanningStage) >= 3

    def test_policyaction(self) -> None:
        assert PolicyAction.ALLOW == "allow"
        assert len(PolicyAction) >= 3

    def test_segmenttype(self) -> None:
        assert SegmentType.APPLICATION == "application"
        assert len(SegmentType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = MicroSegmentationPlannerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = MicroSegmentationPlannerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
