"""Tests for resource_rightsizer."""

from __future__ import annotations

from shieldops.agents.resource_rightsizer.models import (
    ResourceCategory,
    ResourceRightsizerState,
    RightsizingAction,
    RRStage,
)


class TestEnums:
    def test_stage(self) -> None:
        assert RRStage.COLLECT_UTILIZATION == "collect_utilization"
        assert len(RRStage) >= 3

    def test_resource_category(self) -> None:
        assert ResourceCategory.EC2_INSTANCE == "ec2_instance"
        assert len(ResourceCategory) >= 3

    def test_rightsizing_action(self) -> None:
        assert RightsizingAction.DOWNSIZE == "downsize"
        assert len(RightsizingAction) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ResourceRightsizerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ResourceRightsizerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
