"""Tests for security_architecture_reviewer."""

from __future__ import annotations

from shieldops.agents.security_architecture_reviewer.models import (
    ArchitectureLayer,
    FindingSeverity,
    ReviewStage,
    SecurityArchitectureReviewerState,
)


class TestEnums:
    def test_architecturelayer(self) -> None:
        assert ArchitectureLayer.NETWORK == "network"
        assert len(ArchitectureLayer) >= 3

    def test_findingseverity(self) -> None:
        assert FindingSeverity.CRITICAL == "critical"
        assert len(FindingSeverity) >= 3

    def test_reviewstage(self) -> None:
        assert ReviewStage.COLLECT_DESIGN == "collect_design"
        assert len(ReviewStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SecurityArchitectureReviewerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SecurityArchitectureReviewerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
