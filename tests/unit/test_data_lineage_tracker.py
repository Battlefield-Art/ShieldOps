"""Tests for data_lineage_tracker."""

from __future__ import annotations

from shieldops.agents.data_lineage_tracker.models import (
    DataLineageTrackerState,
    DataStage,
    LineageStatus,
)


class TestEnums:
    def test_datastage(self) -> None:
        assert DataStage.INGESTION == "ingestion"
        assert len(DataStage) >= 3

    def test_lineagestatus(self) -> None:
        assert LineageStatus.VERIFIED == "verified"
        assert len(LineageStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = DataLineageTrackerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = DataLineageTrackerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
