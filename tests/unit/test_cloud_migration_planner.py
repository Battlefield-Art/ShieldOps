"""Tests for cloud_migration_planner."""

from __future__ import annotations

from shieldops.agents.cloud_migration_planner.models import (
    CloudMigrationPlannerState,
    CMPStage,
    MigrationStrategy,
    ReadinessLevel,
)


class TestEnums:
    def test_stage(self) -> None:
        assert CMPStage.ASSESS_WORKLOADS == "assess_workloads"
        assert len(CMPStage) >= 3

    def test_migration_strategy(self) -> None:
        assert MigrationStrategy.REHOST == "rehost"
        assert len(MigrationStrategy) >= 3

    def test_readiness_level(self) -> None:
        assert ReadinessLevel.READY == "ready"
        assert len(ReadinessLevel) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = CloudMigrationPlannerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = CloudMigrationPlannerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
