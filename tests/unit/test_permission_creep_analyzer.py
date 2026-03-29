"""Tests for permission_creep_analyzer."""

from __future__ import annotations

from shieldops.agents.permission_creep_analyzer.models import (
    AnalysisStage,
    CreepType,
    PermissionCreepAnalyzerState,
    SeverityLevel,
)


class TestEnums:
    def test_analysisstage(self) -> None:
        assert AnalysisStage.COLLECT_PERMISSIONS == "collect_permissions"
        assert len(AnalysisStage) >= 3

    def test_creeptype(self) -> None:
        assert CreepType.UNUSED_PERMISSION == "unused_permission"
        assert len(CreepType) >= 3

    def test_severitylevel(self) -> None:
        assert SeverityLevel.CRITICAL == "critical"
        assert len(SeverityLevel) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = PermissionCreepAnalyzerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = PermissionCreepAnalyzerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
