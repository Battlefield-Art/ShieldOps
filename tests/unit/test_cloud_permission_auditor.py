"""Unit tests for cloud_permission_auditor agent models."""

from __future__ import annotations

from shieldops.agents.cloud_permission_auditor.models import (
    CloudPermissionAuditorState,
    CPAStage,
    PermissionScope,
    ViolationType,
)


class TestEnums:
    def test_cpa_stage_values(self) -> None:
        assert CPAStage.COLLECT_PERMISSIONS == "collect_permissions"
        assert CPAStage.DETECT_VIOLATIONS == "detect_violations"
        assert CPAStage.REPORT == "report"

    def test_violation_type(self) -> None:
        assert ViolationType.OVERPRIVILEGED == "overprivileged"
        assert ViolationType.WILDCARD_ACCESS == "wildcard_access"
        assert ViolationType.ESCALATION_PATH == "escalation_path"

    def test_permission_scope(self) -> None:
        assert PermissionScope.ORGANIZATION == "organization"
        assert PermissionScope.RESOURCE == "resource"


class TestState:
    def test_default_state(self) -> None:
        state = CloudPermissionAuditorState()
        assert state.request_id == ""
        assert state.stage == CPAStage.COLLECT_PERMISSIONS
        assert state.error == ""

    def test_state_with_values(self) -> None:
        state = CloudPermissionAuditorState(
            request_id="req-001",
            stage=CPAStage.DETECT_VIOLATIONS,
        )
        assert state.stage == CPAStage.DETECT_VIOLATIONS
