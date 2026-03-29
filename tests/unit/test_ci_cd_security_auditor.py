"""Tests for ci_cd_security_auditor."""

from __future__ import annotations

from shieldops.agents.ci_cd_security_auditor.models import (
    AuditStage,
    CiCdSecurityAuditorState,
    CIProvider,
    PipelineRisk,
)


class TestEnums:
    def test_auditstage(self) -> None:
        assert AuditStage.MAP_PIPELINES == "map_pipelines"
        assert len(AuditStage) >= 3

    def test_ciprovider(self) -> None:
        assert CIProvider.GITHUB_ACTIONS == "github_actions"
        assert len(CIProvider) >= 3

    def test_pipelinerisk(self) -> None:
        assert PipelineRisk.CRITICAL == "critical"
        assert len(PipelineRisk) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = CiCdSecurityAuditorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = CiCdSecurityAuditorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
