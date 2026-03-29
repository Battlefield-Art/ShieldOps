"""Tests for artifact_integrity_checker."""

from __future__ import annotations

from shieldops.agents.artifact_integrity_checker.models import (
    ArtifactIntegrityCheckerState,
    ArtifactType,
    CheckStage,
    IntegrityStatus,
)


class TestEnums:
    def test_artifacttype(self) -> None:
        assert ArtifactType.CONTAINER_IMAGE == "container_image"
        assert len(ArtifactType) >= 3

    def test_checkstage(self) -> None:
        assert CheckStage.COLLECT_ARTIFACTS == "collect_artifacts"
        assert len(CheckStage) >= 3

    def test_integritystatus(self) -> None:
        assert IntegrityStatus.VERIFIED == "verified"
        assert len(IntegrityStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ArtifactIntegrityCheckerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ArtifactIntegrityCheckerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
