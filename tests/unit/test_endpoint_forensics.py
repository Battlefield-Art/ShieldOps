"""Unit tests for endpoint_forensics."""

from __future__ import annotations

from shieldops.agents.endpoint_forensics.models import (
    ArtifactType,
    EndpointForensicsState,
    FindingSeverity,
    ForensicsStage,
)


class TestEnums:
    def test_artifacttype(self) -> None:
        assert ArtifactType.MEMORY_DUMP == "memory_dump"
        assert len(ArtifactType) >= 3

    def test_findingseverity(self) -> None:
        assert FindingSeverity.CRITICAL == "critical"
        assert len(FindingSeverity) >= 3

    def test_forensicsstage(self) -> None:
        assert ForensicsStage.COLLECT_ARTIFACTS == "collect_artifacts"
        assert len(ForensicsStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = EndpointForensicsState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = EndpointForensicsState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
