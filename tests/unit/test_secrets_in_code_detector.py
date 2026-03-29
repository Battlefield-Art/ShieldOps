"""Unit tests for secrets_in_code_detector."""

from __future__ import annotations

from shieldops.agents.secrets_in_code_detector.models import (
    DetectionStage,
    ExposureRisk,
    SecretsInCodeDetectorState,
    SecretType,
)


class TestEnums:
    def test_detectionstage(self) -> None:
        assert DetectionStage.DISCOVER_REPOSITORIES == "discover_repositories"
        assert len(DetectionStage) >= 3

    def test_exposurerisk(self) -> None:
        assert ExposureRisk.CRITICAL == "critical"
        assert len(ExposureRisk) >= 3

    def test_secrettype(self) -> None:
        assert SecretType.API_KEY == "api_key"
        assert len(SecretType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SecretsInCodeDetectorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SecretsInCodeDetectorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
