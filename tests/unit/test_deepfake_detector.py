"""Tests for deepfake_detector."""

from __future__ import annotations

from shieldops.agents.deepfake_detector.models import (
    AuthenticityVerdict,
    DeepfakeDetectorState,
    DetectionStage,
    MediaType,
)


class TestEnums:
    def test_detection_stage(self) -> None:
        assert DetectionStage.INGEST_MEDIA == "ingest_media"
        assert len(DetectionStage) >= 3

    def test_media_type(self) -> None:
        assert MediaType.IMAGE == "image"
        assert len(MediaType) >= 3

    def test_authenticity_verdict(self) -> None:
        assert AuthenticityVerdict.AUTHENTIC == "authentic"
        assert len(AuthenticityVerdict) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = DeepfakeDetectorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = DeepfakeDetectorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
