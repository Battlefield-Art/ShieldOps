"""Tests for data_masking_engine."""

from __future__ import annotations

from shieldops.agents.data_masking_engine.models import (
    DataMaskingEngineState,
    MaskingStage,
    MaskingTechnique,
    SensitivityLevel,
)


class TestEnums:
    def test_maskingstage(self) -> None:
        assert MaskingStage.DISCOVER_DATA == "discover_data"
        assert len(MaskingStage) >= 3

    def test_maskingtechnique(self) -> None:
        assert MaskingTechnique.REDACTION == "redaction"
        assert len(MaskingTechnique) >= 3

    def test_sensitivitylevel(self) -> None:
        assert SensitivityLevel.PUBLIC == "public"
        assert len(SensitivityLevel) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = DataMaskingEngineState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = DataMaskingEngineState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
