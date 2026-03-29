"""Tests for ai_bias_scanner."""

from __future__ import annotations

from shieldops.agents.ai_bias_scanner.models import (
    AIBiasScannerState,
    BiasMetric,
    FairnessLevel,
    ScanStage,
)


class TestEnums:
    def test_biasmetric(self) -> None:
        assert BiasMetric.DEMOGRAPHIC_PARITY == "demographic_parity"
        assert len(BiasMetric) >= 3

    def test_fairnesslevel(self) -> None:
        assert FairnessLevel.FAIR == "fair"
        assert len(FairnessLevel) >= 3

    def test_scanstage(self) -> None:
        assert ScanStage.COLLECT_DATA == "collect_data"
        assert len(ScanStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = AIBiasScannerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = AIBiasScannerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
