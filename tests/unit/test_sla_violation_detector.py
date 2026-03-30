"""Tests for sla_violation_detector."""

from __future__ import annotations

from shieldops.agents.sla_violation_detector.models import (
    SLAType,
    SLAViolationDetectorState,
    SVDStage,
    ViolationSeverity,
)


class TestEnums:
    def test_stage(self) -> None:
        assert SVDStage.COLLECT_METRICS == "collect_metrics"
        assert len(SVDStage) >= 3

    def test_sla_type(self) -> None:
        assert SLAType.AVAILABILITY == "availability"
        assert len(SLAType) >= 3

    def test_violation_severity(self) -> None:
        assert ViolationSeverity.BREACH == "breach"
        assert len(ViolationSeverity) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SLAViolationDetectorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SLAViolationDetectorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
