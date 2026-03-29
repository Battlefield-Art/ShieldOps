"""Tests for threat_correlation_engine."""

from __future__ import annotations

from shieldops.agents.threat_correlation_engine.models import (
    CorrelationConfidence,
    CorrelationStage,
    ThreatCategory,
    ThreatCorrelationEngineState,
)


class TestEnums:
    def test_correlation_stage(self) -> None:
        assert CorrelationStage.COLLECT_EVENTS == "collect_events"
        assert len(CorrelationStage) >= 3

    def test_threat_category(self) -> None:
        assert ThreatCategory.MALWARE == "malware"
        assert len(ThreatCategory) >= 3

    def test_correlation_confidence(self) -> None:
        assert CorrelationConfidence.CONFIRMED == "confirmed"
        assert len(CorrelationConfidence) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ThreatCorrelationEngineState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ThreatCorrelationEngineState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
