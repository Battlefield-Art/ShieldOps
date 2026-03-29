"""Tests for alert_enrichment_engine."""

from __future__ import annotations

from shieldops.agents.alert_enrichment_engine.models import (
    AlertEnrichmentEngineState,
    AlertPriority,
    EnrichmentSource,
    EnrichmentStage,
)


class TestEnums:
    def test_alertpriority(self) -> None:
        assert AlertPriority.P1_CRITICAL == "p1_critical"
        assert len(AlertPriority) >= 3

    def test_enrichmentsource(self) -> None:
        assert EnrichmentSource.THREAT_INTEL == "threat_intel"
        assert len(EnrichmentSource) >= 3

    def test_enrichmentstage(self) -> None:
        assert EnrichmentStage.INGEST_ALERT == "ingest_alert"
        assert len(EnrichmentStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = AlertEnrichmentEngineState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = AlertEnrichmentEngineState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
