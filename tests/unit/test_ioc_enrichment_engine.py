"""Tests for ioc_enrichment_engine."""

from __future__ import annotations

from shieldops.agents.ioc_enrichment_engine.models import (
    EnrichmentConfidence,
    IEEStage,
    IOCEnrichmentEngineState,
    IOCType,
)


class TestEnums:
    def test_stage(self) -> None:
        assert IEEStage.COLLECT_IOCS == "collect_iocs"
        assert len(IEEStage) >= 3

    def test_ioc_type(self) -> None:
        assert IOCType.IP_ADDRESS == "ip_address"
        assert len(IOCType) >= 3

    def test_enrichment_confidence(self) -> None:
        assert EnrichmentConfidence.CONFIRMED == "confirmed"
        assert len(EnrichmentConfidence) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = IOCEnrichmentEngineState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = IOCEnrichmentEngineState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
