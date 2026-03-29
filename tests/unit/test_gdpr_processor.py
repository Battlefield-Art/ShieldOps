"""Tests for gdpr_processor."""

from __future__ import annotations

from shieldops.agents.gdpr_processor.models import (
    GDPRProcessorState,
    GDPRStage,
    ProcessingBasis,
    RequestType,
)


class TestEnums:
    def test_gdprstage(self) -> None:
        assert GDPRStage.INTAKE == "intake"
        assert len(GDPRStage) >= 3

    def test_processingbasis(self) -> None:
        assert ProcessingBasis.CONSENT == "consent"
        assert len(ProcessingBasis) >= 3

    def test_requesttype(self) -> None:
        assert RequestType.ACCESS == "access"
        assert len(RequestType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = GDPRProcessorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = GDPRProcessorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
