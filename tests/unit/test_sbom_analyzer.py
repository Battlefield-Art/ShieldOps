"""Tests for sbom_analyzer."""

from __future__ import annotations

from shieldops.agents.sbom_analyzer.models import (
    AnalysisStage,
    ComponentRisk,
    SbomAnalyzerState,
    SBOMFormat,
)


class TestEnums:
    def test_analysisstage(self) -> None:
        assert AnalysisStage.PARSE_SBOM == "parse_sbom"
        assert len(AnalysisStage) >= 3

    def test_componentrisk(self) -> None:
        assert ComponentRisk.CRITICAL == "critical"
        assert len(ComponentRisk) >= 3

    def test_sbomformat(self) -> None:
        assert SBOMFormat.SPDX == "spdx"
        assert len(SBOMFormat) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SbomAnalyzerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SbomAnalyzerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
