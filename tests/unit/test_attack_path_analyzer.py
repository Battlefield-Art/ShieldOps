"""Tests for attack_path_analyzer."""

from __future__ import annotations

from shieldops.agents.attack_path_analyzer.models import (
    AnalyzerStage,
    AssetCriticality,
    AttackPathAnalyzerState,
    PathSeverity,
)


class TestEnums:
    def test_analyzer_stage(self) -> None:
        assert AnalyzerStage.DISCOVER_ASSETS == "discover_assets"
        assert len(AnalyzerStage) >= 3

    def test_asset_criticality(self) -> None:
        assert AssetCriticality.CROWN_JEWEL == "crown_jewel"
        assert len(AssetCriticality) >= 3

    def test_path_severity(self) -> None:
        assert PathSeverity.CRITICAL == "critical"
        assert len(PathSeverity) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = AttackPathAnalyzerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = AttackPathAnalyzerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
