"""Unit tests for compliance_gap_analyzer agent models."""

from __future__ import annotations

from shieldops.agents.compliance_gap_analyzer.models import (
    CGAStage,
    ComplianceGapAnalyzerState,
    GapSeverity,
    RegulatoryDomain,
)


class TestEnums:
    def test_cga_stage_values(self) -> None:
        assert CGAStage.SCAN_POSTURE == "scan_posture"
        assert CGAStage.IDENTIFY_GAPS == "identify_gaps"
        assert CGAStage.REPORT == "report"

    def test_regulatory_domain_values(self) -> None:
        assert RegulatoryDomain.FINANCIAL == "financial"
        assert RegulatoryDomain.HEALTHCARE == "healthcare"
        assert RegulatoryDomain.GOVERNMENT == "government"

    def test_gap_severity_values(self) -> None:
        assert GapSeverity.CRITICAL == "critical"
        assert GapSeverity.HIGH == "high"
        assert GapSeverity.LOW == "low"


class TestState:
    def test_default_state(self) -> None:
        state = ComplianceGapAnalyzerState()
        assert state.request_id == ""
        assert state.stage == CGAStage.SCAN_POSTURE
        assert state.error == ""

    def test_state_with_values(self) -> None:
        state = ComplianceGapAnalyzerState(
            request_id="req-001",
            tenant_id="t-001",
            stage=CGAStage.IDENTIFY_GAPS,
        )
        assert state.request_id == "req-001"
        assert state.stage == CGAStage.IDENTIFY_GAPS
