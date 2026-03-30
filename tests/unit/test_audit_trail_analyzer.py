"""Tests for audit_trail_analyzer."""

from __future__ import annotations

from shieldops.agents.audit_trail_analyzer.models import (
    ATAStage,
    AuditSource,
    AuditTrailAnalyzerState,
    FindingSeverity,
)


class TestEnums:
    def test_stage(self) -> None:
        assert ATAStage.COLLECT_LOGS == "collect_logs"
        assert len(ATAStage) >= 3

    def test_audit_source(self) -> None:
        assert AuditSource.APPLICATION == "application"
        assert len(AuditSource) >= 3

    def test_finding_severity(self) -> None:
        assert FindingSeverity.CRITICAL == "critical"
        assert len(FindingSeverity) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = AuditTrailAnalyzerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = AuditTrailAnalyzerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
