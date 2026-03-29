"""Tests for cloud_audit_logger."""

from __future__ import annotations

from shieldops.agents.cloud_audit_logger.models import (
    AuditEventSeverity,
    AuditLogSource,
    AuditStage,
    CloudAuditLoggerState,
)


class TestEnums:
    def test_auditeventseverity(self) -> None:
        assert AuditEventSeverity.CRITICAL == "critical"
        assert len(AuditEventSeverity) >= 3

    def test_auditlogsource(self) -> None:
        assert AuditLogSource.CLOUDTRAIL == "cloudtrail"
        assert len(AuditLogSource) >= 3

    def test_auditstage(self) -> None:
        assert AuditStage.INGEST_LOGS == "ingest_logs"
        assert len(AuditStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = CloudAuditLoggerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = CloudAuditLoggerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
