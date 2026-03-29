"""Tests for shieldops.agents.cloud_audit_logger."""

from __future__ import annotations

from shieldops.agents.cloud_audit_logger.models import (
    AuditEventSeverity,
    AuditLogSource,
    AuditStage,
    CloudAuditLoggerState,
)


class TestEnums:
    def test_stage_ingest(self):
        assert AuditStage.INGEST_LOGS == "ingest_logs"

    def test_stage_parse(self):
        assert AuditStage.PARSE_EVENTS == "parse_events"

    def test_stage_detect(self):
        assert AuditStage.DETECT_ANOMALIES == "detect_anomalies"

    def test_stage_correlate(self):
        assert AuditStage.CORRELATE_ACTIVITY == "correlate_activity"

    def test_stage_assess(self):
        assert AuditStage.ASSESS_RISK == "assess_risk"

    def test_stage_report(self):
        assert AuditStage.REPORT == "report"

    def test_source_cloudtrail(self):
        assert AuditLogSource.CLOUDTRAIL == "cloudtrail"

    def test_source_gcp(self):
        assert AuditLogSource.GCP_AUDIT == "gcp_audit"

    def test_source_azure(self):
        assert AuditLogSource.AZURE_ACTIVITY == "azure_activity"

    def test_severity_critical(self):
        assert AuditEventSeverity.CRITICAL == "critical"

    def test_severity_high(self):
        assert AuditEventSeverity.HIGH == "high"

    def test_severity_medium(self):
        assert AuditEventSeverity.MEDIUM == "medium"


class TestState:
    def test_state_defaults(self):
        s = CloudAuditLoggerState()
        assert s.error == ""

    def test_state_request_id(self):
        s = CloudAuditLoggerState()
        assert s.request_id == ""

    def test_state_stage(self):
        s = CloudAuditLoggerState()
        assert s.stage == AuditStage.INGEST_LOGS


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.cloud_audit_logger.graph import (
            create_cloud_audit_logger_graph,
        )

        sg = create_cloud_audit_logger_graph()
        assert sg.compile() is not None
