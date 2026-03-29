"""Tests for shieldops.agents.serverless_security."""

from __future__ import annotations

from shieldops.agents.serverless_security.models import (
    ServerlessPlatform,
    ServerlessSecurityState,
    ServerlessStage,
    ServerlessThreatType,
)


class TestEnums:
    def test_stage_discover(self):
        assert ServerlessStage.DISCOVER_FUNCTIONS == "discover_functions"

    def test_stage_permissions(self):
        assert ServerlessStage.ANALYZE_PERMISSIONS == "analyze_permissions"

    def test_stage_dependencies(self):
        assert ServerlessStage.SCAN_DEPENDENCIES == "scan_dependencies"

    def test_stage_threats(self):
        assert ServerlessStage.DETECT_THREATS == "detect_threats"

    def test_stage_risk(self):
        assert ServerlessStage.ASSESS_RISK == "assess_risk"

    def test_stage_report(self):
        assert ServerlessStage.REPORT == "report"

    def test_platform_lambda(self):
        assert ServerlessPlatform.AWS_LAMBDA == "aws_lambda"

    def test_platform_gcf(self):
        assert ServerlessPlatform.GCP_CLOUD_FUNCTIONS == "gcp_cloud_functions"

    def test_platform_azure(self):
        assert ServerlessPlatform.AZURE_FUNCTIONS == "azure_functions"

    def test_threat_cold_start(self):
        assert ServerlessThreatType.COLD_START_ATTACK == "cold_start_attack"

    def test_threat_injection(self):
        assert ServerlessThreatType.EVENT_INJECTION == "event_injection"

    def test_threat_exfil(self):
        assert ServerlessThreatType.DATA_EXFILTRATION == "data_exfiltration"


class TestState:
    def test_state_defaults(self):
        s = ServerlessSecurityState()
        assert s.error == ""

    def test_state_request_id(self):
        s = ServerlessSecurityState()
        assert s.request_id == ""

    def test_state_stage(self):
        s = ServerlessSecurityState()
        assert s.stage == ServerlessStage.DISCOVER_FUNCTIONS


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.serverless_security.graph import (
            create_serverless_security_graph,
        )

        sg = create_serverless_security_graph()
        assert sg.compile() is not None
