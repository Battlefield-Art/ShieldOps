"""Tests for shieldops.agents.multi_cloud_compliance."""

from __future__ import annotations

from shieldops.agents.multi_cloud_compliance.models import (
    ComplianceFramework,
    ComplianceStage,
    ComplianceStatus,
    MultiCloudComplianceState,
)


class TestEnums:
    def test_stage_collect(self):
        assert ComplianceStage.COLLECT_CONFIGS == "collect_configs"

    def test_stage_evaluate(self):
        assert ComplianceStage.EVALUATE_BENCHMARKS == "evaluate_benchmarks"

    def test_stage_gaps(self):
        assert ComplianceStage.IDENTIFY_GAPS == "identify_gaps"

    def test_stage_remediation(self):
        assert ComplianceStage.GENERATE_REMEDIATION == "generate_remediation"

    def test_stage_track(self):
        assert ComplianceStage.TRACK_PROGRESS == "track_progress"

    def test_stage_report(self):
        assert ComplianceStage.REPORT == "report"

    def test_framework_cis_aws(self):
        assert ComplianceFramework.CIS_AWS == "cis_aws"

    def test_framework_cis_gcp(self):
        assert ComplianceFramework.CIS_GCP == "cis_gcp"

    def test_framework_cis_azure(self):
        assert ComplianceFramework.CIS_AZURE == "cis_azure"

    def test_status_compliant(self):
        assert ComplianceStatus.COMPLIANT == "compliant"

    def test_status_non_compliant(self):
        assert ComplianceStatus.NON_COMPLIANT == "non_compliant"

    def test_status_partial(self):
        assert ComplianceStatus.PARTIALLY_COMPLIANT == "partially_compliant"


class TestState:
    def test_state_defaults(self):
        s = MultiCloudComplianceState()
        assert s.error == ""

    def test_state_request_id(self):
        s = MultiCloudComplianceState()
        assert s.request_id == ""

    def test_state_stage(self):
        s = MultiCloudComplianceState()
        assert s.stage == ComplianceStage.COLLECT_CONFIGS


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.multi_cloud_compliance.graph import (
            create_multi_cloud_compliance_graph,
        )

        sg = create_multi_cloud_compliance_graph()
        assert sg.compile() is not None
