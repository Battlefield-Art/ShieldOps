"""Tests for shieldops.agents.compliance_reporter."""

from __future__ import annotations

from shieldops.agents.compliance_reporter.models import (
    ComplianceFramework,
    ComplianceReporterState,
    ControlStatus,
    ReporterStage,
)


class TestEnums:
    def test_reporterstage_select_framework(self):
        assert ReporterStage.SELECT_FRAMEWORK == "select_framework"

    def test_reporterstage_collect_evidence(self):
        assert ReporterStage.COLLECT_EVIDENCE == "collect_evidence"

    def test_reporterstage_assess_controls(self):
        assert ReporterStage.ASSESS_CONTROLS == "assess_controls"

    def test_reporterstage_generate_report(self):
        assert ReporterStage.GENERATE_REPORT == "generate_report"

    def test_complianceframework_soc2_type2(self):
        assert ComplianceFramework.SOC2_TYPE2 == "soc2_type2"

    def test_complianceframework_pci_dss_4(self):
        assert ComplianceFramework.PCI_DSS_4 == "pci_dss_4"

    def test_complianceframework_hipaa(self):
        assert ComplianceFramework.HIPAA == "hipaa"

    def test_complianceframework_fedramp_moderate(self):
        assert ComplianceFramework.FEDRAMP_MODERATE == "fedramp_moderate"

    def test_controlstatus_compliant(self):
        assert ControlStatus.COMPLIANT == "compliant"

    def test_controlstatus_partially_compliant(self):
        assert ControlStatus.PARTIALLY_COMPLIANT == "partially_compliant"

    def test_controlstatus_non_compliant(self):
        assert ControlStatus.NON_COMPLIANT == "non_compliant"

    def test_controlstatus_not_applicable(self):
        assert ControlStatus.NOT_APPLICABLE == "not_applicable"


class TestModels:
    def test_state_defaults(self):
        s = ComplianceReporterState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.compliance_reporter.graph import (
            create_compliance_reporter_graph,
        )

        sg = create_compliance_reporter_graph()
        assert sg.compile() is not None
