"""Tests for shieldops.agents.compliance_auditor."""

from __future__ import annotations

from shieldops.agents.compliance_auditor.models import (
    AuditStage,
    ComplianceAuditorState,
    ComplianceFramework,
    ControlStatus,
)


class TestEnums:
    def test_auditstage_scan(self):
        assert AuditStage.SCAN == "scan"

    def test_auditstage_collect_evidence(self):
        assert AuditStage.COLLECT_EVIDENCE == "collect_evidence"

    def test_auditstage_analyze_gaps(self):
        assert AuditStage.ANALYZE_GAPS == "analyze_gaps"

    def test_auditstage_generate_report(self):
        assert AuditStage.GENERATE_REPORT == "generate_report"

    def test_complianceframework_soc2(self):
        assert ComplianceFramework.SOC2 == "soc2"

    def test_complianceframework_pci_dss(self):
        assert ComplianceFramework.PCI_DSS == "pci_dss"

    def test_complianceframework_hipaa(self):
        assert ComplianceFramework.HIPAA == "hipaa"

    def test_complianceframework_gdpr(self):
        assert ComplianceFramework.GDPR == "gdpr"

    def test_controlstatus_compliant(self):
        assert ControlStatus.COMPLIANT == "compliant"

    def test_controlstatus_non_compliant(self):
        assert ControlStatus.NON_COMPLIANT == "non_compliant"

    def test_controlstatus_partial(self):
        assert ControlStatus.PARTIAL == "partial"

    def test_controlstatus_not_applicable(self):
        assert ControlStatus.NOT_APPLICABLE == "not_applicable"


class TestModels:
    def test_state_defaults(self):
        s = ComplianceAuditorState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.compliance_auditor.graph import (
            create_compliance_auditor_graph,
        )

        sg = create_compliance_auditor_graph()
        assert sg.compile() is not None
