"""Tests for shieldops.agents.compliance_scanner."""

from __future__ import annotations

from shieldops.agents.compliance_scanner.models import (
    ComplianceScannerState,
    ComplianceStage,
    ControlStatus,
    FindingSeverity,
)


class TestEnums:
    def test_compliancestage_select_frameworks(self):
        assert ComplianceStage.SELECT_FRAMEWORKS == "select_frameworks"

    def test_compliancestage_scan_controls(self):
        assert ComplianceStage.SCAN_CONTROLS == "scan_controls"

    def test_compliancestage_evaluate_findings(self):
        assert ComplianceStage.EVALUATE_FINDINGS == "evaluate_findings"

    def test_compliancestage_track_remediation(self):
        assert ComplianceStage.TRACK_REMEDIATION == "track_remediation"

    def test_controlstatus_pass(self):
        assert ControlStatus.PASS == "pass"  # noqa: S105

    def test_controlstatus_fail(self):
        assert ControlStatus.FAIL == "fail"

    def test_controlstatus_partial(self):
        assert ControlStatus.PARTIAL == "partial"

    def test_controlstatus_not_applicable(self):
        assert ControlStatus.NOT_APPLICABLE == "not_applicable"

    def test_findingseverity_critical(self):
        assert FindingSeverity.CRITICAL == "critical"

    def test_findingseverity_high(self):
        assert FindingSeverity.HIGH == "high"

    def test_findingseverity_medium(self):
        assert FindingSeverity.MEDIUM == "medium"

    def test_findingseverity_low(self):
        assert FindingSeverity.LOW == "low"


class TestModels:
    def test_state_defaults(self):
        s = ComplianceScannerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.compliance_scanner.graph import (
            create_compliance_scanner_graph,
        )

        sg = create_compliance_scanner_graph()
        assert sg.compile() is not None
