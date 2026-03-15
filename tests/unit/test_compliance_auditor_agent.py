"""Tests for the Compliance Auditor agent."""

from __future__ import annotations

import time

import pytest

from shieldops.agents.compliance_auditor import create_compliance_auditor_graph
from shieldops.agents.compliance_auditor.models import (
    AuditStage,
    ComplianceAuditorState,
    ComplianceFramework,
    ControlAssessment,
    ControlStatus,
    EvidenceItem,
    ReasoningStep,
)
from shieldops.agents.compliance_auditor.tools import ComplianceAuditorToolkit
from shieldops.agents.compliance_auditor.nodes import (
    analyze_gaps,
    collect_evidence,
    generate_report,
    scan_infrastructure,
)
from shieldops.agents.compliance_auditor.prompts import (
    SYSTEM_ANALYZE_GAPS,
    SYSTEM_COLLECT_EVIDENCE,
    SYSTEM_GENERATE_REPORT,
    SYSTEM_SCAN,
)
from shieldops.agents.compliance_auditor.runner import ComplianceAuditorRunner


class TestComplianceAuditorModels:
    def test_audit_stage_values(self) -> None:
        assert AuditStage.SCAN == "scan"
        assert AuditStage.COLLECT_EVIDENCE == "collect_evidence"
        assert AuditStage.ANALYZE_GAPS == "analyze_gaps"
        assert AuditStage.GENERATE_REPORT == "generate_report"

    def test_compliance_framework_values(self) -> None:
        assert ComplianceFramework.SOC2 == "soc2"
        assert ComplianceFramework.PCI_DSS == "pci_dss"
        assert ComplianceFramework.HIPAA == "hipaa"
        assert ComplianceFramework.GDPR == "gdpr"
        assert ComplianceFramework.ISO27001 == "iso27001"

    def test_control_status_values(self) -> None:
        assert ControlStatus.COMPLIANT == "compliant"
        assert ControlStatus.NON_COMPLIANT == "non_compliant"
        assert ControlStatus.PARTIAL == "partial"
        assert ControlStatus.NOT_APPLICABLE == "not_applicable"

    def test_control_assessment_defaults(self) -> None:
        assessment = ControlAssessment()
        assert assessment.control_id == ""
        assert assessment.framework == ComplianceFramework.SOC2
        assert assessment.status == ControlStatus.NOT_APPLICABLE
        assert assessment.evidence_refs == []
        assert assessment.gaps == []

    def test_control_assessment_with_values(self) -> None:
        assessment = ControlAssessment(
            control_id="SOC2-CC6.1",
            framework=ComplianceFramework.SOC2,
            description="Access controls",
            status=ControlStatus.COMPLIANT,
            evidence_refs=["ev-001"],
            gaps=[],
        )
        assert assessment.control_id == "SOC2-CC6.1"
        assert assessment.status == ControlStatus.COMPLIANT

    def test_evidence_item_defaults(self) -> None:
        item = EvidenceItem()
        assert item.id == ""
        assert item.source == ""
        assert item.collected_at == 0.0
        assert item.valid_until == 0.0

    def test_reasoning_step_defaults(self) -> None:
        step = ReasoningStep()
        assert step.step == ""
        assert step.detail == ""

    def test_compliance_auditor_state_defaults(self) -> None:
        state = ComplianceAuditorState()
        assert state.stage == AuditStage.SCAN
        assert state.frameworks == []
        assert state.controls_assessed == []
        assert state.evidence_collected == []
        assert state.gaps_found == 0
        assert state.compliance_score == 0.0
        assert state.report == {}
        assert state.error == ""


class TestComplianceAuditorToolkit:
    @pytest.mark.asyncio
    async def test_scan_controls_soc2_mock(self) -> None:
        toolkit = ComplianceAuditorToolkit()
        result = await toolkit.scan_controls("soc2")
        assert len(result) == 5
        assert result[0]["control_id"] == "SOC2-CC6.1"
        assert result[0]["framework"] == "soc2"

    @pytest.mark.asyncio
    async def test_scan_controls_pci_dss_mock(self) -> None:
        toolkit = ComplianceAuditorToolkit()
        result = await toolkit.scan_controls("pci_dss")
        assert len(result) == 5
        assert result[0]["control_id"].startswith("PCI-")

    @pytest.mark.asyncio
    async def test_scan_controls_unknown_framework(self) -> None:
        toolkit = ComplianceAuditorToolkit()
        result = await toolkit.scan_controls("unknown_framework")
        assert result == []

    @pytest.mark.asyncio
    async def test_collect_evidence_mock(self) -> None:
        toolkit = ComplianceAuditorToolkit()
        result = await toolkit.collect_evidence("SOC2-CC6.1")
        assert len(result) == 1
        assert result[0]["id"] == "ev-SOC2-CC6.1-001"
        assert result[0]["source"] == "infrastructure_scan"
        assert result[0]["collected_at"] > 0

    def test_assess_control_compliant(self) -> None:
        toolkit = ComplianceAuditorToolkit()
        control = {
            "control_id": "SOC2-CC6.1",
            "framework": "soc2",
            "description": "Access controls",
            "status": "compliant",
            "gaps": [],
        }
        evidence = [{"id": "ev-001", "source": "scan"}]
        result = toolkit.assess_control(control, evidence)
        assert result["status"] == "compliant"
        assert "ev-001" in result["evidence_refs"]

    def test_assess_control_no_evidence_non_compliant(self) -> None:
        toolkit = ComplianceAuditorToolkit()
        control = {
            "control_id": "PCI-1.1",
            "framework": "pci_dss",
            "description": "Network controls",
            "status": "partial",
            "gaps": [],
        }
        result = toolkit.assess_control(control, [])
        assert result["status"] == "non_compliant"
        assert any("No evidence" in g for g in result["gaps"])

    def test_generate_audit_report_empty(self) -> None:
        toolkit = ComplianceAuditorToolkit()
        result = toolkit.generate_audit_report([])
        assert result["total_controls"] == 0
        assert result["compliance_score"] == 0.0
        assert "No controls assessed" in result["recommendations"][0]

    def test_generate_audit_report_mixed(self) -> None:
        toolkit = ComplianceAuditorToolkit()
        assessments = [
            {"control_id": "C1", "framework": "soc2", "status": "compliant", "gaps": []},
            {"control_id": "C2", "framework": "soc2", "status": "non_compliant",
             "gaps": ["Missing encryption"]},
            {"control_id": "C3", "framework": "soc2", "status": "partial", "gaps": []},
            {"control_id": "C4", "framework": "soc2", "status": "not_applicable", "gaps": []},
        ]
        result = toolkit.generate_audit_report(assessments)
        assert result["total_controls"] == 4
        assert result["compliant"] == 1
        assert result["non_compliant"] == 1
        assert result["partial"] == 1
        assert result["not_applicable"] == 1
        # Score: (1 + 0.5) / 3 applicable = 0.5
        assert result["compliance_score"] == 0.5
        assert len(result["gaps"]) == 1
        assert any("Remediate" in r for r in result["recommendations"])

    def test_generate_audit_report_all_compliant(self) -> None:
        toolkit = ComplianceAuditorToolkit()
        assessments = [
            {"control_id": "C1", "framework": "soc2", "status": "compliant", "gaps": []},
            {"control_id": "C2", "framework": "soc2", "status": "compliant", "gaps": []},
        ]
        result = toolkit.generate_audit_report(assessments)
        assert result["compliance_score"] == 1.0
        assert "All assessed controls are compliant" in result["recommendations"]


class TestComplianceAuditorNodes:
    @pytest.mark.asyncio
    async def test_scan_infrastructure_node(self) -> None:
        toolkit = ComplianceAuditorToolkit()
        state: dict = {"frameworks": ["soc2"], "reasoning_chain": []}
        result = await scan_infrastructure(state, toolkit)
        assert result["stage"] == "collect_evidence"
        assert len(result["controls_assessed"]) == 5
        assert len(result["reasoning_chain"]) == 1

    @pytest.mark.asyncio
    async def test_collect_evidence_node(self) -> None:
        toolkit = ComplianceAuditorToolkit()
        state: dict = {
            "controls_assessed": [
                {
                    "control_id": "SOC2-CC6.1",
                    "framework": "soc2",
                    "description": "Access controls",
                    "status": "compliant",
                    "gaps": [],
                }
            ],
            "reasoning_chain": [],
        }
        result = await collect_evidence(state, toolkit)
        assert result["stage"] == "analyze_gaps"
        assert len(result["evidence_collected"]) >= 1
        assert len(result["controls_assessed"]) == 1

    @pytest.mark.asyncio
    async def test_analyze_gaps_node(self) -> None:
        toolkit = ComplianceAuditorToolkit()
        state: dict = {
            "controls_assessed": [
                {"control_id": "C1", "status": "non_compliant", "gaps": ["Gap A"]},
                {"control_id": "C2", "status": "compliant", "gaps": []},
            ],
            "reasoning_chain": [],
        }
        result = await analyze_gaps(state, toolkit)
        assert result["stage"] == "generate_report"
        assert result["gaps_found"] == 1

    @pytest.mark.asyncio
    async def test_generate_report_node(self) -> None:
        toolkit = ComplianceAuditorToolkit()
        state: dict = {
            "controls_assessed": [
                {"control_id": "C1", "framework": "soc2", "status": "compliant", "gaps": []},
                {"control_id": "C2", "framework": "soc2", "status": "non_compliant",
                 "gaps": ["Missing config"]},
            ],
            "reasoning_chain": [],
        }
        result = await generate_report(state, toolkit)
        assert result["stage"] == "generate_report"
        assert "report" in result
        assert result["compliance_score"] > 0


class TestComplianceAuditorGraph:
    def test_create_graph(self) -> None:
        graph = create_compliance_auditor_graph()
        assert graph is not None

    def test_create_graph_with_toolkit(self) -> None:
        toolkit = ComplianceAuditorToolkit()
        graph = create_compliance_auditor_graph(toolkit)
        assert graph is not None


class TestComplianceAuditorPrompts:
    def test_system_scan_prompt_exists(self) -> None:
        assert "compliance auditor" in SYSTEM_SCAN.lower()

    def test_system_collect_evidence_prompt_exists(self) -> None:
        assert "evidence" in SYSTEM_COLLECT_EVIDENCE.lower()

    def test_system_analyze_gaps_prompt_exists(self) -> None:
        assert "gap analysis" in SYSTEM_ANALYZE_GAPS.lower()

    def test_system_generate_report_prompt_exists(self) -> None:
        assert "audit-ready" in SYSTEM_GENERATE_REPORT.lower()
