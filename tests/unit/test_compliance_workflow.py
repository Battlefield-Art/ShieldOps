"""Unit tests for compliance_workflow agent."""

from __future__ import annotations

import pytest

from shieldops.agents.compliance_workflow.models import (
    ComplianceControl,
    ComplianceStage,
    ComplianceWorkflowState,
    ControlStatus,
    EvidenceItem,
    Framework,
    GapFinding,
)
from shieldops.agents.compliance_workflow.tools import (
    FRAMEWORK_CONTROLS,
    ComplianceWorkflowToolkit,
)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class TestEnums:
    def test_compliance_stage_values(self):
        assert ComplianceStage.IDENTIFY_CONTROLS == "identify_controls"
        assert ComplianceStage.COLLECT_EVIDENCE == "collect_evidence"
        assert ComplianceStage.TEST_CONTROLS == "test_controls"
        assert ComplianceStage.IDENTIFY_GAPS == "identify_gaps"
        assert ComplianceStage.REMEDIATE == "remediate"
        assert ComplianceStage.REPORT == "report"

    def test_framework_values(self):
        assert Framework.SOC2 == "soc2"
        assert Framework.HIPAA == "hipaa"
        assert Framework.PCI_DSS == "pci_dss"
        assert Framework.GDPR == "gdpr"
        assert Framework.ISO27001 == "iso27001"
        assert Framework.NIST_CSF == "nist_csf"

    def test_control_status_values(self):
        assert ControlStatus.PASSING == "passing"
        assert ControlStatus.FAILING == "failing"
        assert ControlStatus.NOT_TESTED == "not_tested"
        assert ControlStatus.PARTIALLY_PASSING == "partially_passing"
        assert ControlStatus.EXEMPT == "exempt"


class TestState:
    def test_defaults(self):
        state = ComplianceWorkflowState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.error == ""
        assert state.stage == ComplianceStage.IDENTIFY_CONTROLS
        assert state.framework == Framework.SOC2
        assert state.controls == []
        assert state.evidence_items == []
        assert state.gaps == []
        assert state.remediation_items == []
        assert state.overall_score == 0.0
        assert state.reasoning_chain == []
        assert state.session_start == 0.0

    def test_with_values(self):
        state = ComplianceWorkflowState(
            request_id="cw-1",
            tenant_id="t-1",
            framework=Framework.HIPAA,
            overall_score=85.5,
        )
        assert state.request_id == "cw-1"
        assert state.framework == Framework.HIPAA
        assert state.overall_score == 85.5


class TestModels:
    def test_compliance_control_defaults(self):
        c = ComplianceControl()
        assert c.id == ""
        assert c.name == ""
        assert c.framework == Framework.SOC2
        assert c.status == ControlStatus.NOT_TESTED
        assert c.owner == ""

    def test_evidence_item_defaults(self):
        e = EvidenceItem()
        assert e.id == ""
        assert e.control_id == ""
        assert e.valid is False

    def test_gap_finding_defaults(self):
        g = GapFinding()
        assert g.id == ""
        assert g.severity == "medium"
        assert g.resolved is False


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        return ComplianceWorkflowToolkit()

    @pytest.mark.asyncio
    async def test_identify_controls_soc2(self, toolkit):
        result = await toolkit.identify_controls(
            framework="soc2",
        )
        assert len(result) == len(FRAMEWORK_CONTROLS["soc2"])
        assert all(isinstance(c, ComplianceControl) for c in result)

    @pytest.mark.asyncio
    async def test_identify_controls_hipaa(self, toolkit):
        result = await toolkit.identify_controls(
            framework="hipaa",
        )
        assert len(result) == len(FRAMEWORK_CONTROLS["hipaa"])

    @pytest.mark.asyncio
    async def test_identify_controls_unknown_framework(
        self,
        toolkit,
    ):
        result = await toolkit.identify_controls(
            framework="unknown",
        )
        # Falls back to soc2
        assert len(result) == len(FRAMEWORK_CONTROLS["soc2"])

    @pytest.mark.asyncio
    async def test_collect_evidence(self, toolkit):
        ctrl = ComplianceControl(
            id="CC6.1",
            name="Logical Access",
            category="Common Criteria",
        )
        result = await toolkit.collect_evidence(ctrl)
        assert len(result) > 0
        assert all(isinstance(e, EvidenceItem) for e in result)
        assert all(e.control_id == "CC6.1" for e in result)
        assert all(e.valid is True for e in result)

    @pytest.mark.asyncio
    async def test_test_control_passing(self, toolkit):
        ctrl = ComplianceControl(id="CC6.1", name="Logical Access")
        evidence = [
            EvidenceItem(
                id="ev-1",
                control_id="CC6.1",
                valid=True,
            ),
        ]
        status = await toolkit.test_control(ctrl, evidence)
        assert status == ControlStatus.PASSING

    @pytest.mark.asyncio
    async def test_test_control_failing(self, toolkit):
        ctrl = ComplianceControl(id="CC6.1", name="Logical Access")
        evidence = [
            EvidenceItem(
                id="ev-1",
                control_id="CC6.1",
                valid=False,
            ),
        ]
        status = await toolkit.test_control(ctrl, evidence)
        assert status == ControlStatus.FAILING

    @pytest.mark.asyncio
    async def test_test_control_no_evidence(self, toolkit):
        ctrl = ComplianceControl(id="CC6.1", name="Logical Access")
        status = await toolkit.test_control(ctrl, [])
        assert status == ControlStatus.NOT_TESTED

    @pytest.mark.asyncio
    async def test_test_control_partial(self, toolkit):
        ctrl = ComplianceControl(id="CC6.1", name="Logical Access")
        evidence = [
            EvidenceItem(id="ev-1", control_id="CC6.1", valid=True),
            EvidenceItem(id="ev-2", control_id="CC6.1", valid=False),
        ]
        status = await toolkit.test_control(ctrl, evidence)
        assert status == ControlStatus.PARTIALLY_PASSING

    @pytest.mark.asyncio
    async def test_identify_gaps(self, toolkit):
        controls = [
            ComplianceControl(
                id="CC6.1",
                name="Logical Access",
                status=ControlStatus.FAILING,
            ),
            ComplianceControl(
                id="CC7.1",
                name="System Ops",
                status=ControlStatus.PASSING,
            ),
        ]
        gaps = await toolkit.identify_gaps(controls)
        assert len(gaps) == 1
        assert gaps[0].control_id == "CC6.1"
        assert gaps[0].severity == "high"

    @pytest.mark.asyncio
    async def test_identify_gaps_partial(self, toolkit):
        controls = [
            ComplianceControl(
                id="CC6.1",
                name="Logical Access",
                status=ControlStatus.PARTIALLY_PASSING,
            ),
        ]
        gaps = await toolkit.identify_gaps(controls)
        assert len(gaps) == 1
        assert gaps[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_generate_remediation(self, toolkit):
        gap = GapFinding(
            id="gap-CC6.1",
            control_id="CC6.1",
            severity="high",
            description="Failing control",
        )
        plan = await toolkit.generate_remediation(gap)
        assert plan["gap_id"] == "gap-CC6.1"
        assert plan["status"] == "pending"


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


class TestNodes:
    @pytest.mark.asyncio
    async def test_identify_controls_node(self):
        from shieldops.agents.compliance_workflow.nodes import (
            identify_controls,
            set_toolkit,
        )

        set_toolkit(ComplianceWorkflowToolkit())
        state = ComplianceWorkflowState(
            framework=Framework.SOC2,
        )
        result = await identify_controls(state)
        assert "controls" in result
        assert len(result["controls"]) > 0
        assert result["stage"] == ComplianceStage.COLLECT_EVIDENCE

    @pytest.mark.asyncio
    async def test_collect_evidence_node(self):
        from shieldops.agents.compliance_workflow.nodes import (
            collect_evidence,
            set_toolkit,
        )

        set_toolkit(ComplianceWorkflowToolkit())
        state = ComplianceWorkflowState(
            controls=[
                ComplianceControl(
                    id="CC6.1",
                    name="Logical Access",
                    category="Common Criteria",
                ),
            ],
        )
        result = await collect_evidence(state)
        assert "evidence_items" in result
        assert len(result["evidence_items"]) > 0
        assert result["stage"] == ComplianceStage.TEST_CONTROLS

    @pytest.mark.asyncio
    async def test_test_controls_node(self):
        from shieldops.agents.compliance_workflow.nodes import (
            set_toolkit,
            test_controls,
        )

        set_toolkit(ComplianceWorkflowToolkit())
        state = ComplianceWorkflowState(
            controls=[
                ComplianceControl(
                    id="CC6.1",
                    name="Logical Access",
                ),
            ],
            evidence_items=[
                EvidenceItem(
                    id="ev-1",
                    control_id="CC6.1",
                    valid=True,
                ),
            ],
        )
        result = await test_controls(state)
        assert len(result["controls"]) == 1
        assert result["controls"][0].status == ControlStatus.PASSING
        assert result["stage"] == ComplianceStage.IDENTIFY_GAPS

    @pytest.mark.asyncio
    async def test_identify_gaps_node(self):
        from shieldops.agents.compliance_workflow.nodes import (
            identify_gaps,
            set_toolkit,
        )

        set_toolkit(ComplianceWorkflowToolkit())
        state = ComplianceWorkflowState(
            controls=[
                ComplianceControl(
                    id="CC6.1",
                    name="Logical Access",
                    status=ControlStatus.FAILING,
                ),
            ],
        )
        result = await identify_gaps(state)
        assert "gaps" in result
        assert len(result["gaps"]) == 1
        assert result["stage"] == ComplianceStage.REMEDIATE

    @pytest.mark.asyncio
    async def test_remediate_node(self):
        from shieldops.agents.compliance_workflow.nodes import (
            remediate,
            set_toolkit,
        )

        set_toolkit(ComplianceWorkflowToolkit())
        state = ComplianceWorkflowState(
            gaps=[
                GapFinding(
                    id="gap-1",
                    control_id="CC6.1",
                    severity="high",
                    description="Failing",
                ),
            ],
        )
        result = await remediate(state)
        assert len(result["remediation_items"]) == 1
        assert result["stage"] == ComplianceStage.REPORT

    @pytest.mark.asyncio
    async def test_report_node(self):
        import time

        from shieldops.agents.compliance_workflow.nodes import (
            report,
            set_toolkit,
        )

        set_toolkit(ComplianceWorkflowToolkit())
        state = ComplianceWorkflowState(
            framework=Framework.SOC2,
            session_start=time.time(),
            controls=[
                ComplianceControl(
                    id="CC6.1",
                    name="Logical Access",
                    status=ControlStatus.PASSING,
                ),
                ComplianceControl(
                    id="CC7.1",
                    name="System Ops",
                    status=ControlStatus.FAILING,
                ),
            ],
            gaps=[
                GapFinding(
                    id="gap-1",
                    control_id="CC7.1",
                ),
            ],
        )
        result = await report(state)
        assert result["stage"] == ComplianceStage.REPORT
        assert result["overall_score"] == 50.0


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.compliance_workflow.graph import (
            create_compliance_workflow_graph,
        )

        sg = create_compliance_workflow_graph()
        assert sg.compile() is not None


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class TestRunner:
    def test_runner_init(self):
        from shieldops.agents.compliance_workflow.runner import (
            ComplianceWorkflowRunner,
        )

        runner = ComplianceWorkflowRunner()
        assert runner is not None
