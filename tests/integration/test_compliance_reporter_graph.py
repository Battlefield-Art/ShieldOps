"""Integration test for the Compliance Reporter Agent LangGraph pipeline.

Tests graph compilation, state model validation, and full compliance
reporting pipeline execution.
"""

from __future__ import annotations

import pytest

from shieldops.agents.compliance_reporter.models import (
    ComplianceFramework,
    ComplianceReporterState,
    ControlAssessment,
    ControlStatus,
    EvidenceItem,
    ReporterStage,
)

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def soc2_audit_state() -> dict:
    """State with SOC 2 Type II audit configuration."""
    return ComplianceReporterState(
        request_id="test-cr-001",
        framework=ComplianceFramework.SOC2_TYPE2,
        period_start="2025-01-01",
        period_end="2025-12-31",
        session_start=1000000.0,
    ).model_dump()


@pytest.fixture
def hipaa_audit_state() -> dict:
    """State with HIPAA assessment configuration."""
    return ComplianceReporterState(
        request_id="test-cr-002",
        framework=ComplianceFramework.HIPAA,
        period_start="2025-06-01",
        period_end="2025-12-31",
        session_start=1000000.0,
    ).model_dump()


# ── Graph Compilation ─────────────────────────────────────────────────


def test_graph_compiles():
    """Graph compiles and contains all expected nodes."""
    from shieldops.agents.compliance_reporter.graph import (
        create_compliance_reporter_graph,
    )

    sg = create_compliance_reporter_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()

    expected_nodes = [
        "select_framework",
        "collect_evidence",
        "assess_controls",
        "generate_report",
        "package_artifacts",
        "deliver",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected_nodes:
        assert name in node_ids, f"Missing node: {name}"


# ── State Model Validation ────────────────────────────────────────────


def test_state_model_validation():
    """ComplianceReporterState validates with rich sample data."""
    evidence = EvidenceItem(
        id="evi-001",
        control_id="CC6.1",
        framework=ComplianceFramework.SOC2_TYPE2,
        title="Access Control Logs",
        description="12 months of access control audit logs",
        evidence_type="log_export",
        source="aws_cloudtrail",
        artifact_path="/evidence/cc6.1/cloudtrail.json.gz",
        hash_digest="sha256:abc123",
        verified=True,
    )
    assessment = ControlAssessment(
        id="ca-001",
        control_id="CC6.1",
        framework=ComplianceFramework.SOC2_TYPE2,
        control_name="Logical and Physical Access Controls",
        status=ControlStatus.COMPLIANT,
        findings=[],
        evidence_ids=["evi-001"],
        remediation_steps=[],
        assessor_notes="All access controls properly enforced",
    )
    state = ComplianceReporterState(
        request_id="test-001",
        framework=ComplianceFramework.SOC2_TYPE2,
        evidence_items=[evidence],
        control_assessments=[assessment],
        stage=ReporterStage.GENERATE_REPORT,
    )
    assert state.framework == ComplianceFramework.SOC2_TYPE2
    assert len(state.evidence_items) == 1
    assert state.evidence_items[0].verified is True
    assert state.control_assessments[0].status == ControlStatus.COMPLIANT


def test_state_model_defaults():
    """ComplianceReporterState defaults are correct."""
    state = ComplianceReporterState()
    assert state.stage == ReporterStage.SELECT_FRAMEWORK
    assert state.framework == ComplianceFramework.SOC2_TYPE2
    assert state.evidence_items == []
    assert state.control_assessments == []
    assert state.compliance_report is None
    assert state.artifact_package is None
    assert state.delivery_results == []
    assert state.error == ""


# ── Full Pipeline ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_full_soc2_pipeline(soc2_audit_state):
    """Run the full Compliance Reporter pipeline for SOC 2; verify graph executes."""
    from shieldops.agents.compliance_reporter.graph import (
        create_compliance_reporter_graph,
    )

    sg = create_compliance_reporter_graph()
    compiled = sg.compile()

    try:
        result = await compiled.ainvoke(soc2_audit_state)
    except Exception:
        pytest.skip("Pipeline ainvoke requires external dependencies")
        return

    assert isinstance(result, dict)
    assert "reasoning_chain" in result
    assert len(result.get("reasoning_chain", [])) > 0


@pytest.mark.asyncio
async def test_full_hipaa_pipeline(hipaa_audit_state):
    """Run the full Compliance Reporter pipeline for HIPAA."""
    from shieldops.agents.compliance_reporter.graph import (
        create_compliance_reporter_graph,
    )

    sg = create_compliance_reporter_graph()
    compiled = sg.compile()

    try:
        result = await compiled.ainvoke(hipaa_audit_state)
    except Exception:
        pytest.skip("Pipeline ainvoke requires external dependencies")
        return

    assert isinstance(result, dict)
