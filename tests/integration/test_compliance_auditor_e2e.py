"""End-to-end integration tests for the Compliance Auditor Agent.

Tests the full LangGraph workflow: scan -> collect_evidence -> analyze_gaps
-> generate_report, with mock backends (no real compliance scanning needed).
The toolkit has built-in mock fallback paths with deterministic control data.
"""

from unittest.mock import patch

import pytest

from shieldops.agents.compliance_auditor.runner import ComplianceAuditorRunner

# ── Helpers ───────────────────────────────────────────────────────────


def _get(result, key, default=None):
    """Access a field from a result that may be a dict or a Pydantic model."""
    if isinstance(result, dict):
        return result.get(key, default) if default is not None else result.get(key)
    return getattr(result, key, default)


def _getitem(result, key):
    """Access a field from a result that may be a dict or a Pydantic model."""
    if isinstance(result, dict):
        return result[key]
    return getattr(result, key)


# ── Full Pipeline ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_compliance_auditor_full_soc2_pipeline():
    """Full SOC2 audit: scan -> evidence -> gaps -> report."""
    with patch(
        "shieldops.agents.compliance_auditor.nodes.llm_structured",
        side_effect=RuntimeError("LLM unavailable"),
    ):
        runner = ComplianceAuditorRunner()
        result = await runner.run(frameworks=["soc2"])

    assert _get(result, "compliance_score", 0) > 0
    assert len(_get(result, "reasoning_chain", [])) >= 4
    report = _get(result, "report", {})
    assert report.get("total_controls") == 5
    assert "soc2" in report.get("frameworks", [])


@pytest.mark.asyncio
async def test_compliance_auditor_no_backends():
    """Pipeline runs with no backends and uses built-in mock controls."""
    runner = ComplianceAuditorRunner()
    result = await runner.run()

    # Default framework is soc2
    report = _get(result, "report", {})
    assert report.get("total_controls") == 5
    assert report.get("compliance_score", 0) > 0


# ── Multi-Framework ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_compliance_auditor_multi_framework():
    """Audit across SOC2 and PCI-DSS produces combined results."""
    with patch(
        "shieldops.agents.compliance_auditor.nodes.llm_structured",
        side_effect=RuntimeError("LLM unavailable"),
    ):
        runner = ComplianceAuditorRunner()
        result = await runner.run(frameworks=["soc2", "pci_dss"])

    report = _get(result, "report", {})
    assert report.get("total_controls") == 10  # 5 SOC2 + 5 PCI-DSS
    frameworks = report.get("frameworks", [])
    assert "soc2" in frameworks
    assert "pci_dss" in frameworks


@pytest.mark.asyncio
async def test_compliance_auditor_all_frameworks():
    """Audit across all five supported frameworks."""
    runner = ComplianceAuditorRunner()
    result = await runner.run(frameworks=["soc2", "pci_dss", "hipaa", "gdpr", "iso27001"])

    report = _get(result, "report", {})
    assert report.get("total_controls") == 25  # 5 controls x 5 frameworks
    assert len(report.get("frameworks", [])) == 5


# ── Gap Analysis ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_compliance_auditor_detects_gaps():
    """Gap analysis finds non-compliant controls with missing documentation."""
    runner = ComplianceAuditorRunner()
    result = await runner.run(frameworks=["soc2"])

    gaps_found = _get(result, "gaps_found", 0)
    assert gaps_found >= 1  # Mock alternates statuses; some will be non_compliant

    report = _get(result, "report", {})
    assert report.get("non_compliant", 0) >= 1
    assert len(report.get("gaps", [])) >= 1


@pytest.mark.asyncio
async def test_compliance_auditor_gap_analysis_with_llm():
    """When LLM is available, gap analysis includes risk summary in reasoning."""
    from shieldops.agents.compliance_auditor.nodes import _LLMGapAnalysis

    llm_response = _LLMGapAnalysis(
        critical_gaps=["SOC2-CC6.2: Missing MFA enforcement"],
        remediation_priorities=["Enable MFA", "Update access policy"],
        risk_summary="Moderate risk due to missing authentication controls",
        estimated_remediation_effort="medium",
    )

    async def fake_llm(system_prompt="", user_prompt="", schema=None, **kwargs):
        return llm_response

    with patch(
        "shieldops.agents.compliance_auditor.nodes.llm_structured",
        side_effect=fake_llm,
    ):
        runner = ComplianceAuditorRunner()
        result = await runner.run(frameworks=["soc2"])

    chain = _get(result, "reasoning_chain", [])
    chain_text = " ".join(str(r) for r in chain)
    assert "risk" in chain_text.lower() or "LLM" in chain_text


# ── Evidence Collection ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_compliance_auditor_collects_evidence():
    """Evidence is collected for each assessed control."""
    runner = ComplianceAuditorRunner()
    result = await runner.run(frameworks=["soc2"])

    evidence = _get(result, "evidence_collected", [])
    # 5 controls, 1 evidence item each from mock
    assert len(evidence) == 5
    # Evidence items may be dicts or Pydantic models
    for e in evidence:
        source = e.get("source") if isinstance(e, dict) else e.source
        assert source == "infrastructure_scan"


# ── Report Generation ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_compliance_auditor_report_structure():
    """Generated report has all required fields."""
    runner = ComplianceAuditorRunner()
    result = await runner.run(frameworks=["soc2"])

    report = _get(result, "report", {})
    required_keys = [
        "total_controls",
        "compliant",
        "non_compliant",
        "partial",
        "not_applicable",
        "compliance_score",
        "frameworks",
        "gaps",
        "recommendations",
        "generated_at",
    ]
    for key in required_keys:
        assert key in report, f"Missing report key: {key}"

    # Score should be between 0 and 1
    assert 0 <= report["compliance_score"] <= 1.0

    # Recommendations should be non-empty when gaps exist
    if report["non_compliant"] > 0 or report["partial"] > 0:
        assert len(report["recommendations"]) >= 1
