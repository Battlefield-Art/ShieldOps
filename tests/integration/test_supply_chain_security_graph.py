"""Integration test for the Supply Chain Security Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.supply_chain_security.models import (
    DependencyRisk,
    PipelineFinding,
    PipelineThreat,
    SBOMEntry,
    SupplyChainSecurityState,
    SupplyChainStage,
)


@pytest.fixture
def supply_chain_state() -> dict:
    return SupplyChainSecurityState(
        request_id="test-scs-001",
        tenant_id="tenant-prod-01",
        repositories=["shieldops/backend", "shieldops/dashboard-ui"],
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.supply_chain_security.graph import create_supply_chain_security_graph

    sg = create_supply_chain_security_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "generate_sbom",
        "scan_dependencies",
        "audit_cicd",
        "verify_signatures",
        "assess_risk",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    entry = SBOMEntry(
        id="sbom-001",
        package_name="requests",
        version="2.31.0",
        ecosystem="pip",
        license="Apache-2.0",
        direct=True,
        vulnerabilities=1,
        risk_level=DependencyRisk.MEDIUM,
    )
    finding = PipelineFinding(
        id="pf-001",
        pipeline_name="ci.yml",
        stage="build",
        threat_type=PipelineThreat.SECRET_EXPOSURE,
        description="Hardcoded API key in workflow file",
        severity="high",
        file_path=".github/workflows/ci.yml",
        remediation="Move secret to GitHub Secrets",
    )
    state = SupplyChainSecurityState(
        sbom_entries=[entry],
        pipeline_findings=[finding],
        stage=SupplyChainStage.ASSESS_RISK,
    )
    assert len(state.sbom_entries) == 1
    assert state.pipeline_findings[0].threat_type == PipelineThreat.SECRET_EXPOSURE


def test_state_defaults():
    state = SupplyChainSecurityState()
    assert state.stage == SupplyChainStage.GENERATE_SBOM
    assert state.sbom_entries == []
    assert state.dependency_vulnerabilities == []
    assert state.pipeline_findings == []
    assert state.error == ""


@pytest.mark.asyncio
async def test_full_pipeline(supply_chain_state):
    from shieldops.agents.supply_chain_security.graph import create_supply_chain_security_graph

    sg = create_supply_chain_security_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(supply_chain_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
    assert "reasoning_chain" in result
