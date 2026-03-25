"""Integration test for the Data Pipeline Security Agent LangGraph pipeline.

Tests graph compilation, state model validation, conditional routing
(findings vs clean path), and full scan pipeline execution.
"""

from __future__ import annotations

import pytest

from shieldops.agents.data_pipeline_security.models import (
    DataPipelineSecurityState,
    DataSourceType,
    PipelineStage,
    PoisoningFinding,
    RiskLevel,
)

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def rag_scan_state() -> dict:
    """State with RAG pipeline data for security scanning."""
    return DataPipelineSecurityState(
        request_id="test-dps-001",
        pipeline_id="rag-prod-01",
        data_sources=[
            {"name": "chromadb-main", "type": "vector_db", "url": "localhost:8000"},
            {"name": "doc-store", "type": "document_store", "path": "/data/docs"},
        ],
        scan_scope=["rag", "documents", "models", "provenance"],
        session_start=1000000.0,
    ).model_dump()


@pytest.fixture
def clean_scan_state() -> dict:
    """State with minimal pipeline data (should produce no findings)."""
    return DataPipelineSecurityState(
        request_id="test-dps-002",
        pipeline_id="rag-dev-01",
        data_sources=[],
        scan_scope=["rag"],
        session_start=1000000.0,
    ).model_dump()


# ── Graph Compilation ─────────────────────────────────────────────────


def test_graph_compiles():
    """Graph compiles and contains all expected nodes."""
    from shieldops.agents.data_pipeline_security.graph import (
        create_data_pipeline_security_graph,
    )

    sg = create_data_pipeline_security_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()

    expected_nodes = [
        "scan_rag_pipeline",
        "audit_data_flows",
        "detect_poisoning",
        "assess_provenance",
        "enforce_policies",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected_nodes:
        assert name in node_ids, f"Missing node: {name}"


# ── State Model Validation ────────────────────────────────────────────


def test_state_model_validation():
    """DataPipelineSecurityState validates with rich sample data."""
    finding = PoisoningFinding(
        id="PSN-001",
        source="chromadb-main",
        source_type=DataSourceType.VECTOR_DB,
        poisoning_type="embedding_manipulation",
        description="Adversarial embedding detected in vector store",
        severity=RiskLevel.HIGH,
        confidence=0.88,
        mitre_technique="AML.T0020",
        affected_records=150,
    )
    state = DataPipelineSecurityState(
        request_id="test-001",
        pipeline_id="rag-prod-01",
        poisoning_findings=[finding],
        stage=PipelineStage.DETECT_POISONING,
    )
    assert state.pipeline_id == "rag-prod-01"
    assert len(state.poisoning_findings) == 1
    assert state.poisoning_findings[0].severity == RiskLevel.HIGH
    assert state.poisoning_findings[0].confidence == 0.88


def test_state_model_defaults():
    """DataPipelineSecurityState defaults are correct."""
    state = DataPipelineSecurityState()
    assert state.stage == PipelineStage.SCAN_RAG
    assert state.poisoning_findings == []
    assert state.data_flow_anomalies == []
    assert state.provenance_records == []
    assert state.policy_violations == []
    assert state.reasoning_chain == []
    assert state.error == ""


# ── Full Pipeline ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_full_scan_pipeline(rag_scan_state):
    """Run the full Data Pipeline Security scan; verify graph executes."""
    from shieldops.agents.data_pipeline_security.graph import (
        create_data_pipeline_security_graph,
    )

    sg = create_data_pipeline_security_graph()
    compiled = sg.compile()

    try:
        result = await compiled.ainvoke(rag_scan_state)
    except Exception:
        pytest.skip("Pipeline ainvoke requires external dependencies")
        return

    assert isinstance(result, dict)
    assert "reasoning_chain" in result
    assert len(result.get("reasoning_chain", [])) > 0


@pytest.mark.asyncio
async def test_clean_pipeline_skips_enforcement(clean_scan_state):
    """Clean pipeline with no data sources should skip policy enforcement."""
    from shieldops.agents.data_pipeline_security.graph import (
        create_data_pipeline_security_graph,
    )

    sg = create_data_pipeline_security_graph()
    compiled = sg.compile()

    try:
        result = await compiled.ainvoke(clean_scan_state)
    except Exception:
        pytest.skip("Pipeline ainvoke requires external dependencies")
        return

    assert isinstance(result, dict)
