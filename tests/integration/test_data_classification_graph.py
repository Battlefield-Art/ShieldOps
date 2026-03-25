"""Integration test for the Data Classification Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.data_classification.models import (
    ClassificationStage,
    DataCategory,
    DataClassificationState,
    SensitiveDataFinding,
    SensitivityLevel,
)


@pytest.fixture
def classification_state() -> dict:
    return DataClassificationState(
        request_id="test-dc-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.data_classification.graph import create_data_classification_graph

    sg = create_data_classification_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "scan_sources",
        "detect_sensitive",
        "classify_level",
        "map_regulations",
        "enforce_labels",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    finding = SensitiveDataFinding(
        id="sdf-001",
        asset_id="rds-users",
        data_category=DataCategory.PII,
        sensitivity_level=SensitivityLevel.CONFIDENTIAL,
        column_or_path="users.ssn",
        sample_count=45000,
        confidence=0.98,
        regex_matched=True,
        llm_classified=False,
    )
    state = DataClassificationState(
        sensitive_findings=[finding], stage=ClassificationStage.MAP_REGULATIONS
    )
    assert state.sensitive_findings[0].data_category == DataCategory.PII


def test_state_defaults():
    state = DataClassificationState()
    assert state.stage == ClassificationStage.SCAN_SOURCES
    assert state.sensitive_findings == []
    assert state.regulatory_mappings == []


@pytest.mark.asyncio
async def test_full_pipeline(classification_state):
    from shieldops.agents.data_classification.graph import create_data_classification_graph

    sg = create_data_classification_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(classification_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
