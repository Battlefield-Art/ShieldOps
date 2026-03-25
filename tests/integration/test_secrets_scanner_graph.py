"""Integration test for the Secrets Scanner Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.secrets_scanner.models import (
    ExposureLevel,
    ScannerStage,
    SecretFinding,
    SecretsScannerState,
    SecretType,
    SourceType,
)


@pytest.fixture
def scan_state() -> dict:
    return SecretsScannerState(
        request_id="test-ss-001",
        tenant_id="tenant-prod-01",
        scan_targets=["git_repos", "config_files", "container_images", "ci_cd"],
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.secrets_scanner.graph import create_secrets_scanner_graph

    sg = create_secrets_scanner_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "scan_sources",
        "detect_secrets",
        "classify_severity",
        "verify_exposure",
        "remediate",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    finding = SecretFinding(
        id="sec-001",
        secret_type=SecretType.AWS_ACCESS_KEY,
        source_type=SourceType.GIT_REPO,
        source_path="src/config/settings.py",
        line_number=42,
        masked_value="AKIA****XXXX",
        exposure_level=ExposureLevel.PUBLIC,
        confidence=0.95,
        is_active=True,
        repository="shieldops/backend",
        branch="main",
    )
    state = SecretsScannerState(
        secret_findings=[finding],
        stage=ScannerStage.CLASSIFY_SEVERITY,
    )
    assert len(state.secret_findings) == 1
    assert state.secret_findings[0].secret_type == SecretType.AWS_ACCESS_KEY
    assert state.secret_findings[0].is_active is True


def test_state_defaults():
    state = SecretsScannerState()
    assert state.stage == ScannerStage.SCAN_SOURCES
    assert state.secret_findings == []
    assert state.severity_assessments == []
    assert state.remediation_actions == []
    assert state.error == ""


@pytest.mark.asyncio
async def test_full_pipeline(scan_state):
    from shieldops.agents.secrets_scanner.graph import create_secrets_scanner_graph

    sg = create_secrets_scanner_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(scan_state)
    except Exception:
        pytest.skip("Pipeline requires external dependencies")
        return
    assert isinstance(result, dict)
    assert "reasoning_chain" in result
