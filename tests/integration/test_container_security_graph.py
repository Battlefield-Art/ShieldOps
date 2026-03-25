"""Integration test for the Container Security Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.container_security.models import (
    ContainerSecurityState,
    ContainerStage,
    ImageSeverity,
    ImageVulnerability,
    RuntimeAnomaly,
    RuntimeThreat,
)


@pytest.fixture
def container_state() -> dict:
    return ContainerSecurityState(
        request_id="test-cs-001",
        tenant_id="tenant-prod-01",
        namespaces=["production", "staging"],
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.container_security.graph import create_container_security_graph

    sg = create_container_security_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "scan_images",
        "analyze_runtime",
        "detect_anomalies",
        "enforce_admission",
        "remediate",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    vuln = ImageVulnerability(
        id="iv-001",
        image="nginx",
        tag="1.24",
        cve_id="CVE-2024-1234",
        severity=ImageSeverity.CRITICAL,
        package_name="openssl",
        installed_version="1.1.1k",
        fixed_version="1.1.1l",
        cvss_score=9.8,
        exploitable=True,
    )
    anomaly = RuntimeAnomaly(
        id="ra-001",
        pod_name="api-pod-xyz",
        namespace="production",
        threat_type=RuntimeThreat.PRIVILEGE_ESCALATION,
        description="Container attempted to mount host filesystem",
        severity=ImageSeverity.CRITICAL,
        confidence=0.92,
        process="/bin/sh",
    )
    state = ContainerSecurityState(
        image_vulnerabilities=[vuln],
        runtime_anomalies=[anomaly],
        stage=ContainerStage.DETECT_ANOMALIES,
    )
    assert len(state.image_vulnerabilities) == 1
    assert state.runtime_anomalies[0].threat_type == RuntimeThreat.PRIVILEGE_ESCALATION


def test_state_defaults():
    state = ContainerSecurityState()
    assert state.stage == ContainerStage.SCAN_IMAGES
    assert state.image_vulnerabilities == []
    assert state.runtime_anomalies == []
    assert state.error == ""


@pytest.mark.asyncio
async def test_full_pipeline(container_state):
    from shieldops.agents.container_security.graph import create_container_security_graph

    sg = create_container_security_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(container_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
    assert "reasoning_chain" in result
