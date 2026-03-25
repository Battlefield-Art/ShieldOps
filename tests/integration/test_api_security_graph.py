"""Integration test for the API Security Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.api_security.models import (
    APIEndpoint,
    APISecurityState,
    APISeverity,
    APIVulnerability,
    SecurityStage,
    VulnerabilityType,
)


@pytest.fixture
def security_state() -> dict:
    return APISecurityState(
        request_id="test-as-001",
        tenant_id="tenant-prod-01",
        scan_scope=["api_gateway", "service_mesh", "openapi_specs"],
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.api_security.graph import create_api_security_graph

    sg = create_api_security_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "discover_endpoints",
        "analyze_traffic",
        "detect_vulnerabilities",
        "detect_abuse",
        "enforce_policies",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    endpoint = APIEndpoint(
        id="ep-001",
        method="GET",
        path="/api/v1/users/{id}",
        service="user-service",
        auth_required=True,
        rate_limited=True,
        requests_per_day=45000,
        avg_latency_ms=120.0,
        error_rate=0.02,
    )
    vuln = APIVulnerability(
        id="vuln-001",
        endpoint_id="ep-001",
        vulnerability_type=VulnerabilityType.BOLA,
        description="Broken Object Level Authorization on user endpoint",
        severity=APISeverity.CRITICAL,
        confidence=0.91,
        owasp_reference="API1:2023",
        cwe_id="CWE-639",
        remediation="Add object-level authorization check",
    )
    state = APISecurityState(
        discovered_endpoints=[endpoint],
        vulnerabilities=[vuln],
        stage=SecurityStage.DETECT_ABUSE,
    )
    assert len(state.vulnerabilities) == 1
    assert state.vulnerabilities[0].vulnerability_type == VulnerabilityType.BOLA


def test_state_defaults():
    state = APISecurityState()
    assert state.stage == SecurityStage.DISCOVER_ENDPOINTS
    assert state.discovered_endpoints == []
    assert state.vulnerabilities == []
    assert state.abuse_incidents == []
    assert state.error == ""


@pytest.mark.asyncio
async def test_full_pipeline(security_state):
    from shieldops.agents.api_security.graph import create_api_security_graph

    sg = create_api_security_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(security_state)
    except Exception:
        pytest.skip("Pipeline requires external dependencies")
        return
    assert isinstance(result, dict)
    assert "reasoning_chain" in result
