"""End-to-end integration tests for the Threat Modeling Agent.

Tests the full LangGraph workflow: discover_architecture -> analyze_threats ->
assess_risk -> recommend_mitigations, with no real RBA client, architecture
registry, or threat intel service. The toolkit uses mock fallback paths.
"""

from __future__ import annotations

import pytest

from shieldops.agents.threat_modeling.runner import ThreatModelingRunner

# ── Full Pipeline ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_full_pipeline_default_service():
    """Full pipeline discovers, analyzes, assesses, and recommends for default service."""
    runner = ThreatModelingRunner()
    result = await runner.run(request_id="tm-001", target_service="default")

    assert isinstance(result, dict)
    assert not result.get("error")
    assert len(result.get("reasoning_chain", [])) >= 4
    assert len(result.get("components", [])) > 0
    assert len(result.get("threats", [])) > 0
    assert len(result.get("mitigations", [])) > 0
    assert result.get("residual_risk", -1) >= 0


@pytest.mark.asyncio
async def test_full_pipeline_web_application():
    """Pipeline handles web application profile with more components."""
    runner = ThreatModelingRunner()
    result = await runner.run(
        request_id="tm-web",
        target_service="web_application",
    )

    assert isinstance(result, dict)
    components = result.get("components", [])
    # web_application profile has 5 components
    assert len(components) == 5
    component_names = {c.get("name") for c in components}
    assert "load_balancer" in component_names
    assert "api_gateway" in component_names
    assert "database" in component_names


@pytest.mark.asyncio
async def test_full_pipeline_microservice():
    """Pipeline handles microservice profile correctly."""
    runner = ThreatModelingRunner()
    result = await runner.run(
        request_id="tm-micro",
        target_service="microservice",
    )

    assert isinstance(result, dict)
    components = result.get("components", [])
    # microservice profile has 3 components
    assert len(components) == 3
    component_names = {c.get("name") for c in components}
    assert "service_mesh" in component_names
    assert "config_store" in component_names


# ── STRIDE Threats ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stride_threats_identified():
    """STRIDE analysis identifies threats across multiple categories."""
    runner = ThreatModelingRunner()
    result = await runner.run(
        request_id="tm-stride",
        target_service="web_application",
    )

    threats = result.get("threats", [])
    assert len(threats) > 0

    # Collect STRIDE categories present
    categories = {t.get("stride_category") for t in threats}
    # Web app should trigger multiple STRIDE categories
    assert len(categories) >= 3

    # Each threat has required fields
    for t in threats:
        assert t.get("id", "").startswith("THR-")
        assert t.get("component") != ""
        assert t.get("description") != ""
        assert t.get("mitre_technique") != ""


@pytest.mark.asyncio
async def test_threats_have_impact_and_likelihood():
    """Each threat has an impact score and likelihood assessment."""
    runner = ThreatModelingRunner()
    result = await runner.run(
        request_id="tm-impact",
        target_service="default",
    )

    threats = result.get("threats", [])
    for t in threats:
        assert 0.0 <= t.get("impact_score", -1) <= 100.0
        assert t.get("likelihood") in ("very_likely", "likely", "possible", "unlikely", "rare")


# ── Risk Assessment ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_risk_scores_computed():
    """Risk scores are calculated using impact * likelihood weight."""
    runner = ThreatModelingRunner()
    result = await runner.run(
        request_id="tm-risk",
        target_service="web_application",
    )

    threats = result.get("threats", [])
    assert len(threats) > 0

    for t in threats:
        risk = t.get("risk_score", -1)
        assert 0.0 <= risk <= 100.0

    # Threats should be sorted by risk_score descending
    risk_scores = [t["risk_score"] for t in threats]
    assert risk_scores == sorted(risk_scores, reverse=True)


# ── Mitigations ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mitigations_recommended():
    """Mitigations are recommended for identified threats."""
    runner = ThreatModelingRunner()
    result = await runner.run(
        request_id="tm-mitigate",
        target_service="web_application",
    )

    mitigations = result.get("mitigations", [])
    assert len(mitigations) > 0

    for m in mitigations:
        assert m.get("threat_id", "").startswith("THR-")
        assert m.get("description") != ""
        assert m.get("control_type") in ("preventive", "detective")
        assert m.get("effort") in ("low", "medium", "high")
        assert m.get("effectiveness") in ("low", "medium", "high")


# ── Residual Risk ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_residual_risk_computed():
    """Residual risk is calculated after mitigations and is lower than max threat risk."""
    runner = ThreatModelingRunner()
    result = await runner.run(
        request_id="tm-residual",
        target_service="web_application",
    )

    residual = result.get("residual_risk", -1)
    assert 0.0 <= residual <= 100.0

    # Residual risk should be lower than the highest individual threat risk
    threats = result.get("threats", [])
    if threats:
        max_risk = max(t.get("risk_score", 0) for t in threats)
        assert residual < max_risk
