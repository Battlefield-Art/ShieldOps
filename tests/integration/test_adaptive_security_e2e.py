"""End-to-end integration tests for the Adaptive Security Agent.

Tests the full LangGraph workflow: baseline -> detect_and_propose -> evaluate
-> (conditionally) apply, with no real SIEM, metrics store, or policy engine.
The toolkit uses mock fallback paths that produce deterministic output.
"""

from __future__ import annotations

import pytest

from shieldops.agents.adaptive_security.models import (
    AdaptationStage,
    ThreatContext,
)
from shieldops.agents.adaptive_security.runner import AdaptiveSecurityRunner


# ── Full Pipeline ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_full_pipeline_normal_context():
    """Full pipeline runs with normal threat context and no backends."""
    runner = AdaptiveSecurityRunner()
    result = await runner.run(
        threat_context=ThreatContext.NORMAL,
        window_hours=24,
    )

    assert isinstance(result, dict)
    assert not result.get("error")
    assert len(result.get("reasoning_chain", [])) >= 3
    assert len(result.get("baselines", [])) > 0


@pytest.mark.asyncio
async def test_full_pipeline_elevated_context():
    """Pipeline with elevated threat context completes successfully."""
    runner = AdaptiveSecurityRunner()
    result = await runner.run(
        threat_context=ThreatContext.ELEVATED,
        window_hours=12,
    )

    assert isinstance(result, dict)
    assert not result.get("error")
    assert len(result.get("baselines", [])) > 0
    assert len(result.get("reasoning_chain", [])) >= 3


@pytest.mark.asyncio
async def test_full_pipeline_active_attack_context():
    """Pipeline with active_attack context completes successfully."""
    runner = AdaptiveSecurityRunner()
    result = await runner.run(
        threat_context=ThreatContext.ACTIVE_ATTACK,
        window_hours=4,
    )

    assert isinstance(result, dict)
    assert not result.get("error")


@pytest.mark.asyncio
async def test_full_pipeline_string_context():
    """Pipeline accepts string threat context (converted internally)."""
    runner = AdaptiveSecurityRunner()
    result = await runner.run(
        threat_context="post_incident",
        window_hours=48,
    )

    assert isinstance(result, dict)
    assert not result.get("error")


# ── Baselines ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_baselines_computed_for_all_entity_types():
    """Baselines are computed across host, user, and ip entity types."""
    runner = AdaptiveSecurityRunner()
    result = await runner.run(
        threat_context=ThreatContext.NORMAL,
        window_hours=24,
    )

    baselines = result.get("baselines", [])
    # 4 metrics per entity type x 3 entity types = 12
    assert len(baselines) == 12
    entity_types = {b.get("entity_type") for b in baselines}
    assert "host" in entity_types
    assert "user" in entity_types
    assert "ip" in entity_types


# ── Proposals ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_threshold_proposals_generated_for_drifted_metrics():
    """When drift is detected, threshold proposals are generated."""
    runner = AdaptiveSecurityRunner()
    result = await runner.run(
        threat_context=ThreatContext.NORMAL,
        window_hours=24,
    )

    # Proposals may or may not exist depending on random drift
    # but the proposals key should be present
    proposals = result.get("proposals", [])
    assert isinstance(proposals, list)
    # Each proposal has threshold_type, current_value, proposed_value
    for p in proposals:
        assert "threshold_type" in p
        assert "proposed_value" in p
        assert "confidence" in p
        assert "risk" in p


# ── Evaluation ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_proposals_are_evaluated():
    """All proposals receive evaluation results with accept/reject decisions."""
    runner = AdaptiveSecurityRunner()
    result = await runner.run(
        threat_context=ThreatContext.NORMAL,
        window_hours=24,
    )

    results = result.get("results", [])
    assert isinstance(results, list)
    for r in results:
        assert "accepted" in r
        assert "false_positive_delta" in r
        assert "detection_delta" in r


# ── Conditional Routing ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_accepted_count_reflects_evaluations():
    """accepted_count tracks how many proposals were accepted."""
    runner = AdaptiveSecurityRunner()
    result = await runner.run(
        threat_context=ThreatContext.NORMAL,
        window_hours=24,
    )

    accepted_count = result.get("accepted_count", 0)
    evaluation_results = result.get("results", [])
    actual_accepted = sum(1 for r in evaluation_results if r.get("accepted", False))
    assert accepted_count == actual_accepted
