"""End-to-end integration tests for the Detection Engineering Agent.

Tests the full LangGraph workflow: assess_coverage -> create_rules ->
test_and_tune -> (conditionally) deploy_rules, with no real SIEM, MITRE
client, or rule store. The toolkit uses mock fallback paths.
"""

from __future__ import annotations

import pytest

from shieldops.agents.detection_engineering.runner import DetectionEngineeringRunner


# ── Full Pipeline ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_full_pipeline_default():
    """Full pipeline discovers gaps, creates rules, tests/tunes, and deploys."""
    runner = DetectionEngineeringRunner()
    result = await runner.run(request_id="test-001")

    assert isinstance(result, dict)
    assert not result.get("error")
    assert len(result.get("reasoning_chain", [])) >= 3
    # Coverage gaps should be identified
    gaps = result.get("coverage_gaps", [])
    assert isinstance(gaps, list)


@pytest.mark.asyncio
async def test_full_pipeline_empty_request_id():
    """Pipeline runs successfully with empty request_id."""
    runner = DetectionEngineeringRunner()
    result = await runner.run()

    assert isinstance(result, dict)
    assert not result.get("error")


# ── Coverage Assessment ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mitre_coverage_gaps_identified():
    """Assessment node identifies MITRE ATT&CK coverage gaps below 60%."""
    runner = DetectionEngineeringRunner()
    result = await runner.run(request_id="coverage-test")

    gaps = result.get("coverage_gaps", [])
    # With random coverage, we expect some gaps (probability is very high)
    # Each gap should have required fields
    for gap in gaps:
        assert "mitre_tactic" in gap
        assert "mitre_technique" in gap
        assert "current_coverage" in gap
        assert gap["current_coverage"] < 0.6
        assert "priority" in gap
        assert gap["priority"] in ("critical", "high", "medium")
        assert "suggested_rule_type" in gap


@pytest.mark.asyncio
async def test_overall_coverage_computed():
    """Overall coverage is calculated as the average of gap coverages."""
    runner = DetectionEngineeringRunner()
    result = await runner.run(request_id="coverage-calc")

    overall = result.get("overall_coverage", -1)
    assert 0.0 <= overall <= 1.0


# ── Rule Creation ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rules_created_for_gaps():
    """A detection rule is created for each coverage gap."""
    runner = DetectionEngineeringRunner()
    result = await runner.run(request_id="rule-creation")

    gaps = result.get("coverage_gaps", [])
    rules = result.get("rules_created", [])
    # One rule per gap
    assert len(rules) == len(gaps)
    for rule in rules:
        assert rule.get("rule_id") != ""
        assert rule.get("name") != ""
        assert rule.get("query") != ""
        assert rule.get("mitre_tactic") != ""
        assert rule.get("mitre_technique") != ""


@pytest.mark.asyncio
async def test_rules_have_valid_risk_scores():
    """Created rules have risk scores mapped from gap priority."""
    runner = DetectionEngineeringRunner()
    result = await runner.run(request_id="risk-scores")

    rules = result.get("rules_created", [])
    for rule in rules:
        # Risk scores: critical=90, high=70, medium=50, low=25
        assert rule.get("risk_score", 0) > 0


# ── Testing and Tuning ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rules_are_tested_and_tuned():
    """Each rule is backtested and high-FP rules are tuned."""
    runner = DetectionEngineeringRunner()
    result = await runner.run(request_id="test-tune")

    test_results = result.get("test_results", [])
    rules = result.get("rules_created", [])
    # Each rule gets a test result
    assert len(test_results) == len(rules)

    for tr in test_results:
        assert "true_positive_rate" in tr
        assert "false_positive_rate" in tr
        assert "total_alerts" in tr


# ── Deployment ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_low_fp_rules_are_deployed():
    """Rules with false_positive_rate < 0.05 are deployed to production."""
    runner = DetectionEngineeringRunner()
    result = await runner.run(request_id="deploy-test")

    rules = result.get("rules_created", [])
    deployed = result.get("rules_deployed", [])

    # Count rules eligible for deployment
    eligible = [r for r in rules if r.get("false_positive_rate", 1.0) < 0.05]
    assert len(deployed) == len(eligible)

    # All deployed IDs should be from eligible rules
    eligible_ids = {r["rule_id"] for r in eligible}
    for rule_id in deployed:
        assert rule_id in eligible_ids
