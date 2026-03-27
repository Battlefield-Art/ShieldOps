"""Detection Engineering Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CoverageGap,
    DetectionRule,
    DetectionStage,
    RuleStatus,
)
from .tools import DetectionEngineeringToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def assess_coverage(
    state: dict[str, Any], toolkit: DetectionEngineeringToolkit
) -> dict[str, Any]:
    """Assess MITRE ATT&CK coverage gaps."""
    logger.info("detection_engineering.node.assess_coverage")
    state = _to_dict(state)

    gaps = await toolkit.assess_mitre_coverage()
    gap_dicts = [g.model_dump() for g in gaps]

    # Calculate overall coverage
    avg_coverage = (
        sum(g.current_coverage for g in gaps) / len(gaps) if gaps else 1.0
    )  # No gaps means full coverage

    return {
        "stage": DetectionStage.CREATE_RULES.value,
        "coverage_gaps": gap_dicts,
        "overall_coverage": round(avg_coverage, 4),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Identified {len(gaps)} MITRE ATT&CK coverage gaps"],
    }


async def create_rules(
    state: dict[str, Any], toolkit: DetectionEngineeringToolkit
) -> dict[str, Any]:
    """Create detection rules for identified coverage gaps."""
    logger.info("detection_engineering.node.create_rules")
    state = _to_dict(state)

    raw_gaps = state.get("coverage_gaps", [])
    gaps = [CoverageGap(**g) for g in raw_gaps]

    rules: list[dict[str, Any]] = []
    for gap in gaps:
        rule = await toolkit.create_detection_rule(gap)
        rules.append(rule.model_dump())

    reasoning_note = f"Created {len(rules)} detection rules for coverage gaps"

    # LLM enhancement: intelligent rule creation analysis
    try:
        from .prompts import SYSTEM_CREATE_RULES, RuleCreationResult

        rules_context = json.dumps(
            {
                "total_gaps": len(gaps),
                "rules_created": len(rules),
                "gaps_summary": [
                    {
                        "technique_id": g.technique_id,  # type: ignore[attr-defined]
                        "technique_name": g.technique_name,  # type: ignore[attr-defined]
                        "current_coverage": g.current_coverage,
                    }
                    for g in gaps[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RuleCreationResult,
            await llm_structured(
                system_prompt=SYSTEM_CREATE_RULES,
                user_prompt=f"Detection rule creation context:\n{rules_context}",
                schema=RuleCreationResult,
            ),
        )
        logger.info("llm_enhanced", agent="detection_engineering", node="create_rules")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="detection_engineering", node="create_rules")

    return {
        "stage": DetectionStage.TEST_RULES.value,
        "rules_created": rules,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def backtest_and_tune(
    state: dict[str, Any], toolkit: DetectionEngineeringToolkit
) -> dict[str, Any]:
    """Test rules against historical data and tune to reduce false positives."""
    logger.info("detection_engineering.node.test_and_tune")
    state = _to_dict(state)

    raw_rules = state.get("rules_created", [])
    rules = [DetectionRule(**r) for r in raw_rules]

    test_results: list[dict[str, Any]] = []
    tuning_results: list[dict[str, Any]] = []
    tuned_rules: list[dict[str, Any]] = []

    for rule in rules:
        # Test the rule
        result = await toolkit.test_rule(rule, days=7)
        test_results.append(result)

        # Update rule with test FP rate
        rule.false_positive_rate = result.get("false_positive_rate", 0.0)
        rule.status = RuleStatus.TESTING

        # Tune if FP rate is above threshold
        if result.get("false_positive_rate", 0.0) > 0.05:
            tuning = await toolkit.tune_rule(rule, fp_threshold=0.05)
            tuning_results.append(tuning.model_dump())
            rule.false_positive_rate = tuning.tuned_fp_rate
            rule.status = RuleStatus.TUNING

        tuned_rules.append(rule.model_dump())

    return {
        "stage": DetectionStage.DEPLOY.value,
        "rules_created": tuned_rules,
        "test_results": test_results,
        "tuning_results": tuning_results,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Tested {len(rules)} rules, tuned {len(tuning_results)} with high FP rates"],
    }


async def deploy_rules(
    state: dict[str, Any], toolkit: DetectionEngineeringToolkit
) -> dict[str, Any]:
    """Deploy rules that meet quality thresholds."""
    logger.info("detection_engineering.node.deploy_rules")
    state = _to_dict(state)

    raw_rules = state.get("rules_created", [])
    rules = [DetectionRule(**r) for r in raw_rules]

    deployed_ids: list[str] = []
    for rule in rules:
        if rule.false_positive_rate < 0.05:
            result = await toolkit.deploy_rule(rule)
            if result.get("deployed", False):
                deployed_ids.append(rule.rule_id)

    return {
        "stage": DetectionStage.DEPLOY.value,
        "rules_deployed": deployed_ids,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Deployed {len(deployed_ids)} rules to production"],
    }
