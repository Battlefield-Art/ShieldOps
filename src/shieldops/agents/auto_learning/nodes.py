"""Auto Learning Agent — Node function implementations."""

from __future__ import annotations

import uuid
from typing import Any, cast

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import (
    BaselineMetrics,
    ExperimentOutcome,
    ExperimentResult,
    LearningStage,
    Proposal,
)
from .prompts import SYSTEM_EVALUATE
from .tools import AutoLearningToolkit

logger = structlog.get_logger()


class _EvaluationLLMResult(BaseModel):
    """Structured LLM output for experiment evaluation."""

    summary: str = Field(description="Brief summary of experiment evaluation")
    recommendations: list[str] = Field(description="Recommendations for next iteration")
    should_continue: bool = Field(description="Whether the learning loop should continue")
    confidence: float = Field(description="Confidence in the evaluation (0.0-1.0)")


# Re-export AutoLearningState for graph.py type references
__all__ = [
    "assess_baseline",
    "generate_proposals",
    "run_experiments",
    "evaluate_and_decide",
]


async def assess_baseline(
    state: dict[str, Any],
    toolkit: AutoLearningToolkit,
) -> dict[str, Any]:
    """Assess current performance baseline and identify improvement areas."""
    logger.info("auto_learning.node.assess")

    baseline_data = await toolkit.get_baseline_metrics()
    baseline = BaselineMetrics(**baseline_data) if baseline_data else BaselineMetrics()

    areas = await toolkit.identify_improvement_areas(baseline.model_dump())
    area_names = [a["area"] for a in areas]

    return {
        "stage": LearningStage.PROPOSE.value,
        "baseline": baseline.model_dump(),
        "improvement_areas": area_names,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Baseline assessed, {len(areas)} improvement areas identified: {area_names}"],
    }


async def generate_proposals(
    state: dict[str, Any],
    toolkit: AutoLearningToolkit,
) -> dict[str, Any]:
    """Generate concrete proposals for the identified improvement areas."""
    logger.info("auto_learning.node.propose")
    baseline = state.get("baseline", {})
    areas = await toolkit.identify_improvement_areas(baseline)

    raw_proposals = await toolkit.generate_proposals(areas)
    proposals = []
    for p in raw_proposals:
        proposal = Proposal(id=str(uuid.uuid4()), **p)
        proposals.append(proposal.model_dump())

    return {
        "stage": LearningStage.EXPERIMENT.value,
        "proposals": proposals,
        "current_proposal": proposals[0] if proposals else None,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Generated {len(proposals)} proposals"],
    }


async def run_experiments(
    state: dict[str, Any],
    toolkit: AutoLearningToolkit,
) -> dict[str, Any]:
    """Execute experiments for each proposal within budget constraints."""
    logger.info("auto_learning.node.experiment")
    proposals = state.get("proposals", [])
    budget = state.get("budget", {})

    results: list[dict[str, Any]] = []
    for proposal in proposals:
        result = await toolkit.run_experiment(proposal, budget)
        result["proposal_id"] = proposal.get("id", "")
        experiment = ExperimentResult(**result)
        results.append(experiment.model_dump())

    return {
        "stage": LearningStage.EVALUATE.value,
        "experiment_results": results,
        "total_experiments": len(results),
        "reasoning_chain": state.get("reasoning_chain", []) + [f"Ran {len(results)} experiments"],
    }


async def evaluate_and_decide(
    state: dict[str, Any],
    toolkit: AutoLearningToolkit,
) -> dict[str, Any]:
    """Evaluate results and accept/reject each change."""
    logger.info("auto_learning.node.evaluate")
    results = state.get("experiment_results", [])
    proposals = state.get("proposals", [])

    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []

    proposal_map = {p.get("id", ""): p for p in proposals}

    for result in results:
        proposal = proposal_map.get(result.get("proposal_id", ""), {})
        outcome = result.get("outcome", "inconclusive")

        if outcome == ExperimentOutcome.ACCEPTED.value:
            await toolkit.apply_change(proposal, dry_run=True)
            accepted.append(
                {
                    "proposal": proposal,
                    "result": result,
                }
            )
        elif outcome in (
            ExperimentOutcome.REJECTED.value,
            ExperimentOutcome.TIMED_OUT.value,
        ):
            if result.get("rollback_needed"):
                await toolkit.rollback_change(proposal)
            rejected.append(
                {
                    "proposal": proposal,
                    "result": result,
                }
            )

    total = len(results)
    acceptance_rate = len(accepted) / total if total > 0 else 0.0
    cumulative_improvement = sum(r["result"].get("improvement_pct", 0.0) for r in accepted)

    recommendations: list[str] = []

    # LLM enhancement: deeper evaluation reasoning
    try:
        import json

        eval_context = json.dumps(
            {
                "total_experiments": total,
                "accepted": len(accepted),
                "rejected": len(rejected),
                "acceptance_rate": acceptance_rate,
                "cumulative_improvement": cumulative_improvement,
                "accepted_proposals": [
                    {
                        "area": a["proposal"].get("area"),
                        "improvement_pct": a["result"].get("improvement_pct"),
                    }
                    for a in accepted
                ],
                "rejected_proposals": [
                    {
                        "area": r["proposal"].get("area"),
                        "outcome": r["result"].get("outcome"),
                    }
                    for r in rejected
                ],
            },
            default=str,
        )
        llm_result = cast(
            _EvaluationLLMResult,
            await llm_structured(
                system_prompt=SYSTEM_EVALUATE,
                user_prompt=f"Experiment evaluation results:\n{eval_context}",
                schema=_EvaluationLLMResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="evaluate_and_decide",
            llm_confidence=llm_result.confidence,
            should_continue=llm_result.should_continue,
        )
        if llm_result.recommendations:
            recommendations = llm_result.recommendations
    except Exception:
        logger.debug("llm_enhancement_skipped", node="evaluate_and_decide")

    if not recommendations:
        if accepted:
            recommendations.append(
                f"{len(accepted)} improvements accepted, "
                f"cumulative improvement: {cumulative_improvement:.2f}%"
            )
        if rejected:
            recommendations.append(f"{len(rejected)} proposals rejected — review parameters")
        if not recommendations:
            recommendations.append("No actionable improvements found this iteration")

    return {
        "stage": LearningStage.DECIDE.value,
        "accepted_changes": accepted,
        "rejected_changes": rejected,
        "acceptance_rate": round(acceptance_rate, 4),
        "cumulative_improvement": round(cumulative_improvement, 4),
        "recommendations": recommendations,
        "confidence_score": round(acceptance_rate, 4),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Accepted {len(accepted)}/{total}, improvement {cumulative_improvement:.2f}%"],
    }
