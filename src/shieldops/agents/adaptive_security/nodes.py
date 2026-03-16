"""Adaptive Security Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AdaptationStage,
    BaselineMetrics,
    ThreatContext,
)
from .tools import AdaptiveSecurityToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def compute_baseline(
    state: dict[str, Any], toolkit: AdaptiveSecurityToolkit
) -> dict[str, Any]:
    """Establish current baselines for security metrics."""
    logger.info("adaptive_security.node.compute_baseline")
    state = _to_dict(state)
    window = state.get("window_hours", 24)

    # Compute baselines for all entity types
    all_baselines: list[dict[str, Any]] = []
    for entity_type in ("host", "user", "ip"):
        baselines = await toolkit.compute_baselines(
            entity_type=entity_type,
            window_hours=window,
        )
        all_baselines.extend([b.model_dump() for b in baselines])

    return {
        "stage": AdaptationStage.DETECT_DRIFT.value,
        "baselines": all_baselines,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Computed {len(all_baselines)} baselines across host/user/ip entities"],
    }


async def detect_and_propose(
    state: dict[str, Any], toolkit: AdaptiveSecurityToolkit
) -> dict[str, Any]:
    """Find drifted metrics and propose threshold adjustments."""
    logger.info("adaptive_security.node.detect_and_propose")
    state = _to_dict(state)
    raw_baselines = state.get("baselines", [])
    threat_ctx_str = state.get("threat_context", ThreatContext.NORMAL.value)
    threat_context = ThreatContext(threat_ctx_str)

    baselines = [BaselineMetrics(**b) for b in raw_baselines]

    # Detect drift
    drifted = await toolkit.detect_drift(baselines)

    # Propose adjustments for drifted metrics
    proposals: list[dict[str, Any]] = []
    for metric in drifted:
        proposal = await toolkit.propose_threshold_adjustment(
            drifted_metric=metric,
            threat_context=threat_context,
        )
        proposals.append(proposal.model_dump())

    return {
        "stage": AdaptationStage.EVALUATE.value,
        "proposals": proposals,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Detected {len(drifted)} drifted metrics, "
            f"generated {len(proposals)} threshold proposals"
        ],
    }


async def evaluate_proposals(
    state: dict[str, Any], toolkit: AdaptiveSecurityToolkit
) -> dict[str, Any]:
    """Dry-run each proposal and decide accept/reject."""
    logger.info("adaptive_security.node.evaluate_proposals")
    state = _to_dict(state)
    from .models import ThresholdProposal

    raw_proposals = state.get("proposals", [])
    proposals = [ThresholdProposal(**p) for p in raw_proposals]

    results: list[dict[str, Any]] = []
    accepted_count = 0
    for proposal in proposals:
        result = await toolkit.evaluate_proposal(proposal, dry_run_hours=4)
        results.append(result.model_dump())
        if result.accepted:
            accepted_count += 1

    total = len(proposals)
    confidence = round(accepted_count / total, 4) if total > 0 else 0.0

    reasoning_note = (
        f"Evaluated {total} proposals: {accepted_count} accepted, {total - accepted_count} rejected"
    )

    # LLM enhancement: deeper evaluation reasoning
    try:
        from .prompts import SYSTEM_EVALUATE, EvaluationResult

        eval_context = json.dumps(
            {
                "total_proposals": total,
                "accepted": accepted_count,
                "rejected": total - accepted_count,
                "proposals_summary": [
                    {"metric": p.metric_name, "old": p.current_value, "new": p.proposed_value}  # type: ignore[attr-defined]
                    for p in proposals[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            EvaluationResult,
            await llm_structured(
                system_prompt=SYSTEM_EVALUATE,
                user_prompt=f"Proposal evaluation context:\n{eval_context}",
                schema=EvaluationResult,
            ),
        )
        logger.info("llm_enhanced", agent="adaptive_security", node="evaluate_proposals")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="adaptive_security", node="evaluate_proposals")

    return {
        "stage": AdaptationStage.APPLY.value,
        "results": results,
        "accepted_count": accepted_count,
        "confidence_score": confidence,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def apply_accepted(state: dict[str, Any], toolkit: AdaptiveSecurityToolkit) -> dict[str, Any]:
    """Apply accepted threshold adjustments."""
    logger.info("adaptive_security.node.apply_accepted")
    state = _to_dict(state)
    from .models import ThresholdProposal

    raw_proposals = state.get("proposals", [])
    raw_results = state.get("results", [])

    proposals = [ThresholdProposal(**p) for p in raw_proposals]

    applied: list[dict[str, Any]] = []
    for i, result_data in enumerate(raw_results):
        if result_data.get("accepted", False) and i < len(proposals):
            adjustment = await toolkit.apply_adjustment(proposals[i])
            applied.append(adjustment)

    return {
        "stage": AdaptationStage.APPLY.value,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Applied {len(applied)} threshold adjustments"],
    }
