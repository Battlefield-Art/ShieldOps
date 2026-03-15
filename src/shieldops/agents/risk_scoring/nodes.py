"""Risk Scoring Agent — Node function implementations."""

from __future__ import annotations

from typing import Any, cast

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import (
    RiskEntity,
    RiskLevel,
    RiskStage,
    SecurityObservation,
)
from .prompts import SYSTEM_DECIDE
from .tools import RiskScoringToolkit

logger = structlog.get_logger()


class _DecisionLLMResult(BaseModel):
    """Structured LLM output for risk-based action decisions."""

    summary: str = Field(description="Brief summary of risk assessment")
    recommendations: list[str] = Field(description="Prioritized action recommendations")
    overall_risk_narrative: str = Field(description="Narrative explaining the risk landscape")
    confidence: float = Field(description="Confidence in the decision analysis (0.0-1.0)")


async def collect_observations(
    state: dict[str, Any], toolkit: RiskScoringToolkit
) -> dict[str, Any]:
    """Collect raw security observations from detection sources."""
    logger.info("risk_scoring.node.collect")
    window = state.get("time_window_hours", 24)

    raw = await toolkit.collect_observations(time_window_hours=window)
    observations = (
        [SecurityObservation(**o).model_dump() for o in raw]
        if raw
        else state.get("raw_observations", [])
    )

    return {
        "stage": RiskStage.ENRICH.value,
        "raw_observations": observations,
        "total_observations": len(observations),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(observations)} observations in {window}h window"],
    }


async def enrich_observations(state: dict[str, Any], toolkit: RiskScoringToolkit) -> dict[str, Any]:
    """Enrich observations with MITRE ATT&CK context and metadata."""
    logger.info("risk_scoring.node.enrich")
    raw = state.get("raw_observations", [])

    enriched: list[dict[str, Any]] = []
    for obs in raw:
        enriched_obs = await toolkit.enrich_with_mitre(obs)
        enriched.append(enriched_obs)

    tactics_found = {e.get("mitre_tactic", "") for e in enriched if e.get("mitre_tactic")}

    return {
        "stage": RiskStage.AGGREGATE.value,
        "enriched_observations": enriched,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Enriched {len(enriched)} observations, {len(tactics_found)} unique MITRE tactics"],
    }


async def aggregate_by_entity(state: dict[str, Any], toolkit: RiskScoringToolkit) -> dict[str, Any]:
    """Aggregate observations by entity (user, host, IP)."""
    logger.info("risk_scoring.node.aggregate")
    enriched = state.get("enriched_observations", [])

    entity_map: dict[str, list[dict[str, Any]]] = {}
    for obs in enriched:
        entity = obs.get("entity", "unknown")
        entity_map.setdefault(entity, []).append(obs)

    risk_entities: list[dict[str, Any]] = []
    for entity, obs_list in entity_map.items():
        entity_type = obs_list[0].get("entity_type", "host") if obs_list else "host"
        criticality_info = await toolkit.get_entity_criticality(entity, entity_type)
        criticality = criticality_info.get("criticality", 0.5)

        score_result = toolkit.compute_composite_score(obs_list, criticality)

        tactics_seen = score_result.get("unique_tactics", [])
        timestamps = [o.get("timestamp", 0.0) for o in obs_list if o.get("timestamp")]

        risk_entity = RiskEntity(
            entity=entity,
            entity_type=entity_type,
            observations=[SecurityObservation(**o) for o in obs_list],
            composite_score=score_result["composite_score"],
            risk_level=RiskLevel(score_result["risk_level"]),
            tactics_seen=tactics_seen,
            first_seen=min(timestamps) if timestamps else 0.0,
            last_seen=max(timestamps) if timestamps else 0.0,
        )
        risk_entities.append(risk_entity.model_dump())

    risk_entities.sort(key=lambda x: x["composite_score"], reverse=True)
    high_risk = sum(1 for r in risk_entities if r["composite_score"] >= 0.6)

    return {
        "stage": RiskStage.SCORE.value,
        "risk_entities": risk_entities,
        "high_risk_entities": high_risk,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Aggregated into {len(risk_entities)} entities, {high_risk} high-risk"],
    }


async def decide_actions(state: dict[str, Any], toolkit: RiskScoringToolkit) -> dict[str, Any]:
    """Make action decisions based on risk scores."""
    logger.info("risk_scoring.node.decide")
    entities = state.get("risk_entities", [])
    auto_thresh = state.get("autonomous_threshold", 0.85)
    approval_thresh = state.get("approval_threshold", 0.5)

    decisions: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    recommendations: list[str] = []

    for entity_data in entities:
        score = entity_data.get("composite_score", 0.0)
        entity_name = entity_data.get("entity", "")
        decision = toolkit.decide_action(score, auto_thresh, approval_thresh)
        decision["entity"] = entity_name
        decisions.append(decision)

        if decision["decision"] in ("autonomous", "human_approval"):
            alerts.append(
                {
                    "entity": entity_name,
                    "risk_level": entity_data.get("risk_level", "low"),
                    "composite_score": score,
                    "decision": decision["decision"],
                    "actions": decision["recommended_actions"],
                    "tactics": entity_data.get("tactics_seen", []),
                }
            )

    autonomous_count = sum(1 for d in decisions if d["decision"] == "autonomous")
    approval_count = sum(1 for d in decisions if d["decision"] == "human_approval")
    monitor_count = sum(1 for d in decisions if d["decision"] == "monitor")

    # LLM enhancement: richer decision reasoning
    try:
        import json

        entity_summary = json.dumps(
            [
                {
                    "entity": e.get("entity"),
                    "score": e.get("composite_score"),
                    "risk_level": e.get("risk_level"),
                    "tactics": e.get("tactics_seen", []),
                }
                for e in entities[:20]  # cap to avoid prompt overflow
            ],
            default=str,
        )
        user_prompt = (
            f"Risk entities:\n{entity_summary}\n\n"
            f"Thresholds: autonomous={auto_thresh}, approval={approval_thresh}\n"
            f"Decisions: {autonomous_count} auto, {approval_count} approval, "
            f"{monitor_count} monitor"
        )
        llm_result = cast(
            _DecisionLLMResult,
            await llm_structured(
                system_prompt=SYSTEM_DECIDE,
                user_prompt=user_prompt,
                schema=_DecisionLLMResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="decide_actions",
            llm_confidence=llm_result.confidence,
        )
        # Use LLM recommendations if available
        if llm_result.recommendations:
            recommendations = llm_result.recommendations
    except Exception:
        logger.debug("llm_enhancement_skipped", node="decide_actions")

    if not recommendations:
        if autonomous_count > 0:
            recommendations.append(f"{autonomous_count} entities require autonomous containment")
        if approval_count > 0:
            recommendations.append(f"{approval_count} entities need analyst review")
        if not recommendations:
            recommendations.append("No entities exceed risk thresholds")

    overall_confidence = max((e.get("composite_score", 0.0) for e in entities), default=0.0)

    return {
        "stage": RiskStage.DECIDE.value,
        "action_decisions": decisions,
        "alerts_generated": alerts,
        "recommendations": recommendations,
        "confidence_score": round(overall_confidence, 4),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Decisions: {autonomous_count} auto, "
            f"{approval_count} approval, {monitor_count} monitor"
        ],
    }
