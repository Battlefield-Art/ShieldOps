"""Node implementations for the Deception Network Manager
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.deception_network_manager.models import (
    DeceptionNetworkManagerState,
    DNMStage,
    ReasoningStep,
)
from shieldops.agents.deception_network_manager.prompts import (
    SYSTEM_BEHAVIOR,
    SYSTEM_CLASSIFY,
    SYSTEM_DEPLOY,
    SYSTEM_REPORT,
    AttackerClassificationOutput,
    BehaviorAnalysisOutput,
    DecoyDeploymentOutput,
    IntelReportOutput,
)
from shieldops.agents.deception_network_manager.tools import (
    DeceptionNetworkManagerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: DeceptionNetworkManagerToolkit | None = None


def _get_toolkit() -> DeceptionNetworkManagerToolkit:
    if _toolkit is None:
        return DeceptionNetworkManagerToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: datetime,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: deploy_decoys
# ------------------------------------------------------------------


async def deploy_decoys(
    state: DeceptionNetworkManagerState,
) -> dict[str, Any]:
    """Deploy deception assets across target network
    segments."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    types = [t.value for t in state.decoy_types]
    results = await toolkit.deploy_decoys(
        segments=state.network_segments,
        decoy_types=types,
        scope=state.scope,
    )

    decoys: list[dict[str, Any]] = list(results)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "segments": state.network_segments,
                "decoy_types": types,
                "scope": state.scope,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DEPLOY,
            user_prompt=f"Plan decoy deployment:\n{ctx}",
            schema=DecoyDeploymentOutput,
        )
        if llm_out.decoys:  # type: ignore[union-attr]
            decoys = [
                *decoys,
                *llm_out.decoys,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="deploy_decoys",
            count=len(llm_out.decoys),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="deploy_decoys",
        )

    step = _step(
        state.reasoning_chain,
        "deploy_decoys",
        f"Segments: {len(state.network_segments)}, types={len(types)}",
        f"Deployed {len(decoys)} decoys",
        start,
        "deception_platform",
    )

    return {
        "decoys": decoys,
        "stage": DNMStage.DEPLOY_DECOYS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "deploy_decoys",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: monitor_interactions
# ------------------------------------------------------------------


async def monitor_interactions(
    state: DeceptionNetworkManagerState,
) -> dict[str, Any]:
    """Monitor deployed decoys for attacker interactions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    interactions = await toolkit.monitor_interactions(
        decoys=state.decoys,
    )

    unique_ips = len({i.get("source_ip", "") for i in interactions})

    step = _step(
        state.reasoning_chain,
        "monitor_interactions",
        f"Monitoring {len(state.decoys)} decoys",
        f"Captured {len(interactions)} interactions from {unique_ips} sources",
        start,
        "network_monitor",
    )

    return {
        "interactions": interactions,
        "total_interactions": len(interactions),
        "unique_attackers": unique_ips,
        "stage": DNMStage.MONITOR_INTERACTIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "monitor_interactions",
    }


# ------------------------------------------------------------------
# Node: analyze_behavior
# ------------------------------------------------------------------


async def analyze_behavior(
    state: DeceptionNetworkManagerState,
) -> dict[str, Any]:
    """Analyze attacker behavior patterns from captured
    interactions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    behaviors = await toolkit.analyze_behavior(
        interactions=state.interactions,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "interaction_count": len(state.interactions),
                "interactions_sample": state.interactions[:5],
                "decoy_count": len(state.decoys),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_BEHAVIOR,
            user_prompt=f"Analyze behavior:\n{ctx}",
            schema=BehaviorAnalysisOutput,
        )
        if llm_out.ttp_chain:  # type: ignore[union-attr]
            behaviors.append(
                {
                    "analysis_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "ttp_chain": llm_out.ttp_chain,  # type: ignore[union-attr]
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "lateral_movement": llm_out.lateral_movement,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_behavior",
            ttps=len(llm_out.ttp_chain),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_behavior",
        )

    high_risk = sum(1 for b in behaviors if b.get("risk_score", 0) > 7)

    step = _step(
        state.reasoning_chain,
        "analyze_behavior",
        f"Analyzing {len(state.interactions)} interactions",
        f"Produced {len(behaviors)} analyses, {high_risk} high-risk",
        start,
        "behavior_analyzer",
    )

    return {
        "behaviors": behaviors,
        "high_risk_count": high_risk,
        "stage": DNMStage.ANALYZE_BEHAVIOR,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_behavior",
    }


# ------------------------------------------------------------------
# Node: classify_attacker
# ------------------------------------------------------------------


async def classify_attacker(
    state: DeceptionNetworkManagerState,
) -> dict[str, Any]:
    """Classify attacker profiles from behavioral analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications: list[dict[str, Any]] = []

    raw = await toolkit.classify_attacker(
        behaviors=state.behaviors,
    )
    classifications.extend(raw)

    for behavior in state.behaviors:
        try:
            ctx = _json.dumps(
                {
                    "behavior": behavior,
                    "interactions": state.interactions[:5],
                },
                default=str,
            )
            llm_out = await llm_structured(
                system_prompt=SYSTEM_CLASSIFY,
                user_prompt=f"Classify attacker:\n{ctx}",
                schema=AttackerClassificationOutput,
            )
            classifications.append(
                {
                    "profile": llm_out.profile,  # type: ignore[union-attr]
                    "sophistication": llm_out.sophistication,  # type: ignore[union-attr]
                    "confidence": llm_out.confidence,  # type: ignore[union-attr]
                    "mitre_techniques": llm_out.mitre_techniques,  # type: ignore[union-attr]
                    "intent": llm_out.intent,  # type: ignore[union-attr]
                }
            )
            logger.info(
                "llm_enhanced",
                node="classify_attacker",
                profile=llm_out.profile,  # type: ignore[union-attr]
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="classify_attacker",
            )

    step = _step(
        state.reasoning_chain,
        "classify_attacker",
        f"Classifying {len(state.behaviors)} behaviors",
        f"{len(classifications)} attacker profiles classified",
        start,
        "threat_classifier",
    )

    return {
        "classifications": classifications,
        "stage": DNMStage.CLASSIFY_ATTACKER,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "classify_attacker",
    }


# ------------------------------------------------------------------
# Node: generate_intel
# ------------------------------------------------------------------


async def generate_intel(
    state: DeceptionNetworkManagerState,
) -> dict[str, Any]:
    """Generate threat intelligence from deception
    campaign data."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    intel = await toolkit.generate_threat_intel(
        classifications=state.classifications,
        interactions=state.interactions,
    )

    iocs_count = sum(len(i.get("iocs", [])) for i in intel)

    step = _step(
        state.reasoning_chain,
        "generate_intel",
        (f"Generating intel from {len(state.classifications)} classifications"),
        f"Produced {len(intel)} intel reports, {iocs_count} IOCs",
        start,
        "intel_generator",
    )

    return {
        "intel": intel,
        "iocs_generated": iocs_count,
        "stage": DNMStage.GENERATE_INTEL,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_intel",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: DeceptionNetworkManagerState,
) -> dict[str, Any]:
    """Generate the final deception operations report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {}

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "total_decoys": len(state.decoys),
                "total_interactions": state.total_interactions,
                "unique_attackers": state.unique_attackers,
                "high_risk_count": state.high_risk_count,
                "classifications": state.classifications[:5],
                "intel_sample": state.intel[:5],
                "iocs_generated": state.iocs_generated,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate deception report:\n{ctx}",
            schema=IntelReportOutput,
        )
        if isinstance(llm_out, IntelReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "iocs": llm_out.iocs,
                    "recommendations": llm_out.recommendations,
                    "mitre_coverage": llm_out.mitre_coverage,
                    "effectiveness_rating": llm_out.effectiveness_rating,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                iocs=len(llm_out.iocs),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Track metric
    await toolkit.record_metric(
        metric_name="deception_campaign_completed",
        value=float(state.total_interactions),
        tags={"attackers": str(state.unique_attackers)},
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_interactions} interactions",
        f"Report generated, {state.iocs_generated} IOCs",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": DNMStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
