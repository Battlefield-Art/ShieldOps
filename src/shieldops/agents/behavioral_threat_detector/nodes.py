"""Node implementations for the Behavioral Threat Detector LangGraph workflow.

Each node is an async function that:
1. Queries behavioral systems via the toolkit
2. Uses the LLM to analyze and reason about data
3. Updates the BTD state with findings
4. Records its reasoning step in the audit trail
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.behavioral_threat_detector.models import (
    BehavioralThreatDetectorState,
    BehaviorBaseline,
    BehaviorDeviation,
    BehaviorRecord,
    BTDStage,
    ReasoningStep,
    ThreatScore,
)
from shieldops.agents.behavioral_threat_detector.prompts import (
    SYSTEM_BUILD_BASELINES,
    SYSTEM_COLLECT_BEHAVIORS,
    SYSTEM_DETECT_DEVIATIONS,
    SYSTEM_GENERATE_ALERTS,
    SYSTEM_SCORE_THREATS,
    AlertGenerationAnalysis,
    BaselineAnalysis,
    BehaviorCollectionAnalysis,
    DeviationAnalysis,
    ThreatScoringAnalysis,
)
from shieldops.agents.behavioral_threat_detector.tools import (
    BehavioralThreatDetectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit, set by runner at startup.
_toolkit: BehavioralThreatDetectorToolkit | None = None


def set_toolkit(
    toolkit: BehavioralThreatDetectorToolkit,
) -> None:
    """Configure toolkit used by all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> BehavioralThreatDetectorToolkit:
    if _toolkit is None:
        return BehavioralThreatDetectorToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# ---- Node: collect_behaviors ----


async def collect_behaviors(
    state: BehavioralThreatDetectorState,
) -> dict[str, Any]:
    """Collect behavioral data from configured sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "btd_collecting_behaviors",
        request_id=state.request_id,
    )

    sources = state.config.get("sources")
    records = await toolkit.collect_behaviors(
        tenant_id=state.tenant_id,
        sources=sources,
    )

    entities = list({r.entity_id for r in records})
    output_summary = f"Collected {len(records)} behavior records from {len(entities)} entities."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "records_collected": len(records),
                "entities": len(entities),
                "sources": list({r.source.value for r in records}),
                "entity_types": list({r.entity_type for r in records}),
            },
            default=str,
        )
        llm_result = cast(
            BehaviorCollectionAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_COLLECT_BEHAVIORS,
                user_prompt=(f"Behavior collection results:\n{ctx}"),
                schema=BehaviorCollectionAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(records)} records."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_behaviors",
        )

    step = ReasoningStep(
        step_number=1,
        action="collect_behaviors",
        input_summary=("Collecting behavioral data from sources"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="behavior_collector",
    )

    return {
        "behaviors": [r.model_dump() for r in records],
        "entity_count": len(entities),
        "stage": BTDStage.BUILD_BASELINES,
        "session_start": start,
        "reasoning_chain": [step],
        "current_step": "collect_behaviors",
    }


# ---- Node: build_baselines ----


async def build_baselines(
    state: BehavioralThreatDetectorState,
) -> dict[str, Any]:
    """Build behavioral baselines from collected data."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    records = [BehaviorRecord.model_validate(b) for b in state.behaviors]

    logger.info(
        "btd_building_baselines",
        request_id=state.request_id,
        record_count=len(records),
    )

    baselines = await toolkit.build_baselines(records)

    output_summary = f"Built {len(baselines)} baselines from {len(records)} records."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "records": len(records),
                "baselines": len(baselines),
                "entities": len({bl.entity_id for bl in baselines}),
                "sources": list({bl.source.value for bl in baselines}),
            },
            default=str,
        )
        llm_result = cast(
            BaselineAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_BUILD_BASELINES,
                user_prompt=(f"Baseline building results:\n{ctx}"),
                schema=BaselineAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Quality: {llm_result.baseline_quality}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="build_baselines",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="build_baselines",
        input_summary=(f"Building baselines from {len(records)} records"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="baseline_builder",
    )

    return {
        "baselines": [bl.model_dump() for bl in baselines],
        "stage": BTDStage.DETECT_DEVIATIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "build_baselines",
    }


# ---- Node: detect_deviations ----


async def detect_deviations(
    state: BehavioralThreatDetectorState,
) -> dict[str, Any]:
    """Detect behavioral deviations from baselines."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    records = [BehaviorRecord.model_validate(b) for b in state.behaviors]
    baselines = [BehaviorBaseline.model_validate(bl) for bl in state.baselines]

    logger.info(
        "btd_detecting_deviations",
        request_id=state.request_id,
        record_count=len(records),
        baseline_count=len(baselines),
    )

    deviations = await toolkit.detect_deviations(records, baselines)
    critical = sum(1 for d in deviations if d.severity == "critical")

    output_summary = f"Detected {len(deviations)} deviations. {critical} critical."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "records": len(records),
                "baselines": len(baselines),
                "deviations": len(deviations),
                "critical": critical,
                "types": [d.deviation_type.value for d in deviations],
            },
            default=str,
        )
        llm_result = cast(
            DeviationAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_DETECT_DEVIATIONS,
                user_prompt=(f"Deviation detection results:\n{ctx}"),
                schema=DeviationAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Threat: {llm_result.threat_level}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_deviations",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_deviations",
        input_summary=(f"Detecting deviations from {len(baselines)} baselines"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="deviation_detector",
    )

    return {
        "deviations": [d.model_dump() for d in deviations],
        "deviation_count": len(deviations),
        "stage": BTDStage.SCORE_THREATS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_deviations",
    }


# ---- Node: score_threats ----


async def score_threats(
    state: BehavioralThreatDetectorState,
) -> dict[str, Any]:
    """Score threat levels from detected deviations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    deviations = [BehaviorDeviation.model_validate(d) for d in state.deviations]

    logger.info(
        "btd_scoring_threats",
        request_id=state.request_id,
        deviation_count=len(deviations),
    )

    scores = await toolkit.score_threats(deviations)
    high_risk = sum(1 for s in scores if s.overall_score > 0.7)

    output_summary = f"Scored {len(scores)} entities. {high_risk} high-risk."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "deviations": len(deviations),
                "scores": len(scores),
                "high_risk": high_risk,
                "avg_score": round(
                    sum(s.overall_score for s in scores) / max(len(scores), 1),
                    3,
                ),
            },
            default=str,
        )
        llm_result = cast(
            ThreatScoringAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_SCORE_THREATS,
                user_prompt=f"Threat scoring results:\n{ctx}",
                schema=ThreatScoringAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Risk: {llm_result.risk_assessment}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="score_threats",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="score_threats",
        input_summary=(f"Scoring threats from {len(deviations)} deviations"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="threat_scorer",
    )

    return {
        "threat_scores": [s.model_dump() for s in scores],
        "stage": BTDStage.GENERATE_ALERTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "score_threats",
    }


# ---- Node: generate_alerts ----


async def generate_alerts(
    state: BehavioralThreatDetectorState,
) -> dict[str, Any]:
    """Generate alerts from threat scores."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scores = [ThreatScore.model_validate(s) for s in state.threat_scores]

    logger.info(
        "btd_generating_alerts",
        request_id=state.request_id,
        score_count=len(scores),
    )

    alerts = await toolkit.generate_alerts(scores)

    output_summary = f"Generated {len(alerts)} alerts from {len(scores)} threat scores."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "scores": len(scores),
                "alerts": len(alerts),
                "severities": [a.severity for a in alerts],
            },
            default=str,
        )
        llm_result = cast(
            AlertGenerationAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_GENERATE_ALERTS,
                user_prompt=(f"Alert generation results:\n{ctx}"),
                schema=AlertGenerationAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(alerts)} alerts."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_alerts",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_alerts",
        input_summary=(f"Generating alerts from {len(scores)} threat scores"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="alert_generator",
    )

    return {
        "alerts": [a.model_dump() for a in alerts],
        "alert_count": len(alerts),
        "stage": BTDStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_alerts",
    }


# ---- Node: generate_report ----


async def generate_report(
    state: BehavioralThreatDetectorState,
) -> dict[str, Any]:
    """Final reporting node -- summarize the detection cycle."""
    start = datetime.now(UTC)

    session_duration_ms = 0
    if state.session_start:
        session_duration_ms = _elapsed_ms(state.session_start)

    output_summary = (
        f"BTD cycle complete. "
        f"{len(state.behaviors)} behaviors, "
        f"{len(state.baselines)} baselines, "
        f"{state.deviation_count} deviations, "
        f"{len(state.threat_scores)} scored, "
        f"{state.alert_count} alerts. "
        f"Duration: {session_duration_ms}ms."
    )

    logger.info(
        "btd_report",
        request_id=state.request_id,
        summary=output_summary,
    )

    report = {
        "request_id": state.request_id,
        "tenant_id": state.tenant_id,
        "behaviors_collected": len(state.behaviors),
        "baselines_built": len(state.baselines),
        "entities_analyzed": state.entity_count,
        "deviations_detected": state.deviation_count,
        "threats_scored": len(state.threat_scores),
        "alerts_generated": state.alert_count,
        "duration_ms": session_duration_ms,
        "summary": output_summary,
    }

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=("Generating final threat detection report"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": session_duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
