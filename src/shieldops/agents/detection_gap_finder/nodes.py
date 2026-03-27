"""Detection Gap Finder Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    AttackSimulation,
    BlindSpot,
    DetectionMonitor,
    DetectionOutcome,
    GapFinderStage,
    TechniqueSelection,
)
from .prompts import (
    SYSTEM_ANALYZE_BLIND_SPOTS,
    SYSTEM_PRIORITIZE_GAPS,
    SYSTEM_REPORT,
    BlindSpotAnalysisOutput,
    GapPriorityOutput,
    GapReportOutput,
)
from .tools import DetectionGapFinderToolkit

logger = structlog.get_logger()


async def select_techniques(
    state: dict[str, Any],
    toolkit: DetectionGapFinderToolkit,
) -> dict[str, Any]:
    """Select MITRE techniques for safe simulation."""
    logger.info("gap_finder.node.select_techniques")

    tenant_id = state.get("tenant_id", "")
    techniques = await toolkit.select_techniques(
        tenant_id,
    )
    data = [t.model_dump() for t in techniques]

    return {
        "current_stage": (GapFinderStage.SELECT_TECHNIQUES.value),
        "techniques_selected": data,
        "reasoning_chain": (
            state.get("reasoning_chain", [])
            + [f"Selected {len(techniques)} techniques for simulation"]
        ),
    }


async def simulate_attacks(
    state: dict[str, Any],
    toolkit: DetectionGapFinderToolkit,
) -> dict[str, Any]:
    """Run safe attack simulations."""
    logger.info("gap_finder.node.simulate_attacks")

    raw = state.get("techniques_selected", [])
    techniques = [TechniqueSelection(**t) for t in raw]
    sims = await toolkit.simulate_attacks(techniques)
    data = [s.model_dump() for s in sims]

    return {
        "current_stage": (GapFinderStage.SIMULATE_ATTACKS.value),
        "simulations_run": data,
        "reasoning_chain": (
            state.get("reasoning_chain", [])
            + [f"Ran {len(sims)} safe simulations (log replay/atomic tests only)"]
        ),
    }


async def monitor_detections(
    state: dict[str, Any],
    toolkit: DetectionGapFinderToolkit,
) -> dict[str, Any]:
    """Monitor whether detections fired."""
    logger.info("gap_finder.node.monitor_detections")

    raw = state.get("simulations_run", [])
    sims = [AttackSimulation(**s) for s in raw]
    monitors = await toolkit.monitor_detections(sims)
    data = [m.model_dump() for m in monitors]

    detected = sum(1 for m in monitors if m.outcome == DetectionOutcome.DETECTED)
    total = len(monitors)
    rate = round(detected / total * 100, 1) if total else 0.0

    return {
        "current_stage": (GapFinderStage.MONITOR_DETECTIONS.value),
        "detections_monitored": data,
        "detection_rate": rate,
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Detection rate: {rate}% ({detected}/{total})"]
        ),
    }


async def identify_blind_spots(
    state: dict[str, Any],
    toolkit: DetectionGapFinderToolkit,
) -> dict[str, Any]:
    """Identify detection blind spots."""
    logger.info("gap_finder.node.identify_blind_spots")

    raw_mon = state.get("detections_monitored", [])
    monitors = [DetectionMonitor(**m) for m in raw_mon]
    raw_tech = state.get("techniques_selected", [])
    techniques = [TechniqueSelection(**t) for t in raw_tech]

    spots = await toolkit.identify_blind_spots(
        monitors,
        techniques,
    )

    # LLM root cause analysis
    for spot in spots:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_ANALYZE_BLIND_SPOTS,
                user_prompt=(
                    f"Technique: {spot.technique_id} "
                    f"- {spot.technique_name}\n"
                    f"Outcome: {spot.outcome}\n"
                    f"Data sources: "
                    f"{', '.join(spot.data_sources_available)}"
                ),
                output_schema=BlindSpotAnalysisOutput,
            )
            spot.root_cause = result.root_cause
        except Exception:
            logger.debug(
                "gap_finder.llm_blind_spot_fallback",
                technique=spot.technique_id,
            )

    data = [s.model_dump() for s in spots]

    return {
        "current_stage": (GapFinderStage.IDENTIFY_BLIND_SPOTS.value),
        "blind_spots": data,
        "missed_techniques": len(spots),
        "reasoning_chain": (state.get("reasoning_chain", []) + [f"Found {len(spots)} blind spots"]),
    }


async def prioritize_gaps(
    state: dict[str, Any],
    toolkit: DetectionGapFinderToolkit,
) -> dict[str, Any]:
    """Prioritize detection gaps by risk."""
    logger.info("gap_finder.node.prioritize_gaps")

    raw = state.get("blind_spots", [])
    spots = [BlindSpot(**s) for s in raw]
    prioritized = await toolkit.prioritize_gaps(spots)

    # LLM enhancement for prioritization
    for gap in prioritized:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_PRIORITIZE_GAPS,
                user_prompt=(
                    f"Gap: {gap.technique_id} "
                    f"- {gap.technique_name}\n"
                    f"Current risk: {gap.risk_score}"
                ),
                output_schema=GapPriorityOutput,
            )
            gap.risk_score = result.risk_score
            gap.exploitability = result.exploitability
            gap.business_impact = result.business_impact
            gap.remediation_effort = result.remediation_effort
        except Exception:
            logger.debug(
                "gap_finder.llm_priority_fallback",
                technique=gap.technique_id,
            )

    data = [g.model_dump() for g in prioritized]

    return {
        "current_stage": (GapFinderStage.PRIORITIZE_GAPS.value),
        "prioritized_gaps": data,
        "reasoning_chain": (
            state.get("reasoning_chain", [])
            + [f"Prioritized {len(prioritized)} gaps by risk score"]
        ),
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: DetectionGapFinderToolkit,
) -> dict[str, Any]:
    """Generate final gap analysis report."""
    logger.info("gap_finder.node.generate_report")

    try:
        context = json.dumps(
            {
                "detection_rate": state.get(
                    "detection_rate",
                    0,
                ),
                "missed_techniques": state.get(
                    "missed_techniques",
                    0,
                ),
                "blind_spots": state.get(
                    "blind_spots",
                    [],
                )[:5],
                "prioritized_gaps": state.get(
                    "prioritized_gaps",
                    [],
                )[:5],
            },
            default=str,
        )
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Gap analysis results:\n{context}"),
            output_schema=GapReportOutput,
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("gap_finder.llm_report_fallback")
        rate = state.get("detection_rate", 0)
        missed = state.get("missed_techniques", 0)
        summary = f"Detection rate: {rate}%. {missed} techniques missed."

    return {
        "current_stage": GapFinderStage.REPORT.value,
        "reasoning_chain": (state.get("reasoning_chain", []) + [f"Report: {summary[:120]}"]),
    }
