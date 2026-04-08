"""Node implementations for the Attack Emulation
Framework Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.attack_emulation_framework.models import (
    AttackEmulationState,
    EmulationStage,
)
from shieldops.agents.attack_emulation_framework.prompts import (
    SYSTEM_ADVERSARY_SELECTION,
    SYSTEM_CAMPAIGN_BUILD,
    SYSTEM_DETECTION_MEASUREMENT,
    SYSTEM_REPORT,
    AdversarySelectionOutput,
    CampaignBuildOutput,
    DetectionMeasurementOutput,
    GapAnalysisReportOutput,
)
from shieldops.agents.attack_emulation_framework.tools import (
    AttackEmulationFrameworkToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AttackEmulationFrameworkToolkit | None = None


def _get_toolkit() -> AttackEmulationFrameworkToolkit:
    if _toolkit is None:
        return AttackEmulationFrameworkToolkit()
    return _toolkit


# ------------------------------------------------------------------
# Node: select_adversary
# ------------------------------------------------------------------


async def select_adversary(
    state: AttackEmulationState,
) -> dict[str, Any]:
    """Select adversary profiles for emulation."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    profiles = await toolkit.select_adversary(
        threat_model={},
        sector="enterprise",
    )

    try:
        ctx = _json.dumps(
            {"profiles": profiles[:5], "tenant": state.tenant_id},
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ADVERSARY_SELECTION,
            user_prompt=f"Select adversary:\n{ctx}",
            schema=AdversarySelectionOutput,
        )
        if llm_out.technique_ids:  # type: ignore[union-attr]
            profiles.append(
                {
                    "name": llm_out.adversary_name,  # type: ignore[union-attr]
                    "tier": llm_out.tier,  # type: ignore[union-attr]
                    "techniques": llm_out.technique_ids,  # type: ignore[union-attr]
                    "rationale": llm_out.rationale,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="select_adversary",
            name=llm_out.adversary_name,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="select_adversary")

    selected = profiles[0] if profiles else {}

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "adversary_profiles": profiles,
        "selected_adversary": selected,
        "stage": EmulationStage.SELECT_ADVERSARY,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Selected {len(profiles)} adversary profiles ({elapsed}ms)",
        ],
        "current_step": "select_adversary",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: build_campaign
# ------------------------------------------------------------------


async def build_campaign(
    state: AttackEmulationState,
) -> dict[str, Any]:
    """Build an emulation campaign from the selected
    adversary profile."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    technique_ids = state.selected_adversary.get("techniques", [])
    campaign = await toolkit.build_campaign(
        adversary=state.selected_adversary,
        technique_ids=technique_ids,
    )

    try:
        ctx = _json.dumps(
            {
                "adversary": state.selected_adversary,
                "techniques": technique_ids[:10],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_CAMPAIGN_BUILD,
            user_prompt=f"Build campaign:\n{ctx}",
            schema=CampaignBuildOutput,
        )
        if llm_out.techniques:  # type: ignore[union-attr]
            campaign = [*campaign, *llm_out.techniques]  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="build_campaign",
            count=len(llm_out.techniques),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="build_campaign")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "campaign_techniques": campaign,
        "stage": EmulationStage.BUILD_CAMPAIGN,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Built campaign with {len(campaign)} techniques ({elapsed}ms)",
        ],
        "current_step": "build_campaign",
    }


# ------------------------------------------------------------------
# Node: execute_techniques
# ------------------------------------------------------------------


async def execute_techniques(
    state: AttackEmulationState,
) -> dict[str, Any]:
    """Execute emulated techniques with safety guards."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.execute_techniques(
        campaign=state.campaign_techniques,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "campaign_techniques": results if results else state.campaign_techniques,
        "techniques_executed": len(results),
        "stage": EmulationStage.EXECUTE_TECHNIQUES,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Executed {len(results)} techniques ({elapsed}ms)",
        ],
        "current_step": "execute_techniques",
    }


# ------------------------------------------------------------------
# Node: measure_detection
# ------------------------------------------------------------------


async def measure_detection(
    state: AttackEmulationState,
) -> dict[str, Any]:
    """Measure detection coverage for executed
    techniques."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    measurements = await toolkit.measure_detection(
        executed=state.campaign_techniques,
    )

    try:
        ctx = _json.dumps(
            {
                "executed": state.techniques_executed,
                "techniques": state.campaign_techniques[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DETECTION_MEASUREMENT,
            user_prompt=f"Measure detection:\n{ctx}",
            schema=DetectionMeasurementOutput,
        )
        if isinstance(llm_out, DetectionMeasurementOutput):
            rand_id = random.randint(1000, 9999)  # noqa: S311
            measurements.append(
                {
                    "id": f"llm-det-{rand_id}",
                    "coverage_pct": llm_out.coverage_pct,
                    "detected": llm_out.detected_techniques,
                    "missed": llm_out.missed_techniques,
                }
            )
        logger.info("llm_enhanced", node="measure_detection")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="measure_detection")

    detected = sum(1 for m in measurements if m.get("detected", False))
    total = max(state.techniques_executed, 1)
    coverage = round((detected / total) * 100, 1)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "detection_measurements": measurements,
        "detection_coverage_pct": coverage,
        "stage": EmulationStage.MEASURE_DETECTION,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Measured {len(measurements)} detections, {coverage}% coverage ({elapsed}ms)",
        ],
        "current_step": "measure_detection",
    }


# ------------------------------------------------------------------
# Node: generate_gaps
# ------------------------------------------------------------------


async def generate_gaps(
    state: AttackEmulationState,
) -> dict[str, Any]:
    """Analyze and report detection gaps."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    gaps = await toolkit.analyze_gaps(
        detections=state.detection_measurements,
        campaign=state.campaign_techniques,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "gap_analyses": gaps,
        "gaps_found": len(gaps),
        "stage": EmulationStage.GENERATE_GAPS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Found {len(gaps)} detection gaps ({elapsed}ms)",
        ],
        "current_step": "generate_gaps",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: AttackEmulationState,
) -> dict[str, Any]:
    """Generate final emulation report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "detection_coverage_pct": state.detection_coverage_pct,
        "techniques_executed": state.techniques_executed,
        "gaps_found": state.gaps_found,
    }

    try:
        ctx = _json.dumps(
            {
                "adversary": state.selected_adversary,
                "coverage": state.detection_coverage_pct,
                "executed": state.techniques_executed,
                "gaps": state.gap_analyses[:10],
                "detections": state.detection_measurements[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate emulation report:\n{ctx}",
            schema=GapAnalysisReportOutput,
        )
        if isinstance(llm_out, GapAnalysisReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "critical_gaps": llm_out.critical_gaps,
                    "recommendations": llm_out.recommendations,
                    "effectiveness": llm_out.effectiveness,
                }
            )
        logger.info("llm_enhanced", node="generate_report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="generate_report")

    await toolkit.record_metric(
        "detection_coverage",
        state.detection_coverage_pct,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    return {
        "stats": report,
        "stage": EmulationStage.REPORT,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report generated ({elapsed}ms)",
        ],
        "current_step": "complete",
    }
