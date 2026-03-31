"""Node implementations for the Multi-Cloud Posture Agent."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.multi_cloud_posture.models import (
    MultiCloudPostureState,
    PostureStage,
    ReasoningStep,
)
from shieldops.agents.multi_cloud_posture.prompts import (
    SYSTEM_COMPARE,
    SYSTEM_GAPS,
    SYSTEM_NORMALIZE,
    SYSTEM_RECOMMEND,
    SYSTEM_SCAN,
    ComparisonOutput,
    GapOutput,
    NormalizationOutput,
    RecommendationOutput,
    ScanOutput,
)
from shieldops.agents.multi_cloud_posture.tools import (
    MultiCloudPostureToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: MultiCloudPostureToolkit | None = None


def set_toolkit(
    toolkit: MultiCloudPostureToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> MultiCloudPostureToolkit:
    if _toolkit is None:
        return MultiCloudPostureToolkit()
    return _toolkit


def _step(
    state: MultiCloudPostureState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Create a reasoning step."""
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def scan_clouds(
    state: MultiCloudPostureState,
) -> dict[str, Any]:
    """Scan all configured cloud environments."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scans = await toolkit.scan_clouds(state.posture_config)
    total = sum(s.get("findings_count", 0) for s in scans)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "providers": state.posture_config.get("providers", []),
                "scans": scans,
                "total_findings": total,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SCAN,
            user_prompt=f"Cloud scan context:\n{ctx}",
            schema=ScanOutput,
        )
        if hasattr(llm_result, "total_findings") and llm_result.total_findings > total:
            total = llm_result.total_findings
        logger.info(
            "llm_enhanced",
            node="scan_clouds",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_clouds",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "scan_clouds",
        f"scanning {len(scans)} cloud providers",
        f"{total} total findings",
        elapsed,
        "cloud_scanner",
    )
    await toolkit.record_metric("total_findings", float(total))

    return {
        "cloud_scans": scans,
        "total_findings": total,
        "stage": PostureStage.NORMALIZE_FINDINGS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "scan_clouds",
        "session_start": start,
    }


async def normalize_findings(
    state: MultiCloudPostureState,
) -> dict[str, Any]:
    """Normalize findings across cloud providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    findings = await toolkit.normalize_findings(
        state.cloud_scans,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scan_count": len(state.cloud_scans),
                "findings": findings[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_NORMALIZE,
            user_prompt=f"Normalization context:\n{ctx}",
            schema=NormalizationOutput,
        )
        if hasattr(llm_result, "categories"):
            logger.info(
                "llm_enhanced",
                node="normalize_findings",
                categories=len(llm_result.categories),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="normalize_findings",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "normalize_findings",
        f"normalizing {state.total_findings} findings",
        f"{len(findings)} normalized",
        elapsed,
        "normalizer",
    )

    return {
        "normalized_findings": findings,
        "stage": PostureStage.COMPARE_POSTURE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "normalize_findings",
    }


async def compare_posture(
    state: MultiCloudPostureState,
) -> dict[str, Any]:
    """Compare security posture across providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    comparisons = await toolkit.compare_posture(
        state.normalized_findings,
    )
    scores = [
        (c.get("aws_score", 0) + c.get("gcp_score", 0) + c.get("azure_score", 0)) / 3
        for c in comparisons
    ]
    overall = round(sum(scores) / max(len(scores), 1), 1)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "finding_count": len(state.normalized_findings),
                "comparisons": comparisons,
                "overall_score": overall,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COMPARE,
            user_prompt=f"Posture comparison:\n{ctx}",
            schema=ComparisonOutput,
        )
        if hasattr(llm_result, "overall_score") and llm_result.overall_score > 0:
            overall = round((overall + llm_result.overall_score) / 2, 1)
        logger.info(
            "llm_enhanced",
            node="compare_posture",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="compare_posture",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "compare_posture",
        f"comparing {len(comparisons)} categories",
        f"overall score={overall}",
        elapsed,
        "posture_engine",
    )
    await toolkit.record_metric("overall_score", overall)

    return {
        "posture_comparisons": comparisons,
        "overall_score": overall,
        "stage": PostureStage.DETECT_GAPS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "compare_posture",
    }


async def detect_gaps(
    state: MultiCloudPostureState,
) -> dict[str, Any]:
    """Detect cross-cloud security gaps."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    gaps = await toolkit.detect_gaps(
        state.posture_comparisons,
        state.normalized_findings,
    )
    critical = sum(1 for g in gaps if g.get("severity") == "critical")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "comparisons": state.posture_comparisons,
                "gaps": gaps[:10],
                "critical": critical,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_GAPS,
            user_prompt=f"Gap detection context:\n{ctx}",
            schema=GapOutput,
        )
        if hasattr(llm_result, "critical_gaps") and llm_result.critical_gaps > critical:
            critical = llm_result.critical_gaps
        logger.info(
            "llm_enhanced",
            node="detect_gaps",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_gaps",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "detect_gaps",
        f"analyzing {len(state.posture_comparisons)} comparisons",
        f"{len(gaps)} gaps, {critical} critical",
        elapsed,
        "gap_detector",
    )

    return {
        "security_gaps": gaps,
        "critical_gaps": critical,
        "stage": PostureStage.RECOMMEND,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "detect_gaps",
    }


async def recommend(
    state: MultiCloudPostureState,
) -> dict[str, Any]:
    """Generate recommendations for posture improvement."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    recs = await toolkit.recommend_fixes(
        state.security_gaps,
        state.posture_comparisons,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "gap_count": len(state.security_gaps),
                "recommendations": recs[:5],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RECOMMEND,
            user_prompt=f"Recommendation context:\n{ctx}",
            schema=RecommendationOutput,
        )
        if hasattr(llm_result, "actions"):
            logger.info(
                "llm_enhanced",
                node="recommend",
                action_count=len(llm_result.actions),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "recommend",
        f"generating recs for {len(state.security_gaps)} gaps",
        f"created {len(recs)} recommendations",
        elapsed,
        "recommendation_engine",
    )

    return {
        "recommendations": recs,
        "stage": PostureStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "recommend",
    }


async def generate_report(
    state: MultiCloudPostureState,
) -> dict[str, Any]:
    """Generate final posture report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "total_findings": state.total_findings,
        "overall_score": state.overall_score,
        "security_gaps": len(state.security_gaps),
        "critical_gaps": state.critical_gaps,
        "recommendations": len(state.recommendations),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "posture_duration_ms",
        float(duration_ms),
    )
    await toolkit.record_metric(
        "overall_score",
        state.overall_score,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing posture {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
