"""Node implementations for the API Abuse Detector."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.api_abuse_detector.models import (
    AbuseStage,
    ApiAbuseDetectorState,
    ReasoningStep,
)
from shieldops.agents.api_abuse_detector.prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_CLASSIFY,
    SYSTEM_COLLECT,
    SYSTEM_DETECT,
    SYSTEM_MITIGATE,
    AbuseDetectionOutput,
    MitigationOutput,
    PatternDetectionOutput,
    ThreatClassifyOutput,
    TrafficAnalysisOutput,
)
from shieldops.agents.api_abuse_detector.tools import (
    ApiAbuseDetectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ApiAbuseDetectorToolkit | None = None


def _get_toolkit() -> ApiAbuseDetectorToolkit:
    if _toolkit is None:
        return ApiAbuseDetectorToolkit()
    return _toolkit


def _step(
    state: ApiAbuseDetectorState,
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


async def collect_traffic(
    state: ApiAbuseDetectorState,
) -> dict[str, Any]:
    """Collect API traffic samples for analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.collect_traffic(state.scan_config)
    total_reqs = sum(s.get("request_count", 0) for s in raw)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "window": state.scan_config.get("time_window", "1h"),
                "endpoints": state.scan_config.get("endpoints", [])[:10],
                "sample_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COLLECT,
            user_prompt=(f"Traffic collection context:\n{ctx}"),
            schema=TrafficAnalysisOutput,
        )
        if hasattr(llm_result, "total_requests") and llm_result.total_requests > total_reqs:
            total_reqs = llm_result.total_requests
        logger.info(
            "llm_enhanced",
            node="collect_traffic",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_traffic",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "collect_traffic",
        f"window={state.scan_config.get('time_window', '1h')}",
        f"collected {len(raw)} samples, {total_reqs} requests",
        elapsed,
        "traffic_collector",
    )
    await toolkit.record_metric("traffic_collected", float(len(raw)))

    return {
        "traffic_samples": raw,
        "total_requests": total_reqs,
        "stage": AbuseStage.ANALYZE_PATTERNS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "collect_traffic",
        "session_start": start,
    }


async def analyze_patterns(
    state: ApiAbuseDetectorState,
) -> dict[str, Any]:
    """Analyze traffic for abuse patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    patterns = await toolkit.analyze_patterns(
        state.traffic_samples,
    )
    anomaly_count = len(patterns)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "sample_count": len(state.traffic_samples),
                "patterns": patterns[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=(f"Pattern analysis:\n{ctx}"),
            schema=PatternDetectionOutput,
        )
        if hasattr(llm_result, "anomaly_count") and llm_result.anomaly_count > anomaly_count:
            anomaly_count = llm_result.anomaly_count
        logger.info(
            "llm_enhanced",
            node="analyze_patterns",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_patterns",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "analyze_patterns",
        f"analyzing {len(state.traffic_samples)} samples",
        f"{anomaly_count} anomalous patterns",
        elapsed,
        "pattern_analyzer",
    )

    return {
        "abuse_patterns": patterns,
        "anomaly_count": anomaly_count,
        "stage": AbuseStage.DETECT_ABUSE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_patterns",
    }


async def detect_abuse(
    state: ApiAbuseDetectorState,
) -> dict[str, Any]:
    """Confirm abuse from detected patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    confirmed = await toolkit.detect_abuse(
        state.abuse_patterns,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "pattern_count": len(state.abuse_patterns),
                "confirmed_count": len(confirmed),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DETECT,
            user_prompt=(f"Abuse detection context:\n{ctx}"),
            schema=AbuseDetectionOutput,
        )
        if hasattr(llm_result, "confirmed_abuse"):
            logger.info(
                "llm_enhanced",
                node="detect_abuse",
                llm_confirmed=llm_result.confirmed_abuse,
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_abuse",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "detect_abuse",
        f"confirming {len(state.abuse_patterns)} patterns",
        f"{len(confirmed)} confirmed abuse patterns",
        elapsed,
        "abuse_detector",
    )

    return {
        "abuse_patterns": confirmed,
        "stage": AbuseStage.CLASSIFY_THREAT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "detect_abuse",
    }


async def classify_threat(
    state: ApiAbuseDetectorState,
) -> dict[str, Any]:
    """Classify threat level for confirmed abuse."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications = await toolkit.classify_threat(
        state.abuse_patterns,
    )

    level_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    max_level = max(
        (c.get("threat_level", "info") for c in classifications),
        key=lambda x: level_order.get(x, 0),
        default="info",
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "pattern_count": len(state.abuse_patterns),
                "classifications": classifications[:10],
                "max_threat_level": max_level,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CLASSIFY,
            user_prompt=(f"Threat classification:\n{ctx}"),
            schema=ThreatClassifyOutput,
        )
        if hasattr(llm_result, "max_threat_level"):
            llm_level = llm_result.max_threat_level
            if level_order.get(llm_level, 0) > level_order.get(max_level, 0):
                max_level = llm_level
        logger.info(
            "llm_enhanced",
            node="classify_threat",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_threat",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "classify_threat",
        f"classifying {len(state.abuse_patterns)} patterns",
        f"max_threat={max_level}",
        elapsed,
        "threat_classifier",
    )
    await toolkit.record_metric(
        "max_threat_level",
        float(level_order.get(max_level, 0)),
    )

    return {
        "threat_classifications": classifications,
        "max_threat_level": max_level,
        "stage": AbuseStage.MITIGATE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "classify_threat",
    }


async def apply_mitigation(
    state: ApiAbuseDetectorState,
) -> dict[str, Any]:
    """Apply mitigation actions for classified threats."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.apply_mitigation(
        state.threat_classifications,
        state.abuse_patterns,
    )
    blocked = sum(1 for a in actions if a.get("action_type") == "block")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "classification_count": len(state.threat_classifications),
                "action_count": len(actions),
                "blocked": blocked,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_MITIGATE,
            user_prompt=(f"Mitigation context:\n{ctx}"),
            schema=MitigationOutput,
        )
        if hasattr(llm_result, "actions"):
            logger.info(
                "llm_enhanced",
                node="apply_mitigation",
                llm_actions=len(llm_result.actions),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="apply_mitigation",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "apply_mitigation",
        f"mitigating {len(state.threat_classifications)} threats",
        f"applied {len(actions)} actions, {blocked} blocked",
        elapsed,
        "waf_client",
    )

    return {
        "mitigations": actions,
        "blocked_sources": blocked,
        "stage": AbuseStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "apply_mitigation",
    }


async def generate_report(
    state: ApiAbuseDetectorState,
) -> dict[str, Any]:
    """Generate final abuse detection report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "total_requests": state.total_requests,
        "anomaly_count": state.anomaly_count,
        "abuse_patterns": len(state.abuse_patterns),
        "max_threat_level": state.max_threat_level,
        "mitigations_applied": len(state.mitigations),
        "blocked_sources": state.blocked_sources,
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("scan_duration_ms", float(duration_ms))
    await toolkit.record_metric(
        "abuse_patterns",
        float(len(state.abuse_patterns)),
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing scan {state.request_id}",
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
