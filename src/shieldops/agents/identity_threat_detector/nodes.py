"""Node implementations for the Identity Threat Detector."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.identity_threat_detector.models import (
    IdentityThreatDetectorState,
    ITDStage,
    ReasoningStep,
)
from shieldops.agents.identity_threat_detector.prompts import (
    SYSTEM_BEHAVIOR,
    SYSTEM_COLLECT,
    SYSTEM_DETECT,
    SYSTEM_RESPOND,
    SYSTEM_RISK,
    AnomalyDetectionOutput,
    AuthCollectionOutput,
    BehaviorAnalysisOutput,
    ResponseDecisionOutput,
    RiskAssessmentOutput,
)
from shieldops.agents.identity_threat_detector.tools import (
    IdentityThreatDetectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IdentityThreatDetectorToolkit | None = None


def set_toolkit(
    toolkit: IdentityThreatDetectorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> IdentityThreatDetectorToolkit:
    if _toolkit is None:
        return IdentityThreatDetectorToolkit()
    return _toolkit


def _step(
    state: IdentityThreatDetectorState,
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


async def collect_auth_events(
    state: IdentityThreatDetectorState,
) -> dict[str, Any]:
    """Collect authentication events from IAM providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.collect_auth_events(
        state.detection_config,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "sources": state.detection_config.get(
                    "sources",
                    [],
                ),
                "event_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COLLECT,
            user_prompt=(f"Auth event collection context:\n{ctx}"),
            schema=AuthCollectionOutput,
        )
        if hasattr(llm_result, "failed_logins"):
            logger.info(
                "llm_enhanced",
                node="collect_auth_events",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_auth_events",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "collect_auth_events",
        f"sources={state.detection_config.get('sources', [])}",
        f"collected {len(raw)} auth events",
        elapsed,
        "iam_provider",
    )
    await toolkit.record_metric(
        "auth_events",
        float(len(raw)),
    )

    return {
        "auth_events": raw,
        "event_count": len(raw),
        "stage": ITDStage.ANALYZE_BEHAVIOR,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "collect_auth_events",
        "session_start": start,
    }


async def analyze_behavior(
    state: IdentityThreatDetectorState,
) -> dict[str, Any]:
    """Analyze user behavior from auth events."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    profiles = await toolkit.analyze_behavior(
        state.auth_events,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "event_count": len(state.auth_events),
                "profiles": profiles[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_BEHAVIOR,
            user_prompt=(f"Behavior analysis context:\n{ctx}"),
            schema=BehaviorAnalysisOutput,
        )
        if hasattr(llm_result, "deviations_found"):
            logger.info(
                "llm_enhanced",
                node="analyze_behavior",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_behavior",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "analyze_behavior",
        f"analyzing {len(state.auth_events)} events",
        f"profiled {len(profiles)} users",
        elapsed,
        "ueba_engine",
    )

    return {
        "behavior_profiles": profiles,
        "stage": ITDStage.DETECT_ANOMALY,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_behavior",
    }


async def detect_anomalies(
    state: IdentityThreatDetectorState,
) -> dict[str, Any]:
    """Detect identity anomalies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    anomalies = await toolkit.detect_anomalies(
        state.auth_events,
        state.behavior_profiles,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "event_count": len(state.auth_events),
                "anomalies": anomalies[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DETECT,
            user_prompt=(f"Anomaly detection context:\n{ctx}"),
            schema=AnomalyDetectionOutput,
        )
        if hasattr(llm_result, "anomaly_count"):
            logger.info(
                "llm_enhanced",
                node="detect_anomalies",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_anomalies",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "detect_anomalies",
        f"detecting across {len(state.auth_events)} events",
        f"found {len(anomalies)} anomalies",
        elapsed,
        "anomaly_detector",
    )
    await toolkit.record_metric(
        "anomalies",
        float(len(anomalies)),
    )

    return {
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "stage": ITDStage.ASSESS_RISK,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "detect_anomalies",
    }


async def assess_risk(
    state: IdentityThreatDetectorState,
) -> dict[str, Any]:
    """Assess risk for identity anomalies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_identity_risk(
        state.anomalies,
    )
    max_score = max(
        (a.get("risk_score", 0.0) for a in assessments),
        default=0.0,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "anomaly_count": len(state.anomalies),
                "assessments": assessments[:10],
                "max_score": max_score,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RISK,
            user_prompt=(f"Risk assessment context:\n{ctx}"),
            schema=RiskAssessmentOutput,
        )
        if hasattr(llm_result, "max_risk_score") and llm_result.max_risk_score > max_score:
            max_score = round(
                (max_score + llm_result.max_risk_score) / 2,
                1,
            )
        logger.info(
            "llm_enhanced",
            node="assess_risk",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risk",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "assess_risk",
        f"assessing {len(state.anomalies)} anomalies",
        f"max_risk={max_score}",
        elapsed,
        "risk_engine",
    )
    await toolkit.record_metric("max_risk", max_score)

    return {
        "risk_assessments": assessments,
        "max_risk_score": max_score,
        "stage": ITDStage.RESPOND,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "assess_risk",
    }


async def respond_to_threats(
    state: IdentityThreatDetectorState,
) -> dict[str, Any]:
    """Respond to identity threats."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.respond_to_threat(
        state.anomalies,
        state.risk_assessments,
    )
    responded = sum(1 for a in actions if a.get("success"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "anomaly_count": len(state.anomalies),
                "actions": actions[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RESPOND,
            user_prompt=(f"Response decision context:\n{ctx}"),
            schema=ResponseDecisionOutput,
        )
        if hasattr(llm_result, "actions"):
            logger.info(
                "llm_enhanced",
                node="respond_to_threats",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="respond_to_threats",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "respond_to_threats",
        f"responding to {len(state.anomalies)} anomalies",
        f"executed {responded} response actions",
        elapsed,
        "response_engine",
    )

    return {
        "response_actions": actions,
        "responded_count": responded,
        "stage": ITDStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "respond_to_threats",
    }


async def generate_report(
    state: IdentityThreatDetectorState,
) -> dict[str, Any]:
    """Generate final identity threat detection report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "total_events": state.event_count,
        "anomalies_detected": state.anomaly_count,
        "max_risk_score": state.max_risk_score,
        "responses_executed": state.responded_count,
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
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
