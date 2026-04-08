"""Node implementations for the Runtime Protection Engine LangGraph workflow.

Each node is an async function that:
1. Queries runtime systems via the toolkit
2. Uses the LLM to analyze and reason about data
3. Updates the RPE state with findings
4. Records its reasoning step in the audit trail
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.runtime_protection_engine.models import (
    AnomalyDetection,
    BehaviorProfile,
    EnforcementAction,
    ReasoningStep,
    RPEStage,
    RuntimeProtectionEngineState,
    RuntimeTelemetry,
)
from shieldops.agents.runtime_protection_engine.prompts import (
    SYSTEM_ANALYZE_BEHAVIOR,
    SYSTEM_COLLECT_TELEMETRY,
    SYSTEM_DETECT_ANOMALIES,
    SYSTEM_ENFORCE_POLICIES,
    SYSTEM_GENERATE_ALERTS,
    AlertAnalysis,
    AnomalyAnalysis,
    BehaviorAnalysis,
    EnforcementAnalysis,
    TelemetryAnalysis,
)
from shieldops.agents.runtime_protection_engine.tools import (
    RuntimeProtectionEngineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit, set by runner at startup.
_toolkit: RuntimeProtectionEngineToolkit | None = None


def _get_toolkit() -> RuntimeProtectionEngineToolkit:
    if _toolkit is None:
        return RuntimeProtectionEngineToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# ---- Node: collect_telemetry ----


async def collect_telemetry(
    state: RuntimeProtectionEngineState,
) -> dict[str, Any]:
    """Collect runtime telemetry from AI agent executions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "rpe_collecting_telemetry",
        request_id=state.request_id,
    )

    agent_ids = state.config.get("agent_ids")
    events = await toolkit.collect_telemetry(
        tenant_id=state.tenant_id,
        agent_ids=agent_ids,
    )

    output_summary = f"Collected {len(events)} telemetry events."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "events_collected": len(events),
                "agents": list({e.agent_id for e in events}),
                "tool_calls": list({e.tool_call for e in events}),
            },
            default=str,
        )
        llm_result = cast(
            TelemetryAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_COLLECT_TELEMETRY,
                user_prompt=f"Telemetry collection results:\n{ctx}",
                schema=TelemetryAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(events)} events."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_telemetry",
        )

    step = ReasoningStep(
        step_number=1,
        action="collect_telemetry",
        input_summary="Collecting runtime telemetry from agent fleet",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="telemetry_collector",
    )

    return {
        "telemetry": [e.model_dump() for e in events],
        "stage": RPEStage.ANALYZE_BEHAVIOR,
        "session_start": start,
        "reasoning_chain": [step],
        "current_step": "collect_telemetry",
    }


# ---- Node: analyze_behavior ----


async def analyze_behavior(
    state: RuntimeProtectionEngineState,
) -> dict[str, Any]:
    """Analyze agent behavior from collected telemetry."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    telemetry = [RuntimeTelemetry.model_validate(t) for t in state.telemetry]

    logger.info(
        "rpe_analyzing_behavior",
        request_id=state.request_id,
        event_count=len(telemetry),
    )

    profiles = await toolkit.analyze_behavior(telemetry)

    suspicious = sum(1 for p in profiles if p.deviation_score > 0.4)

    output_summary = f"Analyzed {len(profiles)} agent behaviors. {suspicious} suspicious or worse."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "agents": len(profiles),
                "suspicious": suspicious,
                "categories": [p.category.value for p in profiles],
                "avg_deviation": round(
                    sum(p.deviation_score for p in profiles) / max(len(profiles), 1),
                    3,
                ),
            },
            default=str,
        )
        llm_result = cast(
            BehaviorAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE_BEHAVIOR,
                user_prompt=f"Behavior analysis results:\n{ctx}",
                schema=BehaviorAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Risk: {llm_result.risk_assessment}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_behavior",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_behavior",
        input_summary=f"Analyzing behavior from {len(telemetry)} events",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="behavior_analyzer",
    )

    return {
        "behaviors": [p.model_dump() for p in profiles],
        "stage": RPEStage.DETECT_ANOMALIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_behavior",
    }


# ---- Node: detect_anomalies ----


async def detect_anomalies(
    state: RuntimeProtectionEngineState,
) -> dict[str, Any]:
    """Detect anomalies from analyzed behavior profiles."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    profiles = [BehaviorProfile.model_validate(b) for b in state.behaviors]

    logger.info(
        "rpe_detecting_anomalies",
        request_id=state.request_id,
        profile_count=len(profiles),
    )

    anomalies = await toolkit.detect_anomalies(profiles)

    critical = sum(1 for a in anomalies if a.severity == "critical")

    output_summary = f"Detected {len(anomalies)} anomalies. {critical} critical."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "profiles": len(profiles),
                "anomalies": len(anomalies),
                "critical": critical,
                "types": [a.anomaly_type for a in anomalies],
                "severities": [a.severity for a in anomalies],
            },
            default=str,
        )
        llm_result = cast(
            AnomalyAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_DETECT_ANOMALIES,
                user_prompt=f"Anomaly detection results:\n{ctx}",
                schema=AnomalyAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Threat: {llm_result.overall_threat}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_anomalies",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_anomalies",
        input_summary=f"Detecting anomalies from {len(profiles)} profiles",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="anomaly_detector",
    )

    return {
        "anomalies": [a.model_dump() for a in anomalies],
        "anomaly_count": len(anomalies),
        "stage": RPEStage.ENFORCE_POLICIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_anomalies",
    }


# ---- Node: enforce_policies ----


async def enforce_policies(
    state: RuntimeProtectionEngineState,
) -> dict[str, Any]:
    """Enforce security policies on detected anomalies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    anomalies = [AnomalyDetection.model_validate(a) for a in state.anomalies]

    logger.info(
        "rpe_enforcing_policies",
        request_id=state.request_id,
        anomaly_count=len(anomalies),
    )

    enforcements = await toolkit.enforce_policies(anomalies)

    blocked = sum(1 for e in enforcements if e.action == EnforcementAction.BLOCK)

    output_summary = f"Enforced {len(enforcements)} policies. {blocked} blocked."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "anomalies": len(anomalies),
                "enforcements": len(enforcements),
                "blocked": blocked,
                "actions": [e.action.value for e in enforcements],
            },
            default=str,
        )
        llm_result = cast(
            EnforcementAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_ENFORCE_POLICIES,
                user_prompt=f"Policy enforcement results:\n{ctx}",
                schema=EnforcementAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Effectiveness: {llm_result.effectiveness}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enforce_policies",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="enforce_policies",
        input_summary=f"Enforcing policies on {len(anomalies)} anomalies",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="policy_enforcer",
    )

    return {
        "enforcements": [e.model_dump() for e in enforcements],
        "blocked_count": blocked,
        "stage": RPEStage.GENERATE_ALERTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enforce_policies",
    }


# ---- Node: generate_alerts ----


async def generate_alerts(
    state: RuntimeProtectionEngineState,
) -> dict[str, Any]:
    """Generate security alerts from anomalies and enforcements."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    anomalies = [AnomalyDetection.model_validate(a) for a in state.anomalies]
    from shieldops.agents.runtime_protection_engine.models import (
        PolicyEnforcement,
    )

    enforcements = [PolicyEnforcement.model_validate(e) for e in state.enforcements]

    logger.info(
        "rpe_generating_alerts",
        request_id=state.request_id,
        anomaly_count=len(anomalies),
    )

    alerts = await toolkit.generate_alerts(anomalies, enforcements)

    output_summary = f"Generated {len(alerts)} alerts from {len(anomalies)} anomalies."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "anomalies": len(anomalies),
                "alerts": len(alerts),
                "severities": [a.severity for a in alerts],
            },
            default=str,
        )
        llm_result = cast(
            AlertAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_GENERATE_ALERTS,
                user_prompt=f"Alert generation results:\n{ctx}",
                schema=AlertAnalysis,
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
        input_summary=(f"Generating alerts from {len(anomalies)} anomalies"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="alert_generator",
    )

    return {
        "alerts": [a.model_dump() for a in alerts],
        "alert_count": len(alerts),
        "stage": RPEStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_alerts",
    }


# ---- Node: generate_report ----


async def generate_report(
    state: RuntimeProtectionEngineState,
) -> dict[str, Any]:
    """Final reporting node -- summarize the runtime protection cycle."""
    start = datetime.now(UTC)

    session_duration_ms = 0
    if state.session_start:
        session_duration_ms = _elapsed_ms(state.session_start)

    output_summary = (
        f"RPE cycle complete. "
        f"{len(state.telemetry)} events, "
        f"{len(state.behaviors)} behaviors, "
        f"{state.anomaly_count} anomalies, "
        f"{state.blocked_count} blocked, "
        f"{state.alert_count} alerts. "
        f"Duration: {session_duration_ms}ms."
    )

    logger.info(
        "rpe_report",
        request_id=state.request_id,
        summary=output_summary,
    )

    report = {
        "request_id": state.request_id,
        "tenant_id": state.tenant_id,
        "telemetry_collected": len(state.telemetry),
        "behaviors_analyzed": len(state.behaviors),
        "anomalies_detected": state.anomaly_count,
        "policies_enforced": len(state.enforcements),
        "blocked_count": state.blocked_count,
        "alerts_generated": state.alert_count,
        "duration_ms": session_duration_ms,
        "summary": output_summary,
    }

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary="Generating final runtime protection report",
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
