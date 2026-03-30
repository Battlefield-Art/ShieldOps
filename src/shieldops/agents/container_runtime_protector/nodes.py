"""Node implementations for the Container Runtime Protector."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.container_runtime_protector.models import (
    ContainerRuntimeProtectorState,
    CRPStage,
    ReasoningStep,
)
from shieldops.agents.container_runtime_protector.prompts import (
    SYSTEM_DRIFT,
    SYSTEM_ENFORCE,
    SYSTEM_MONITOR,
    SYSTEM_PROFILE,
    SYSTEM_SYSCALL,
    DriftDetectionOutput,
    PolicyEnforcementOutput,
    RuntimeMonitorOutput,
    SyscallAnalysisOutput,
    WorkloadProfileOutput,
)
from shieldops.agents.container_runtime_protector.tools import (
    ContainerRuntimeProtectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ContainerRuntimeProtectorToolkit | None = None


def set_toolkit(
    toolkit: ContainerRuntimeProtectorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ContainerRuntimeProtectorToolkit:
    if _toolkit is None:
        return ContainerRuntimeProtectorToolkit()
    return _toolkit


def _step(
    state: ContainerRuntimeProtectorState,
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


async def profile_workload(
    state: ContainerRuntimeProtectorState,
) -> dict[str, Any]:
    """Profile container workloads."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.profile_workload(
        state.protection_config,
    )
    priv_count = sum(1 for p in raw if p.get("privileged"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "namespaces": state.protection_config.get("namespaces", []),
                "workload_count": len(raw),
                "privileged": priv_count,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PROFILE,
            user_prompt=f"Workload profiling:\n{ctx}",
            schema=WorkloadProfileOutput,
        )
        if hasattr(llm_result, "privileged_count") and llm_result.privileged_count > priv_count:
            priv_count = llm_result.privileged_count
        logger.info(
            "llm_enhanced",
            node="profile_workload",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="profile_workload",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "profile_workload",
        f"namespaces={state.protection_config.get('namespaces', [])}",
        f"profiled {len(raw)} workloads, {priv_count} privileged",
        elapsed,
        "k8s_client",
    )
    await toolkit.record_metric("workloads", float(len(raw)))

    return {
        "workload_profiles": raw,
        "privileged_count": priv_count,
        "stage": CRPStage.MONITOR_RUNTIME,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "profile_workload",
        "session_start": start,
    }


async def monitor_runtime(
    state: ContainerRuntimeProtectorState,
) -> dict[str, Any]:
    """Monitor runtime events."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    events = await toolkit.monitor_runtime(
        state.workload_profiles,
    )
    anomalous = sum(1 for e in events if e.get("is_anomalous"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "workload_count": len(state.workload_profiles),
                "event_count": len(events),
                "anomalous": anomalous,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_MONITOR,
            user_prompt=f"Runtime monitoring:\n{ctx}",
            schema=RuntimeMonitorOutput,
        )
        if hasattr(llm_result, "anomalous_events") and llm_result.anomalous_events > anomalous:
            anomalous = llm_result.anomalous_events
        logger.info(
            "llm_enhanced",
            node="monitor_runtime",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="monitor_runtime",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "monitor_runtime",
        f"monitoring {len(state.workload_profiles)} workloads",
        f"{len(events)} events, {anomalous} anomalous",
        elapsed,
        "runtime_monitor",
    )

    return {
        "runtime_events": events,
        "anomalous_event_count": anomalous,
        "stage": CRPStage.DETECT_DRIFT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "monitor_runtime",
    }


async def detect_drift(
    state: ContainerRuntimeProtectorState,
) -> dict[str, Any]:
    """Detect image and configuration drift."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    drifts = await toolkit.detect_drift(
        state.workload_profiles,
        state.runtime_events,
    )
    critical = sum(1 for d in drifts if d.get("severity") == "critical")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "workload_count": len(state.workload_profiles),
                "drifts": drifts[:10],
                "critical": critical,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DRIFT,
            user_prompt=f"Drift detection:\n{ctx}",
            schema=DriftDetectionOutput,
        )
        if hasattr(llm_result, "critical_count") and llm_result.critical_count > critical:
            critical = llm_result.critical_count
        logger.info(
            "llm_enhanced",
            node="detect_drift",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_drift",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "detect_drift",
        f"checking {len(state.workload_profiles)} workloads",
        f"{len(drifts)} drifts, {critical} critical",
        elapsed,
        "image_scanner",
    )
    await toolkit.record_metric("drifts", float(len(drifts)))

    return {
        "drift_detections": drifts,
        "critical_drift_count": critical,
        "stage": CRPStage.ANALYZE_SYSCALLS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "detect_drift",
    }


async def analyze_syscalls(
    state: ContainerRuntimeProtectorState,
) -> dict[str, Any]:
    """Analyze syscall patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_syscalls(
        state.runtime_events,
    )
    max_risk = max(
        (a.get("risk_score", 0.0) for a in analyses),
        default=0.0,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "event_count": len(state.runtime_events),
                "analyses": analyses[:10],
                "max_risk": max_risk,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SYSCALL,
            user_prompt=f"Syscall analysis:\n{ctx}",
            schema=SyscallAnalysisOutput,
        )
        if hasattr(llm_result, "max_risk_score") and llm_result.max_risk_score > max_risk:
            max_risk = round(
                (max_risk + llm_result.max_risk_score) / 2,
                1,
            )
        logger.info(
            "llm_enhanced",
            node="analyze_syscalls",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_syscalls",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "analyze_syscalls",
        f"analyzing {len(state.runtime_events)} events",
        f"max_risk={max_risk}",
        elapsed,
        "runtime_monitor",
    )

    return {
        "syscall_analyses": analyses,
        "max_risk_score": max_risk,
        "stage": CRPStage.ENFORCE_POLICY,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_syscalls",
    }


async def enforce_policy(
    state: ContainerRuntimeProtectorState,
) -> dict[str, Any]:
    """Enforce runtime policies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.enforce_policy(
        state.syscall_analyses,
        state.drift_detections,
    )
    blocked = sum(1 for a in actions if a.get("blocked"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "analysis_count": len(state.syscall_analyses),
                "drift_count": len(state.drift_detections),
                "actions": actions[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ENFORCE,
            user_prompt=f"Policy enforcement:\n{ctx}",
            schema=PolicyEnforcementOutput,
        )
        if hasattr(llm_result, "actions"):
            logger.info(
                "llm_enhanced",
                node="enforce_policy",
                llm_actions=len(llm_result.actions),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enforce_policy",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "enforce_policy",
        f"enforcing on {len(state.syscall_analyses)} workloads",
        f"{len(actions)} actions, {blocked} blocked",
        elapsed,
        "policy_engine",
    )

    return {
        "enforcement_actions": actions,
        "blocked_count": blocked,
        "stage": CRPStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "enforce_policy",
    }


async def generate_report(
    state: ContainerRuntimeProtectorState,
) -> dict[str, Any]:
    """Generate final protection report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "total_workloads": len(state.workload_profiles),
        "privileged_containers": state.privileged_count,
        "runtime_events": len(state.runtime_events),
        "anomalous_events": state.anomalous_event_count,
        "drifts_detected": len(state.drift_detections),
        "critical_drifts": state.critical_drift_count,
        "max_risk_score": state.max_risk_score,
        "enforcement_actions": len(state.enforcement_actions),
        "blocked": state.blocked_count,
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("protection_duration_ms", float(duration_ms))
    await toolkit.record_metric("blocked_count", float(state.blocked_count))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing protection {state.request_id}",
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
