"""Node implementations for the Service Health Monitor Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.service_health_monitor.models import (
    DegradationEvent,
    DependencyAnalysis,
    HealthCheck,
    ReasoningStep,
    RemediationAction,
    ServiceEndpoint,
    ServiceHealthMonitorState,
)
from shieldops.agents.service_health_monitor.prompts import (
    SYSTEM_DEGRADATION,
    DegradationAnalysisOutput,
)
from shieldops.agents.service_health_monitor.tools import (
    ServiceHealthMonitorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ServiceHealthMonitorToolkit | None = None


def set_toolkit(
    toolkit: ServiceHealthMonitorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> ServiceHealthMonitorToolkit:
    if _toolkit is None:
        return ServiceHealthMonitorToolkit()
    return _toolkit


async def discover_services(
    state: ServiceHealthMonitorState,
) -> dict[str, Any]:
    """Discover microservices for the tenant."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.discover_services(
        state.tenant_id,
    )
    services = [ServiceEndpoint(**s) for s in raw if isinstance(s, dict)]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="discover_services",
        input_summary=(f"Discovering services for tenant {state.tenant_id}"),
        output_summary=(f"Discovered {len(services)} services"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="service_registry",
    )

    await toolkit.record_metric(
        "services_discovered",
        float(len(services)),
    )

    return {
        "services": services,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "discover_services",
        "session_start": start,
    }


async def check_health(
    state: ServiceHealthMonitorState,
) -> dict[str, Any]:
    """Check health of all discovered services."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    svc_dicts = [s.model_dump() for s in state.services]
    raw = await toolkit.check_health(svc_dicts)
    checks = [HealthCheck(**c) for c in raw if isinstance(c, dict)]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="check_health",
        input_summary=(f"Checking health of {len(state.services)} services"),
        output_summary=(f"Completed {len(checks)} health checks"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="health_checker",
    )

    await toolkit.record_metric(
        "health_checks_completed",
        float(len(checks)),
    )

    return {
        "health_checks": checks,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "check_health",
    }


async def analyze_dependencies(
    state: ServiceHealthMonitorState,
) -> dict[str, Any]:
    """Analyze inter-service dependencies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    svc_dicts = [s.model_dump() for s in state.services]
    check_dicts = [c.model_dump() for c in state.health_checks]
    raw = await toolkit.analyze_dependencies(svc_dicts, check_dicts)
    analyses = [DependencyAnalysis(**a) for a in raw if isinstance(a, dict)]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_dependencies",
        input_summary=(f"Analyzing dependencies for {len(state.services)} services"),
        output_summary=(f"Analyzed {len(analyses)} dependency graphs"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="dependency_mapper",
    )

    return {
        "dependency_analyses": analyses,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_dependencies",
    }


async def detect_degradation(
    state: ServiceHealthMonitorState,
) -> dict[str, Any]:
    """Detect service degradation from health checks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    check_dicts = [c.model_dump() for c in state.health_checks]
    raw = await toolkit.detect_degradation(check_dicts)
    events = [DegradationEvent(**e) for e in raw if isinstance(e, dict)]

    # LLM enhancement for degradation analysis
    if events:
        try:
            import json as _json

            dep_dicts = [a.model_dump() for a in state.dependency_analyses]
            context = _json.dumps(
                {
                    "tenant_id": state.tenant_id,
                    "health_checks": check_dicts[:20],
                    "degradation_events": [e.model_dump() for e in events[:10]],
                    "dependencies": dep_dicts[:10],
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_DEGRADATION,
                user_prompt=(f"Degradation analysis context:\n{context}"),
                schema=DegradationAnalysisOutput,
            )
            if hasattr(llm_result, "severity"):
                logger.info(
                    "llm_enhanced",
                    node="detect_degradation",
                    severity=llm_result.severity,
                    cascade_risk=(llm_result.cascade_risk),
                )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="detect_degradation",
            )

    has_degradation = len(events) > 0

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_degradation",
        input_summary=(f"Detecting degradation from {len(state.health_checks)} checks"),
        output_summary=(f"Detected {len(events)} degradation events"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="health_checker",
    )

    await toolkit.record_metric(
        "degradation_events",
        float(len(events)),
    )

    return {
        "degradation_events": events,
        "has_degradation": has_degradation,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "detect_degradation",
    }


async def trigger_remediation(
    state: ServiceHealthMonitorState,
) -> dict[str, Any]:
    """Trigger automated remediation for events."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    event_dicts = [e.model_dump() for e in state.degradation_events]
    raw = await toolkit.trigger_remediation(
        event_dicts,
    )
    actions = [RemediationAction(**a) for a in raw if isinstance(a, dict)]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="trigger_remediation",
        input_summary=(f"Remediating {len(state.degradation_events)} events"),
        output_summary=(f"Executed {len(actions)} remediation actions"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="remediation_engine",
    )

    await toolkit.record_metric(
        "remediation_actions",
        float(len(actions)),
    )

    return {
        "remediation_actions": actions,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "trigger_remediation",
    }


async def report(
    state: ServiceHealthMonitorState,
) -> dict[str, Any]:
    """Generate final health monitoring report."""
    start = datetime.now(UTC)

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    # Status breakdown
    status_counts: dict[str, int] = {}
    for check in state.health_checks:
        val = check.status.value if hasattr(check.status, "value") else str(check.status)
        status_counts[val] = status_counts.get(val, 0) + 1

    # Services at risk
    at_risk = [c.service_name for c in state.health_checks if c.status in ("degraded", "unhealthy")]

    # Cascade risks
    high_cascade = [a.service_name for a in state.dependency_analyses if a.cascade_risk == "high"]

    report_data: dict[str, Any] = {
        "tenant_id": state.tenant_id,
        "services_discovered": len(state.services),
        "health_checks": len(state.health_checks),
        "status_breakdown": status_counts,
        "services_at_risk": at_risk,
        "high_cascade_risk": high_cascade,
        "degradation_events": len(state.degradation_events),
        "remediation_actions": len(state.remediation_actions),
        "duration_ms": duration_ms,
    }

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary=(f"Generating report for {len(state.services)} services"),
        output_summary=(f"Report complete; {len(at_risk)} services at risk"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "report": report_data,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
