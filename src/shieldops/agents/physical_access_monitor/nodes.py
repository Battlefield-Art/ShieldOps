"""Physical Access Monitor Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import AccessEvent, AlertLevel
from .tools import PhysicalAccessMonitorToolkit

logger = structlog.get_logger()

_toolkit: PhysicalAccessMonitorToolkit | None = None


def _get_toolkit() -> PhysicalAccessMonitorToolkit:
    """Return the module-level toolkit."""
    if _toolkit is None:
        raise RuntimeError("toolkit not initialised")
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def ingest_events(
    state: dict[str, Any],
    toolkit: PhysicalAccessMonitorToolkit | None = None,
) -> dict[str, Any]:
    """Ingest badge swipe and access events."""
    logger.info("physical_access.node.ingest_events")
    state = _to_dict(state)
    tk = toolkit or _get_toolkit()
    tenant_id = state.get("tenant_id", "")
    zones = state.get("zones", [])
    hours = state.get("time_range_hours", 24)
    start = time.time()

    events = await tk.ingest_events(
        tenant_id=tenant_id,
        zones=zones or None,
        time_range_hours=hours,
    )
    event_dicts = [e.model_dump() for e in events]

    reasoning = f"Ingested {len(events)} access events across {len({e.zone for e in events})} zones"

    return {
        "access_events": event_dicts,
        "session_start": start,
        "stage": "ingest_events",
        "current_step": "ingest_events",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def analyze_patterns(
    state: dict[str, Any],
    toolkit: PhysicalAccessMonitorToolkit | None = None,
) -> dict[str, Any]:
    """Analyze access patterns for anomalies."""
    logger.info("physical_access.node.analyze_patterns")
    state = _to_dict(state)
    tk = toolkit or _get_toolkit()
    event_dicts = state.get("access_events", [])
    events = [AccessEvent(**e) for e in event_dicts]

    patterns = await tk.analyze_patterns(events)

    reasoning = f"Detected {len(patterns)} access patterns"

    try:
        from .prompts import (
            SYSTEM_ACCESS_PATTERN,
            AccessPatternResult,
        )

        ctx = json.dumps(
            {
                "event_count": len(events),
                "patterns": patterns[:15],
            },
            default=str,
        )
        llm_result = cast(
            AccessPatternResult,
            await llm_structured(
                system_prompt=SYSTEM_ACCESS_PATTERN,
                user_prompt=f"Access pattern data:\n{ctx}",
                schema=AccessPatternResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="physical_access_monitor",
            node="analyze_patterns",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="physical_access_monitor",
            node="analyze_patterns",
        )

    return {
        "patterns_detected": patterns,
        "stage": "analyze_patterns",
        "current_step": "analyze_patterns",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def detect_anomalies(
    state: dict[str, Any],
    toolkit: PhysicalAccessMonitorToolkit | None = None,
) -> dict[str, Any]:
    """Detect anomalies from patterns."""
    logger.info("physical_access.node.detect_anomalies")
    state = _to_dict(state)
    tk = toolkit or _get_toolkit()
    event_dicts = state.get("access_events", [])
    patterns = state.get("patterns_detected", [])
    events = [AccessEvent(**e) for e in event_dicts]

    anomalies = await tk.detect_anomalies(events, patterns)

    critical = sum(1 for a in anomalies if a.get("alert_level") == AlertLevel.CRITICAL)
    reasoning = f"Found {len(anomalies)} anomalies ({critical} critical)"

    try:
        from .prompts import (
            SYSTEM_ANOMALY_DETECTION,
            AnomalyDetectionResult,
        )

        ctx = json.dumps(
            {"anomalies": anomalies[:15]},
            default=str,
        )
        llm_result = cast(
            AnomalyDetectionResult,
            await llm_structured(
                system_prompt=SYSTEM_ANOMALY_DETECTION,
                user_prompt=f"Anomaly data:\n{ctx}",
                schema=AnomalyDetectionResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="physical_access_monitor",
            node="detect_anomalies",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="physical_access_monitor",
            node="detect_anomalies",
        )

    return {
        "anomalies": anomalies,
        "stage": "detect_anomalies",
        "current_step": "detect_anomalies",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def evaluate_policies(
    state: dict[str, Any],
    toolkit: PhysicalAccessMonitorToolkit | None = None,
) -> dict[str, Any]:
    """Evaluate access events against zone policies."""
    logger.info("physical_access.node.evaluate_policies")
    state = _to_dict(state)
    tk = toolkit or _get_toolkit()
    event_dicts = state.get("access_events", [])
    events = [AccessEvent(**e) for e in event_dicts]

    violations = await tk.evaluate_policies(events)

    reasoning = f"Found {len(violations)} policy violations"

    return {
        "policy_violations": violations,
        "stage": "evaluate_policies",
        "current_step": "evaluate_policies",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def generate_alerts(
    state: dict[str, Any],
    toolkit: PhysicalAccessMonitorToolkit | None = None,
) -> dict[str, Any]:
    """Generate alerts from anomalies and violations."""
    logger.info("physical_access.node.generate_alerts")
    state = _to_dict(state)
    tk = toolkit or _get_toolkit()
    anomalies = state.get("anomalies", [])
    violations = state.get("policy_violations", [])

    alerts = await tk.generate_alerts(anomalies, violations)

    reasoning = f"Generated {len(alerts)} alerts"

    return {
        "alerts_generated": alerts,
        "stage": "generate_alerts",
        "current_step": "generate_alerts",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: PhysicalAccessMonitorToolkit | None = None,
) -> dict[str, Any]:
    """Generate final physical access report."""
    logger.info("physical_access.node.generate_report")
    state = _to_dict(state)
    start = state.get("session_start", time.time())
    duration_ms = (time.time() - start) * 1000

    events = state.get("access_events", [])
    anomalies = state.get("anomalies", [])
    violations = state.get("policy_violations", [])
    alerts = state.get("alerts_generated", [])

    stats = state.get("stats", {})
    stats.update(
        {
            "total_events": len(events),
            "total_anomalies": len(anomalies),
            "total_violations": len(violations),
            "total_alerts": len(alerts),
            "critical_alerts": sum(1 for a in alerts if a.get("level") == AlertLevel.CRITICAL),
        }
    )

    reasoning = f"Report: {stats['total_events']} events, {stats['total_alerts']} alerts"

    return {
        "stats": stats,
        "stage": "report",
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }
