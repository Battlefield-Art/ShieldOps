"""Endpoint Behavior Monitor Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import MonitorStage
from .prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_CORRELATE,
    BehaviorAnalysisResult,
    CorrelationResult,
)
from .tools import EndpointBehaviorMonitorToolkit

logger = structlog.get_logger()

_toolkit: EndpointBehaviorMonitorToolkit | None = None


def _tk() -> EndpointBehaviorMonitorToolkit:
    assert _toolkit is not None
    return _toolkit


async def collect_telemetry(
    state: dict[str, Any], toolkit: EndpointBehaviorMonitorToolkit
) -> dict[str, Any]:
    """Collect all telemetry from the endpoint."""
    logger.info("ebm.node.collect")
    eid = state.get("endpoint_id", "")

    procs = await toolkit.collect_process_events(eid)
    fs = await toolkit.collect_filesystem_events(eid)
    reg = await toolkit.collect_registry_events(eid)
    net = await toolkit.collect_network_events(eid)
    usb = await toolkit.collect_usb_events(eid)

    total = len(procs) + len(fs) + len(reg) + len(net) + len(usb)
    return {
        "stage": MonitorStage.ANALYZE_PROCESSES.value,
        "process_events": procs,
        "filesystem_events": fs,
        "registry_events": reg,
        "network_events": net,
        "usb_events": usb,
        "total_events": total,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {total} events from endpoint {eid}"],
    }


async def analyze_behavior(
    state: dict[str, Any], toolkit: EndpointBehaviorMonitorToolkit
) -> dict[str, Any]:
    """Analyze collected telemetry for anomalies."""
    logger.info("ebm.node.analyze")

    anomalies, risk = await toolkit.analyze_anomalies(
        process_events=state.get("process_events", []),
        fs_events=state.get("filesystem_events", []),
        registry_events=state.get("registry_events", []),
        network_events=state.get("network_events", []),
        usb_events=state.get("usb_events", []),
    )

    reasoning = f"Detected {len(anomalies)} anomalies, risk score {risk:.1f}"

    if anomalies:
        try:
            ctx = json.dumps(
                {"anomalies": anomalies[:10], "risk": risk},
                default=str,
            )
            result = cast(
                BehaviorAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_ANALYZE,
                    user_prompt=f"Endpoint behavior:\n{ctx}",
                    schema=BehaviorAnalysisResult,
                ),
            )
            reasoning = f"{result.summary}. {reasoning}"
        except Exception:
            logger.debug("llm_fallback", agent="ebm", node="analyze")

    return {
        "stage": MonitorStage.CORRELATE.value,
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "risk_score": risk,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def correlate_signals(
    state: dict[str, Any], toolkit: EndpointBehaviorMonitorToolkit
) -> dict[str, Any]:
    """Correlate anomalies across data sources."""
    logger.info("ebm.node.correlate")

    anomalies = state.get("anomalies", [])
    risk = state.get("risk_score", 0.0)

    summary = f"Correlated {len(anomalies)} anomalies across endpoint, risk={risk:.1f}"
    recommendations: list[str] = []

    if risk >= 70:
        recommendations.append("Isolate endpoint immediately")
        recommendations.append("Initiate incident response")
    elif risk >= 40:
        recommendations.append("Escalate to SOC for investigation")
        recommendations.append("Block suspicious network connections")
    else:
        recommendations.append("Continue monitoring")

    try:
        ctx = json.dumps(
            {
                "anomalies": anomalies[:10],
                "risk_score": risk,
            },
            default=str,
        )
        result = cast(
            CorrelationResult,
            await llm_structured(
                system_prompt=SYSTEM_CORRELATE,
                user_prompt=f"Correlation context:\n{ctx}",
                schema=CorrelationResult,
            ),
        )
        summary = result.attack_narrative
    except Exception:
        logger.debug("llm_fallback", agent="ebm", node="correlate")

    return {
        "stage": MonitorStage.REPORT.value,
        "summary": summary,
        "recommendations": recommendations,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
