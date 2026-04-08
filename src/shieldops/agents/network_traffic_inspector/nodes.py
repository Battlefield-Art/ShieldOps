"""Node implementations for the Network Traffic Inspector."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.network_traffic_inspector.models import (
    NetworkTrafficInspectorState,
    NTIStage,
    ReasoningStep,
)
from shieldops.agents.network_traffic_inspector.prompts import (
    SYSTEM_ALERT,
    SYSTEM_ANALYZE,
    SYSTEM_CAPTURE,
    SYSTEM_CLASSIFY,
    SYSTEM_DETECT,
    AlertOutput,
    AnomalyDetectionOutput,
    ProtocolAnalysisOutput,
    ThreatClassifyOutput,
    TrafficCaptureOutput,
)
from shieldops.agents.network_traffic_inspector.tools import (
    NetworkTrafficInspectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: NetworkTrafficInspectorToolkit | None = None


def _get_toolkit() -> NetworkTrafficInspectorToolkit:
    if _toolkit is None:
        return NetworkTrafficInspectorToolkit()
    return _toolkit


def _step(
    state: NetworkTrafficInspectorState,
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


async def capture_traffic(
    state: NetworkTrafficInspectorState,
) -> dict[str, Any]:
    """Capture network traffic flows."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.capture_traffic(state.capture_config)
    total_bytes = sum(f.get("bytes_sent", 0) + f.get("bytes_recv", 0) for f in raw)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "interface": state.capture_config.get("interface", ""),
                "targets": state.capture_config.get("targets", [])[:10],
                "flow_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CAPTURE,
            user_prompt=f"Traffic capture context:\n{ctx}",
            schema=TrafficCaptureOutput,
        )
        if hasattr(llm_result, "total_bytes") and llm_result.total_bytes > total_bytes:
            total_bytes = llm_result.total_bytes
        logger.info(
            "llm_enhanced",
            node="capture_traffic",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="capture_traffic",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "capture_traffic",
        f"interface={state.capture_config.get('interface', '')}",
        f"captured {len(raw)} flows, {total_bytes} bytes",
        elapsed,
        "packet_capture",
    )
    await toolkit.record_metric("capture", float(len(raw)))

    return {
        "captured_flows": raw,
        "total_bytes": total_bytes,
        "stage": NTIStage.ANALYZE_PROTOCOLS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "capture_traffic",
        "session_start": start,
    }


async def analyze_protocols(
    state: NetworkTrafficInspectorState,
) -> dict[str, Any]:
    """Analyze protocol conversations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_protocols(
        state.captured_flows,
    )
    anomalous = sum(1 for a in analyses if a.get("anomaly_indicators"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "flow_count": len(state.captured_flows),
                "analyses": analyses[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"Protocol analysis:\n{ctx}",
            schema=ProtocolAnalysisOutput,
        )
        if hasattr(llm_result, "anomalous_count") and llm_result.anomalous_count > anomalous:
            anomalous = llm_result.anomalous_count
        logger.info(
            "llm_enhanced",
            node="analyze_protocols",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_protocols",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "analyze_protocols",
        f"analyzing {len(state.captured_flows)} flows",
        f"{anomalous} anomalous protocols",
        elapsed,
        "protocol_analyzer",
    )

    return {
        "protocol_analyses": analyses,
        "anomalous_protocol_count": anomalous,
        "stage": NTIStage.DETECT_ANOMALIES,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_protocols",
    }


async def detect_anomalies(
    state: NetworkTrafficInspectorState,
) -> dict[str, Any]:
    """Detect anomalies from protocol analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    anomalies = await toolkit.detect_anomalies(
        state.protocol_analyses,
    )
    high_conf = sum(1 for a in anomalies if a.get("confidence", 0) > 0.8)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "analysis_count": len(state.protocol_analyses),
                "anomalies": anomalies[:10],
                "high_confidence": high_conf,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DETECT,
            user_prompt=f"Anomaly detection context:\n{ctx}",
            schema=AnomalyDetectionOutput,
        )
        if hasattr(llm_result, "high_confidence") and llm_result.high_confidence > high_conf:
            high_conf = llm_result.high_confidence
        logger.info(
            "llm_enhanced",
            node="detect_anomalies",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_anomalies",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "detect_anomalies",
        f"detecting in {len(state.protocol_analyses)} analyses",
        f"found {len(anomalies)} anomalies, {high_conf} high",
        elapsed,
        "anomaly_engine",
    )
    await toolkit.record_metric("anomalies", float(len(anomalies)))

    return {
        "detected_anomalies": anomalies,
        "high_confidence_count": high_conf,
        "stage": NTIStage.CLASSIFY_THREATS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "detect_anomalies",
    }


async def classify_threats(
    state: NetworkTrafficInspectorState,
) -> dict[str, Any]:
    """Classify detected anomalies into threat categories."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications = await toolkit.classify_threats(
        state.detected_anomalies,
    )
    critical = sum(1 for c in classifications if c.get("severity") == "critical")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "anomaly_count": len(state.detected_anomalies),
                "classifications": classifications[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CLASSIFY,
            user_prompt=(f"Threat classification context:\n{ctx}"),
            schema=ThreatClassifyOutput,
        )
        if hasattr(llm_result, "critical_count") and llm_result.critical_count > critical:
            critical = llm_result.critical_count
        logger.info(
            "llm_enhanced",
            node="classify_threats",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_threats",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "classify_threats",
        f"classifying {len(state.detected_anomalies)} anomalies",
        f"{critical} critical threats",
        elapsed,
        "threat_classifier",
    )

    return {
        "threat_classifications": classifications,
        "critical_threat_count": critical,
        "stage": NTIStage.ALERT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "classify_threats",
    }


async def generate_alerts(
    state: NetworkTrafficInspectorState,
) -> dict[str, Any]:
    """Generate alerts from threat classifications."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    alerts = await toolkit.generate_alerts(
        state.threat_classifications,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "threat_count": len(state.threat_classifications),
                "alert_count": len(alerts),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ALERT,
            user_prompt=f"Alert generation context:\n{ctx}",
            schema=AlertOutput,
        )
        if hasattr(llm_result, "alerts"):
            logger.info(
                "llm_enhanced",
                node="generate_alerts",
                llm_alerts=len(llm_result.alerts),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_alerts",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_alerts",
        f"alerting on {len(state.threat_classifications)} threats",
        f"generated {len(alerts)} alerts",
        elapsed,
        "alert_manager",
    )

    return {
        "generated_alerts": alerts,
        "stage": NTIStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "generate_alerts",
    }


async def generate_report(
    state: NetworkTrafficInspectorState,
) -> dict[str, Any]:
    """Generate final traffic inspection report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "total_flows": len(state.captured_flows),
        "total_bytes": state.total_bytes,
        "anomalous_protocols": state.anomalous_protocol_count,
        "anomalies_detected": len(state.detected_anomalies),
        "critical_threats": state.critical_threat_count,
        "alerts_generated": len(state.generated_alerts),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("inspection_duration_ms", float(duration_ms))
    await toolkit.record_metric(
        "total_flows",
        float(len(state.captured_flows)),
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing inspection {state.request_id}",
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
