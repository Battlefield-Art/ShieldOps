"""OT Protocol Monitor Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    OPMStage,
    OTDevice,
    OTThreat,
    ProtocolAnomaly,
    ProtocolEvent,
    ReasoningStep,
)
from .tools import OTProtocolMonitorToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Discover Devices
# ------------------------------------------------------------------


async def discover_devices(
    state: dict[str, Any],
    toolkit: OTProtocolMonitorToolkit,
) -> dict[str, Any]:
    """Discover OT/ICS devices on the network."""
    logger.info("opm.node.discover_devices")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    devices = await toolkit.discover_devices(tenant_id)
    data = [d.model_dump() for d in devices]

    note = f"Discovered {len(devices)} OT devices"

    return {
        "stage": OPMStage.MONITOR_PROTOCOLS.value,
        "devices": data,
        "total_devices_scanned": len(devices),
        "current_step": "discover_devices",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="discover_devices",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Monitor Protocols
# ------------------------------------------------------------------


async def monitor_protocols(
    state: dict[str, Any],
    toolkit: OTProtocolMonitorToolkit,
) -> dict[str, Any]:
    """Monitor OT protocol traffic."""
    logger.info("opm.node.monitor_protocols")
    state = _to_dict(state)

    devices = [OTDevice(**d) for d in state.get("devices", [])]
    events = await toolkit.monitor_protocols(devices)
    data = [e.model_dump() for e in events]

    note = f"Captured {len(events)} protocol events"

    return {
        "stage": OPMStage.DETECT_ANOMALIES.value,
        "events": data,
        "current_step": "monitor_protocols",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="monitor_protocols",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Detect Anomalies
# ------------------------------------------------------------------


async def detect_anomalies(
    state: dict[str, Any],
    toolkit: OTProtocolMonitorToolkit,
) -> dict[str, Any]:
    """Detect protocol anomalies from events."""
    logger.info("opm.node.detect_anomalies")
    state = _to_dict(state)

    events = [ProtocolEvent(**e) for e in state.get("events", [])]
    anomalies = await toolkit.detect_anomalies(events)
    data = [a.model_dump() for a in anomalies]

    note = f"Detected {len(anomalies)} anomalies across {len(events)} events"

    try:
        from .prompts import SYSTEM_ANOMALY, AnomalyInsight

        ctx = json.dumps(
            {
                "anomalies": [
                    {
                        "type": a.anomaly_type,
                        "device": a.device_id,
                        "protocol": a.protocol.value,
                        "confidence": a.confidence,
                    }
                    for a in anomalies[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            AnomalyInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANOMALY,
                user_prompt=f"OT anomalies:\n{ctx}",
                schema=AnomalyInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="opm",
            node="detect_anomalies",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="opm",
            node="detect_anomalies",
        )

    return {
        "stage": OPMStage.CLASSIFY_THREATS.value,
        "anomalies": data,
        "anomalies_detected": len(anomalies),
        "current_step": "detect_anomalies",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_anomalies",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Classify Threats
# ------------------------------------------------------------------


async def classify_threats(
    state: dict[str, Any],
    toolkit: OTProtocolMonitorToolkit,
) -> dict[str, Any]:
    """Classify anomalies into OT threat categories."""
    logger.info("opm.node.classify_threats")
    state = _to_dict(state)

    anomalies = [ProtocolAnomaly(**a) for a in state.get("anomalies", [])]
    threats = await toolkit.classify_threats(anomalies)
    data = [t.model_dump() for t in threats]

    critical = sum(1 for t in threats if t.severity.value == "critical")
    note = f"Classified {len(threats)} threats, {critical} critical"

    return {
        "stage": OPMStage.ALERT.value,
        "threats": data,
        "current_step": "classify_threats",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="classify_threats",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Alert
# ------------------------------------------------------------------


async def generate_alerts(
    state: dict[str, Any],
    toolkit: OTProtocolMonitorToolkit,
) -> dict[str, Any]:
    """Generate alerts for classified threats."""
    logger.info("opm.node.alert")
    state = _to_dict(state)

    threats = [OTThreat(**t) for t in state.get("threats", [])]
    alerts = await toolkit.generate_alerts(threats)
    data = [a.model_dump() for a in alerts]

    sent = sum(1 for a in alerts if a.notified)
    note = f"Generated {len(alerts)} alerts, {sent} notified"

    return {
        "stage": OPMStage.REPORT.value,
        "alerts": data,
        "current_step": "alert",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="alert",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: OTProtocolMonitorToolkit,
) -> dict[str, Any]:
    """Compile the final OT protocol monitoring report."""
    logger.info("opm.node.report")
    state = _to_dict(state)

    total_devices = state.get("total_devices_scanned", 0)
    anomaly_count = state.get("anomalies_detected", 0)
    threat_count = len(state.get("threats", []))
    alert_count = len(state.get("alerts", []))

    lines = [
        "# OT Protocol Monitor Report",
        "",
        f"**Devices scanned:** {total_devices}",
        f"**Anomalies detected:** {anomaly_count}",
        f"**Threats classified:** {threat_count}",
        f"**Alerts generated:** {alert_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "devices": total_devices,
                "anomalies": anomaly_count,
                "threats": threat_count,
                "alerts": alert_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"OT security report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="opm",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="opm",
            node="report",
        )

    return {
        "stage": OPMStage.REPORT.value,
        "report": report_text,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
