"""Node implementations for the Data Exfiltration Monitor."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.data_exfiltration_monitor.models import (
    DataExfiltrationMonitorState,
    DEMStage,
    ReasoningStep,
)
from shieldops.agents.data_exfiltration_monitor.prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_BLOCK,
    SYSTEM_CLASSIFY,
    SYSTEM_DETECT,
    SYSTEM_MONITOR,
    BlockDecisionOutput,
    ChannelMonitorOutput,
    ExfilDetectionOutput,
    FlowAnalysisOutput,
    SensitivityOutput,
)
from shieldops.agents.data_exfiltration_monitor.tools import (
    DataExfiltrationMonitorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: DataExfiltrationMonitorToolkit | None = None


def _get_toolkit() -> DataExfiltrationMonitorToolkit:
    if _toolkit is None:
        return DataExfiltrationMonitorToolkit()
    return _toolkit


def _step(
    state: DataExfiltrationMonitorState,
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


async def monitor_channels(
    state: DataExfiltrationMonitorState,
) -> dict[str, Any]:
    """Monitor data transfer channels for activity."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.monitor_channels(state.monitor_config)
    channels = set(f.get("channel", "") for f in raw)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "channels": list(channels),
                "flow_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_MONITOR,
            user_prompt=(f"Channel monitoring context:\n{ctx}"),
            schema=ChannelMonitorOutput,
        )
        if hasattr(llm_result, "suspicious_flows"):
            logger.info(
                "llm_enhanced",
                node="monitor_channels",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="monitor_channels",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "monitor_channels",
        f"channels={list(channels)}",
        f"found {len(raw)} flows across {len(channels)} channels",
        elapsed,
        "network_monitor",
    )
    await toolkit.record_metric("flows", float(len(raw)))

    return {
        "data_flows": raw,
        "channel_count": len(channels),
        "stage": DEMStage.ANALYZE_FLOWS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "monitor_channels",
        "session_start": start,
    }


async def analyze_flows(
    state: DataExfiltrationMonitorState,
) -> dict[str, Any]:
    """Analyze data flows for anomalous patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyzed = await toolkit.analyze_data_flows(state.data_flows)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "flow_count": len(state.data_flows),
                "analyzed": analyzed[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=(f"Flow analysis context:\n{ctx}"),
            schema=FlowAnalysisOutput,
        )
        if hasattr(llm_result, "anomalous_flows"):
            logger.info(
                "llm_enhanced",
                node="analyze_flows",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_flows",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "analyze_flows",
        f"analyzing {len(state.data_flows)} flows",
        f"analyzed {len(analyzed)} flows",
        elapsed,
        "flow_analyzer",
    )

    return {
        "data_flows": analyzed,
        "stage": DEMStage.DETECT_EXFIL,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_flows",
    }


async def detect_exfiltration(
    state: DataExfiltrationMonitorState,
) -> dict[str, Any]:
    """Detect exfiltration attempts from analyzed flows."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    detections = await toolkit.detect_exfiltration(
        state.data_flows,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "flow_count": len(state.data_flows),
                "detections": detections[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DETECT,
            user_prompt=(f"Exfil detection context:\n{ctx}"),
            schema=ExfilDetectionOutput,
        )
        if hasattr(llm_result, "exfil_count"):
            logger.info(
                "llm_enhanced",
                node="detect_exfiltration",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_exfiltration",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "detect_exfiltration",
        f"detecting across {len(state.data_flows)} flows",
        f"found {len(detections)} exfil attempts",
        elapsed,
        "dlp_engine",
    )
    await toolkit.record_metric(
        "exfil_detections",
        float(len(detections)),
    )

    return {
        "detections": detections,
        "exfil_count": len(detections),
        "stage": DEMStage.CLASSIFY_SENSITIVITY,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "detect_exfiltration",
    }


async def classify_sensitivity(
    state: DataExfiltrationMonitorState,
) -> dict[str, Any]:
    """Classify sensitivity of exfiltrated data."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications = await toolkit.classify_sensitivity(
        state.detections,
    )
    sensitive = sum(
        1 for c in classifications if c.get("sensitivity") in ("restricted", "confidential")
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "detection_count": len(state.detections),
                "classifications": classifications[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CLASSIFY,
            user_prompt=(f"Sensitivity context:\n{ctx}"),
            schema=SensitivityOutput,
        )
        if hasattr(llm_result, "sensitive_count") and llm_result.sensitive_count > sensitive:
            sensitive = llm_result.sensitive_count
        logger.info(
            "llm_enhanced",
            node="classify_sensitivity",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_sensitivity",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "classify_sensitivity",
        f"classifying {len(state.detections)} detections",
        f"{sensitive} sensitive detections",
        elapsed,
        "classifier",
    )

    return {
        "classifications": classifications,
        "sensitive_count": sensitive,
        "stage": DEMStage.BLOCK,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "classify_sensitivity",
    }


async def block_transfers(
    state: DataExfiltrationMonitorState,
) -> dict[str, Any]:
    """Block exfiltration transfers based on policy."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.block_transfer(
        state.detections,
        state.classifications,
    )
    blocked = sum(1 for a in actions if a.get("success"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "detection_count": len(state.detections),
                "actions": actions[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_BLOCK,
            user_prompt=(f"Block decision context:\n{ctx}"),
            schema=BlockDecisionOutput,
        )
        if hasattr(llm_result, "should_block"):
            logger.info(
                "llm_enhanced",
                node="block_transfers",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="block_transfers",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "block_transfers",
        f"evaluating {len(state.detections)} detections",
        f"blocked {blocked} transfers",
        elapsed,
        "policy_engine",
    )
    await toolkit.record_metric("blocked", float(blocked))

    return {
        "block_actions": actions,
        "blocked_count": blocked,
        "stage": DEMStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "block_transfers",
    }


async def generate_report(
    state: DataExfiltrationMonitorState,
) -> dict[str, Any]:
    """Generate final exfiltration monitoring report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "total_flows": len(state.data_flows),
        "channels_monitored": state.channel_count,
        "exfil_detections": state.exfil_count,
        "sensitive_count": state.sensitive_count,
        "blocked_count": state.blocked_count,
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
