"""Data Loss Prevention Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import DataFlow, ExfiltrationAttempt, SensitiveDataRecord
from .tools import DataLossPreventionToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_data_flows(
    state: dict[str, Any],
    toolkit: DataLossPreventionToolkit,
) -> dict[str, Any]:
    """Discover data flows across all monitored channels."""
    logger.info("dlp.node.discover_data_flows")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    session_start = time.time()

    channels = state.get("channels", None)
    window = state.get("time_window_hours", 24)

    flows = await toolkit.discover_data_flows(
        tenant_id=tenant_id,
        channels=channels,
        time_window_hours=window,
    )
    flow_dicts = [f.model_dump() for f in flows]

    total_mb = sum(f.volume_mb for f in flows)
    return {
        "data_flows_discovered": flow_dicts,
        "data_at_risk_gb": round(total_mb / 1024, 3),
        "session_start": session_start,
        "current_step": "discover_data_flows",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(flows)} data flows ({total_mb:.1f} MB) for tenant {tenant_id}"],
    }


async def classify_sensitive_data(
    state: dict[str, Any],
    toolkit: DataLossPreventionToolkit,
) -> dict[str, Any]:
    """Classify sensitive data in discovered flows."""
    logger.info("dlp.node.classify_sensitive_data")
    state = _to_dict(state)
    flow_dicts = state.get("data_flows_discovered", [])
    flows = [DataFlow(**f) for f in flow_dicts]

    content_samples = state.get("content_samples", None)
    records = await toolkit.classify_flow_data(
        flows=flows,
        content_samples=content_samples,
    )
    record_dicts = [r.model_dump() for r in records]

    # Count by data type
    type_counts: dict[str, int] = {}
    for r in records:
        type_counts[r.data_type] = type_counts.get(r.data_type, 0) + 1

    reasoning = f"Classified {len(records)} sensitive records: " + ", ".join(
        f"{k}={v}" for k, v in type_counts.items()
    )
    return {
        "sensitive_records": record_dicts,
        "current_step": "classify_sensitive_data",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def detect_exfiltration(
    state: dict[str, Any],
    toolkit: DataLossPreventionToolkit,
) -> dict[str, Any]:
    """Detect exfiltration attempts across all surfaces."""
    logger.info("dlp.node.detect_exfiltration")
    state = _to_dict(state)
    flow_dicts = state.get("data_flows_discovered", [])
    record_dicts = state.get("sensitive_records", [])

    flows = [DataFlow(**f) for f in flow_dicts]
    records = [SensitiveDataRecord(**r) for r in record_dicts]

    attempts = await toolkit.detect_exfiltration(
        flows=flows,
        sensitive_records=records,
    )
    attempt_dicts = [a.model_dump() for a in attempts]

    # LLM enhancement: exfiltration analysis
    reasoning_note = f"Detected {len(attempts)} exfiltration attempts"
    try:
        from .prompts import (
            SYSTEM_EXFILTRATION_ANALYSIS,
            ExfiltrationAnalysisResult,
        )

        context = json.dumps(
            {
                "total_flows": len(flows),
                "attempts": attempt_dicts[:20],
                "channels": list({a.channel.value for a in attempts}),
                "severities": list({a.severity for a in attempts}),
            },
            default=str,
        )
        llm_result = cast(
            ExfiltrationAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_EXFILTRATION_ANALYSIS,
                user_prompt=(f"Exfiltration analysis:\n{context}"),
                schema=ExfiltrationAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_loss_prevention",
            node="detect_exfiltration",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_loss_prevention",
            node="detect_exfiltration",
        )

    return {
        "exfiltration_attempts": attempt_dicts,
        "current_step": "detect_exfiltration",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def enforce_policies(
    state: dict[str, Any],
    toolkit: DataLossPreventionToolkit,
) -> dict[str, Any]:
    """Enforce DLP policies against exfiltration attempts."""
    logger.info("dlp.node.enforce_policies")
    state = _to_dict(state)
    attempt_dicts = state.get("exfiltration_attempts", [])
    attempts = [ExfiltrationAttempt(**a) for a in attempt_dicts]

    custom_policies = state.get("custom_policies", None)
    policies = await toolkit.enforce_policies(
        attempts=attempts,
        custom_policies=custom_policies,
    )
    policy_dicts = [p.model_dump() for p in policies]

    applied = sum(1 for p in policies if p.applied)

    # LLM enhancement: policy coverage analysis
    reasoning_note = f"Enforced {applied}/{len(policies)} policies"
    try:
        from .prompts import (
            SYSTEM_POLICY_ENFORCEMENT,
            PolicyEnforcementResult,
        )

        context = json.dumps(
            {
                "policies": policy_dicts,
                "channels_covered": list({p.channel.value for p in policies}),
                "total_applied": applied,
            },
            default=str,
        )
        llm_result = cast(
            PolicyEnforcementResult,
            await llm_structured(
                system_prompt=SYSTEM_POLICY_ENFORCEMENT,
                user_prompt=(f"Policy enforcement state:\n{context}"),
                schema=PolicyEnforcementResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_loss_prevention",
            node="enforce_policies",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_loss_prevention",
            node="enforce_policies",
        )

    return {
        "policies_enforced": policy_dicts,
        "current_step": "enforce_policies",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def respond_to_incidents(
    state: dict[str, Any],
    toolkit: DataLossPreventionToolkit,
) -> dict[str, Any]:
    """Respond to confirmed exfiltration incidents."""
    logger.info("dlp.node.respond_to_incidents")
    state = _to_dict(state)
    attempt_dicts = state.get("exfiltration_attempts", [])
    policy_dicts = state.get("policies_enforced", [])

    from .models import DLPPolicy

    attempts = [ExfiltrationAttempt(**a) for a in attempt_dicts]
    policies = [DLPPolicy(**p) for p in policy_dicts]

    responses = await toolkit.respond_to_incidents(
        attempts=attempts,
        policies=policies,
    )
    response_dicts = [r.model_dump() for r in responses]

    contained = sum(1 for r in responses if r.containment_status == "contained")
    escalated = sum(1 for r in responses if r.escalated)
    return {
        "incidents_responded": response_dicts,
        "current_step": "respond_to_incidents",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Responded to {len(responses)} incidents; {contained} contained, {escalated} escalated"
        ],
    }


async def report(
    state: dict[str, Any],
    toolkit: DataLossPreventionToolkit,
) -> dict[str, Any]:
    """Generate final DLP assessment report."""
    logger.info("dlp.node.report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    flows = state.get("data_flows_discovered", [])
    records = state.get("sensitive_records", [])
    attempts = state.get("exfiltration_attempts", [])
    policies = state.get("policies_enforced", [])
    incidents = state.get("incidents_responded", [])

    # Channel breakdown
    channel_counts: dict[str, int] = {}
    for a in attempts:
        ch = a.get("channel", "unknown")
        channel_counts[ch] = channel_counts.get(ch, 0) + 1

    # Severity breakdown
    severity_counts: dict[str, int] = {}
    for a in attempts:
        sev = a.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Data type breakdown
    dtype_counts: dict[str, int] = {}
    for r in records:
        dt = r.get("data_type", "unknown")
        dtype_counts[dt] = dtype_counts.get(dt, 0) + 1

    blocked = sum(1 for i in incidents if i.get("containment_status") == "contained")
    total_attempts = len(attempts)
    block_rate = blocked / total_attempts if total_attempts else 1.0

    stats = {
        "flows_discovered": len(flows),
        "sensitive_records": len(records),
        "exfiltration_attempts": total_attempts,
        "channel_breakdown": channel_counts,
        "severity_breakdown": severity_counts,
        "data_type_breakdown": dtype_counts,
        "policies_enforced": len(policies),
        "policies_applied": sum(1 for p in policies if p.get("applied", False)),
        "incidents_responded": len(incidents),
        "incidents_contained": blocked,
        "containment_rate": round(block_rate, 3),
        "data_at_risk_gb": state.get("data_at_risk_gb", 0),
    }

    # LLM enhancement: executive DLP report
    reasoning_note = (
        f"Report: {stats['flows_discovered']} flows, "
        f"{stats['exfiltration_attempts']} attempts, "
        f"containment={stats['containment_rate']:.1%}"
    )
    try:
        from .prompts import (
            SYSTEM_DLP_REPORT,
            DLPReportResult,
        )

        context = json.dumps(stats, default=str)
        llm_result = cast(
            DLPReportResult,
            await llm_structured(
                system_prompt=SYSTEM_DLP_REPORT,
                user_prompt=(f"DLP assessment stats:\n{context}"),
                schema=DLPReportResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_loss_prevention",
            node="report",
        )
        reasoning_note = f"{llm_result.executive_summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_loss_prevention",
            node="report",
        )

    return {
        "stats": stats,
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }
