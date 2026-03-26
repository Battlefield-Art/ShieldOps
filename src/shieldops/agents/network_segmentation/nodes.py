"""Network Segmentation Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    SegmentationStage,
    SegmentationViolation,
    TrafficFlow,
    ViolationSeverity,
)
from .tools import NetworkSegmentationToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_zones(
    state: dict[str, Any], toolkit: NetworkSegmentationToolkit
) -> dict[str, Any]:
    """Discover network zones from infrastructure sources."""
    logger.info("network_segmentation.node.discover_zones")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    environment = state.get("environment", "production")

    zones = await toolkit.discover_network_zones(
        tenant_id=tenant_id,
        environment=environment,
    )
    zone_dicts = [z.model_dump() for z in zones]

    return {
        "zones": zone_dicts,
        "total_zones": len(zone_dicts),
        "current_stage": SegmentationStage.DISCOVER_ZONES.value,
        "session_start": time.time(),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(zone_dicts)} network zones in {environment}"],
    }


async def map_traffic(state: dict[str, Any], toolkit: NetworkSegmentationToolkit) -> dict[str, Any]:
    """Map traffic flows between discovered zones."""
    logger.info("network_segmentation.node.map_traffic")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    zones = state.get("zones", [])
    zone_ids = [z.get("id", "") for z in zones]

    flows = await toolkit.map_traffic_flows(
        tenant_id=tenant_id,
        zone_ids=zone_ids,
    )
    flow_dicts = [f.model_dump() for f in flows]

    unauthorized = sum(1 for f in flows if not f.authorized)
    return {
        "traffic_flows": flow_dicts,
        "total_flows": len(flow_dicts),
        "current_stage": SegmentationStage.MAP_TRAFFIC.value,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Mapped {len(flow_dicts)} traffic flows, {unauthorized} unauthorized"],
    }


async def detect_violations(
    state: dict[str, Any], toolkit: NetworkSegmentationToolkit
) -> dict[str, Any]:
    """Detect segmentation policy violations from traffic flows."""
    logger.info("network_segmentation.node.detect_violations")
    state = _to_dict(state)
    raw_flows = state.get("traffic_flows", [])

    flows = [TrafficFlow(**f) for f in raw_flows]
    violations = await toolkit.detect_violations(flows)
    violation_dicts = [v.model_dump() for v in violations]

    critical = sum(
        1 for v in violations if v.severity in (ViolationSeverity.CRITICAL, ViolationSeverity.HIGH)
    )

    return {
        "violations": violation_dicts,
        "total_violations": len(violation_dicts),
        "critical_violations": critical,
        "current_stage": SegmentationStage.DETECT_VIOLATIONS.value,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Detected {len(violation_dicts)} violations, {critical} critical/high"],
    }


async def assess_risk(state: dict[str, Any], toolkit: NetworkSegmentationToolkit) -> dict[str, Any]:
    """Assess risk using violation analysis and optional LLM enhancement."""
    logger.info("network_segmentation.node.assess_risk")
    state = _to_dict(state)
    zones = state.get("zones", [])
    violations = state.get("violations", [])
    total_flows = state.get("total_flows", 0)

    # Compute per-zone risk scores
    risk_scores: dict[str, float] = {}
    for zone in zones:
        zid = zone.get("id", "")
        zone_violations = [
            v for v in violations if v.get("source_zone") == zid or v.get("dest_zone") == zid
        ]
        if not zone_violations:
            risk_scores[zid] = 0.0
            continue

        severity_weights = {
            ViolationSeverity.CRITICAL.value: 1.0,
            ViolationSeverity.HIGH.value: 0.75,
            ViolationSeverity.MEDIUM.value: 0.5,
            ViolationSeverity.LOW.value: 0.25,
            ViolationSeverity.INFO.value: 0.1,
        }
        total_weight = sum(
            severity_weights.get(v.get("severity", "medium"), 0.5) for v in zone_violations
        )
        risk_scores[zid] = round(min(total_weight / max(len(zone_violations), 1), 1.0), 4)

    reasoning_note = (
        f"Assessed risk for {len(zones)} zones, "
        f"max score={max(risk_scores.values()) if risk_scores else 0:.2f}"
    )

    # LLM enhancement: deeper risk analysis
    try:
        from .prompts import SYSTEM_RISK_ASSESSMENT, RiskAssessmentResult

        risk_context = json.dumps(
            {
                "zone_count": len(zones),
                "total_flows": total_flows,
                "violation_count": len(violations),
                "violations_summary": violations[:20],
                "risk_scores": risk_scores,
            },
            default=str,
        )
        llm_result = cast(
            RiskAssessmentResult,
            await llm_structured(
                system_prompt=SYSTEM_RISK_ASSESSMENT,
                user_prompt=(f"Network segmentation data:\n{risk_context}"),
                schema=RiskAssessmentResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="network_segmentation",
            node="assess_risk",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="network_segmentation",
            node="assess_risk",
        )

    return {
        "risk_scores": risk_scores,
        "current_stage": SegmentationStage.ASSESS_RISK.value,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def enforce_policies(
    state: dict[str, Any], toolkit: NetworkSegmentationToolkit
) -> dict[str, Any]:
    """Enforce segmentation policies for detected violations."""
    logger.info("network_segmentation.node.enforce_policies")
    state = _to_dict(state)
    raw_violations = state.get("violations", [])

    violations = [SegmentationViolation(**v) for v in raw_violations]
    enforcements = await toolkit.enforce_segmentation_policies(violations)
    enforcement_dicts = [e.model_dump() for e in enforcements]

    applied = sum(1 for e in enforcements if e.applied)
    success = sum(1 for e in enforcements if e.success)

    reasoning_note = (
        f"Enforcement: {len(enforcement_dicts)} actions planned, "
        f"{applied} applied, {success} successful"
    )

    # LLM enhancement: enforcement plan validation
    try:
        from .prompts import SYSTEM_ENFORCEMENT_PLAN, EnforcementPlanResult

        plan_context = json.dumps(
            {
                "violations": raw_violations[:15],
                "enforcements": enforcement_dicts[:15],
                "risk_scores": state.get("risk_scores", {}),
            },
            default=str,
        )
        llm_result = cast(
            EnforcementPlanResult,
            await llm_structured(
                system_prompt=SYSTEM_ENFORCEMENT_PLAN,
                user_prompt=(f"Enforcement plan context:\n{plan_context}"),
                schema=EnforcementPlanResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="network_segmentation",
            node="enforce_policies",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="network_segmentation",
            node="enforce_policies",
        )

    return {
        "enforcements": enforcement_dicts,
        "total_enforcements": len(enforcement_dicts),
        "current_stage": SegmentationStage.ENFORCE_POLICIES.value,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def report(state: dict[str, Any], toolkit: NetworkSegmentationToolkit) -> dict[str, Any]:
    """Generate final network segmentation report."""
    logger.info("network_segmentation.node.report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    return {
        "current_stage": SegmentationStage.REPORT.value,
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report complete: {state.get('total_zones', 0)} zones, "
            f"{state.get('total_flows', 0)} flows, "
            f"{state.get('total_violations', 0)} violations, "
            f"{state.get('total_enforcements', 0)} enforcements"
        ],
    }
