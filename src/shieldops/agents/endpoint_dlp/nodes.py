"""Endpoint DLP Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    DataMovement,
    EndpointActivity,
    EndpointDLPStage,
    PolicyAction,
    PolicyEnforcement,
    ReasoningStep,
    SensitivityClassification,
    ViolationInvestigation,
)
from .tools import EndpointDLPToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Monitor Endpoints
# ------------------------------------------------------------------


async def monitor_endpoints(
    state: dict[str, Any],
    toolkit: EndpointDLPToolkit,
) -> dict[str, Any]:
    """Monitor endpoint activity."""
    logger.info("endpoint_dlp.node.monitor")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    activities = await toolkit.monitor_endpoints(tenant_id)
    data = [a.model_dump() for a in activities]

    note = f"Monitoring {len(activities)} endpoints"

    try:
        from .prompts import (
            SYSTEM_MONITOR,
            EndpointInsight,
        )

        ctx = json.dumps(
            {
                "endpoints": [
                    {
                        "hostname": a.hostname,
                        "os": a.os,
                        "risk": a.risk_score,
                        "online": a.online,
                    }
                    for a in activities[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            EndpointInsight,
            await llm_structured(
                system_prompt=SYSTEM_MONITOR,
                user_prompt=(f"Endpoint data:\n{ctx}"),
                schema=EndpointInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="endpoint_dlp",
            node="monitor",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="endpoint_dlp",
            node="monitor",
        )

    return {
        "stage": (EndpointDLPStage.DETECT_DATA_MOVEMENT.value),
        "activities": data,
        "total_endpoints": len(activities),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="monitor_endpoints",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Detect Data Movement
# ------------------------------------------------------------------


async def detect_data_movement(
    state: dict[str, Any],
    toolkit: EndpointDLPToolkit,
) -> dict[str, Any]:
    """Detect data movement events."""
    logger.info("endpoint_dlp.node.detect")
    state = _to_dict(state)

    activities = [EndpointActivity(**a) for a in state.get("activities", [])]
    movements = await toolkit.detect_data_movement(activities)
    data = [m.model_dump() for m in movements]

    suspicious = sum(1 for m in movements if m.suspicious)
    note = f"Detected {len(movements)} movements, {suspicious} suspicious"

    try:
        from .prompts import (
            SYSTEM_DETECT,
            MovementInsight,
        )

        ctx = json.dumps(
            {
                "movements": [
                    {
                        "type": (m.movement_type.value),
                        "app": m.source_app,
                        "suspicious": m.suspicious,
                        "size": m.data_size_bytes,
                    }
                    for m in movements[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            MovementInsight,
            await llm_structured(
                system_prompt=SYSTEM_DETECT,
                user_prompt=(f"Movements:\n{ctx}"),
                schema=MovementInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="endpoint_dlp",
            node="detect",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="endpoint_dlp",
            node="detect",
        )

    return {
        "stage": (EndpointDLPStage.CLASSIFY_SENSITIVITY.value),
        "movements": data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="detect_data_movement",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Classify Sensitivity
# ------------------------------------------------------------------


async def classify_sensitivity(
    state: dict[str, Any],
    toolkit: EndpointDLPToolkit,
) -> dict[str, Any]:
    """Classify sensitivity of data movements."""
    logger.info("endpoint_dlp.node.classify")
    state = _to_dict(state)

    movements = [DataMovement(**m) for m in state.get("movements", [])]
    classifications = await toolkit.classify_sensitivity(movements)
    data = [c.model_dump() for c in classifications]

    pii = sum(1 for c in classifications if c.pii_detected)
    note = f"Classified {len(classifications)}, {pii} with PII"

    return {
        "stage": (EndpointDLPStage.ENFORCE_POLICIES.value),
        "classifications": data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="classify_sensitivity",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Enforce Policies
# ------------------------------------------------------------------


async def enforce_policies(
    state: dict[str, Any],
    toolkit: EndpointDLPToolkit,
) -> dict[str, Any]:
    """Enforce DLP policies."""
    logger.info("endpoint_dlp.node.enforce")
    state = _to_dict(state)

    movements = [DataMovement(**m) for m in state.get("movements", [])]
    classifications = [SensitivityClassification(**c) for c in state.get("classifications", [])]
    enforcements = await toolkit.enforce_policies(movements, classifications)
    data = [e.model_dump() for e in enforcements]

    blocked = sum(1 for e in enforcements if e.action == PolicyAction.BLOCK)
    note = f"Enforced {len(enforcements)} policies, {blocked} blocked"

    try:
        from .prompts import (
            SYSTEM_ENFORCE,
            PolicyInsight,
        )

        ctx = json.dumps(
            {
                "enforcements": [
                    {
                        "policy": e.policy_name,
                        "action": e.action.value,
                        "escalated": e.escalated,
                    }
                    for e in enforcements[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PolicyInsight,
            await llm_structured(
                system_prompt=SYSTEM_ENFORCE,
                user_prompt=(f"Enforcements:\n{ctx}"),
                schema=PolicyInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="endpoint_dlp",
            node="enforce",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="endpoint_dlp",
            node="enforce",
        )

    return {
        "stage": (EndpointDLPStage.INVESTIGATE_VIOLATIONS.value),
        "enforcements": data,
        "movements_blocked": blocked,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="enforce_policies",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Investigate Violations
# ------------------------------------------------------------------


async def investigate_violations(
    state: dict[str, Any],
    toolkit: EndpointDLPToolkit,
) -> dict[str, Any]:
    """Investigate policy violations."""
    logger.info("endpoint_dlp.node.investigate")
    state = _to_dict(state)

    movements = [DataMovement(**m) for m in state.get("movements", [])]
    enforcements = [PolicyEnforcement(**e) for e in state.get("enforcements", [])]
    investigations = await toolkit.investigate_violations(movements, enforcements)
    data = [inv.model_dump() for inv in investigations]

    note = f"Investigated {len(investigations)} violations"

    try:
        from .prompts import (
            SYSTEM_INVESTIGATE,
            ViolationInsight,
        )

        ctx = json.dumps(
            {
                "violations": [
                    {
                        "user": inv.user,
                        "type": inv.violation_type,
                        "severity": inv.severity,
                    }
                    for inv in investigations[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ViolationInsight,
            await llm_structured(
                system_prompt=SYSTEM_INVESTIGATE,
                user_prompt=(f"Violations:\n{ctx}"),
                schema=ViolationInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="endpoint_dlp",
            node="investigate",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="endpoint_dlp",
            node="investigate",
        )

    return {
        "stage": EndpointDLPStage.REPORT.value,
        "investigations": data,
        "violations_count": len(investigations),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="investigate_violations",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def report(
    state: dict[str, Any],
    toolkit: EndpointDLPToolkit,
) -> dict[str, Any]:
    """Compile the final endpoint DLP report."""
    logger.info("endpoint_dlp.node.report")
    state = _to_dict(state)

    total = state.get("total_endpoints", 0)
    blocked = state.get("movements_blocked", 0)
    violations = state.get("violations_count", 0)
    investigations = [ViolationInvestigation(**inv) for inv in state.get("investigations", [])]

    lines = [
        "# Endpoint DLP Report",
        "",
        f"**Endpoints monitored:** {total}",
        f"**Movements blocked:** {blocked}",
        f"**Violations investigated:** {violations}",
        "",
        "## Violations",
    ]
    for i, inv in enumerate(investigations[:10], 1):
        lines.append(
            f"{i}. [{inv.severity}] {inv.user} — {inv.violation_type}: {inv.recommended_action}"
        )

    return {
        "stage": EndpointDLPStage.REPORT.value,
        "report": "\n".join(lines),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
