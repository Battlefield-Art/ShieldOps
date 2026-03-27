"""Unified Cloud Security Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CloudSecStage,
    CloudState,
    CloudThreat,
    PostureAssessment,
    ReasoningStep,
    ResponseOrchestration,
    RiskPriority,
)
from .tools import UnifiedCloudSecurityToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Collect Cloud State
# ------------------------------------------------------------------


async def collect_cloud_state(
    state: dict[str, Any],
    toolkit: UnifiedCloudSecurityToolkit,
) -> dict[str, Any]:
    """Collect cloud state across providers."""
    logger.info("cloud_sec.node.collect")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    providers = state.get("providers", ["aws"])
    cloud_states = await toolkit.collect_cloud_state(tenant_id, providers)
    data = [cs.model_dump() for cs in cloud_states]

    total = sum(cs.resource_count for cs in cloud_states)
    note = f"Collected state from {len(cloud_states)} regions, {total} resources"

    try:
        from .prompts import (
            SYSTEM_COLLECT,
            CloudStateInsight,
        )

        ctx = json.dumps(
            {
                "states": [
                    {
                        "platform": (cs.platform.value),
                        "region": cs.region,
                        "resources": (cs.resource_count),
                        "misconfigs": (cs.misconfiguration_count),
                    }
                    for cs in cloud_states[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            CloudStateInsight,
            await llm_structured(
                system_prompt=SYSTEM_COLLECT,
                user_prompt=(f"Cloud state:\n{ctx}"),
                schema=CloudStateInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cloud_sec",
            node="collect",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cloud_sec",
            node="collect",
        )

    return {
        "stage": (CloudSecStage.ASSESS_POSTURE.value),
        "cloud_states": data,
        "total_resources": total,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="collect_cloud_state",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Assess Posture
# ------------------------------------------------------------------


async def assess_posture(
    state: dict[str, Any],
    toolkit: UnifiedCloudSecurityToolkit,
) -> dict[str, Any]:
    """Assess security posture per function."""
    logger.info("cloud_sec.node.posture")
    state = _to_dict(state)

    cloud_states = [CloudState(**cs) for cs in state.get("cloud_states", [])]
    assessments = await toolkit.assess_posture(cloud_states)
    data = [a.model_dump() for a in assessments]

    avg = (
        round(
            sum(a.score for a in assessments) / len(assessments),
            1,
        )
        if assessments
        else 0.0
    )
    note = f"Assessed {len(assessments)} postures, avg score: {avg}"

    try:
        from .prompts import (
            SYSTEM_POSTURE,
            PostureInsight,
        )

        ctx = json.dumps(
            {
                "assessments": [
                    {
                        "platform": (a.platform.value),
                        "function": (a.function.value),
                        "score": a.score,
                        "critical": (a.critical_findings),
                    }
                    for a in assessments[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PostureInsight,
            await llm_structured(
                system_prompt=SYSTEM_POSTURE,
                user_prompt=(f"Posture data:\n{ctx}"),
                schema=PostureInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cloud_sec",
            node="posture",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cloud_sec",
            node="posture",
        )

    return {
        "stage": (CloudSecStage.DETECT_THREATS.value),
        "assessments": data,
        "avg_posture_score": avg,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="assess_posture",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Detect Threats
# ------------------------------------------------------------------


async def detect_threats(
    state: dict[str, Any],
    toolkit: UnifiedCloudSecurityToolkit,
) -> dict[str, Any]:
    """Detect cloud threats."""
    logger.info("cloud_sec.node.detect")
    state = _to_dict(state)

    cloud_states = [CloudState(**cs) for cs in state.get("cloud_states", [])]
    threats = await toolkit.detect_threats(cloud_states)
    data = [t.model_dump() for t in threats]

    critical = sum(1 for t in threats if t.severity == "critical")
    note = f"Detected {len(threats)} threats, {critical} critical"

    try:
        from .prompts import (
            SYSTEM_THREAT,
            ThreatInsight,
        )

        ctx = json.dumps(
            {
                "threats": [
                    {
                        "platform": (t.platform.value),
                        "type": t.threat_type,
                        "severity": t.severity,
                        "mitre": t.mitre_technique,
                    }
                    for t in threats[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ThreatInsight,
            await llm_structured(
                system_prompt=SYSTEM_THREAT,
                user_prompt=f"Threats:\n{ctx}",
                schema=ThreatInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cloud_sec",
            node="detect",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cloud_sec",
            node="detect",
        )

    return {
        "stage": (CloudSecStage.PRIORITIZE_RISKS.value),
        "threats": data,
        "critical_threats": critical,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="detect_threats",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Prioritize Risks
# ------------------------------------------------------------------


async def prioritize_risks(
    state: dict[str, Any],
    toolkit: UnifiedCloudSecurityToolkit,
) -> dict[str, Any]:
    """Prioritize risks from threats."""
    logger.info("cloud_sec.node.prioritize")
    state = _to_dict(state)

    threats = [CloudThreat(**t) for t in state.get("threats", [])]
    assessments = [PostureAssessment(**a) for a in state.get("assessments", [])]
    priorities = await toolkit.prioritize_risks(threats, assessments)
    data = [p.model_dump() for p in priorities]

    note = f"Prioritized {len(priorities)} risks"

    return {
        "stage": (CloudSecStage.ORCHESTRATE_RESPONSE.value),
        "priorities": data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="prioritize_risks",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Orchestrate Response
# ------------------------------------------------------------------


async def orchestrate_response(
    state: dict[str, Any],
    toolkit: UnifiedCloudSecurityToolkit,
) -> dict[str, Any]:
    """Orchestrate response actions."""
    logger.info("cloud_sec.node.respond")
    state = _to_dict(state)

    priorities = [RiskPriority(**p) for p in state.get("priorities", [])]
    responses = await toolkit.orchestrate_response(priorities)
    data = [r.model_dump() for r in responses]

    note = f"Orchestrated {len(responses)} responses"

    try:
        from .prompts import (
            SYSTEM_RESPONSE,
            ResponseInsight,
        )

        ctx = json.dumps(
            {
                "responses": [
                    {
                        "platform": (r.platform.value),
                        "action": r.action_type,
                        "automated": r.automated,
                        "status": r.status,
                    }
                    for r in responses[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ResponseInsight,
            await llm_structured(
                system_prompt=SYSTEM_RESPONSE,
                user_prompt=(f"Responses:\n{ctx}"),
                schema=ResponseInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cloud_sec",
            node="respond",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cloud_sec",
            node="respond",
        )

    return {
        "stage": CloudSecStage.REPORT.value,
        "responses": data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="orchestrate_response",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def report(
    state: dict[str, Any],
    toolkit: UnifiedCloudSecurityToolkit,
) -> dict[str, Any]:
    """Compile the final cloud security report."""
    logger.info("cloud_sec.node.report")
    state = _to_dict(state)

    total = state.get("total_resources", 0)
    critical = state.get("critical_threats", 0)
    avg = state.get("avg_posture_score", 0.0)
    responses = [ResponseOrchestration(**r) for r in state.get("responses", [])]

    lines = [
        "# Unified Cloud Security Report",
        "",
        f"**Total resources:** {total}",
        f"**Critical threats:** {critical}",
        f"**Avg posture score:** {avg}",
        "",
        "## Response Actions",
    ]
    for i, r in enumerate(responses[:10], 1):
        lines.append(
            f"{i}. [{r.platform.value}] "
            f"{r.action_type} — "
            f"{'auto' if r.automated else 'manual'}"
            f", status: {r.status}"
        )

    return {
        "stage": CloudSecStage.REPORT.value,
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
