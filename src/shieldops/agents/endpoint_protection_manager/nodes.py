"""Endpoint Protection Manager Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AgentHealth,
    EndpointDevice,
    EPMStage,
    MalwareScan,
    PatchStatus,
    ReasoningStep,
)
from .tools import EndpointProtectionManagerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Inventory Endpoints
# ------------------------------------------------------------------


async def inventory_endpoints(
    state: dict[str, Any],
    toolkit: EndpointProtectionManagerToolkit,
) -> dict[str, Any]:
    """Discover and inventory all managed endpoints."""
    logger.info("epm.node.inventory_endpoints")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    endpoints = await toolkit.inventory_endpoints(tenant_id)
    data = [e.model_dump() for e in endpoints]

    note = f"Discovered {len(endpoints)} endpoints"

    return {
        "stage": EPMStage.CHECK_AGENTS.value,
        "endpoints": data,
        "total_endpoints": len(endpoints),
        "current_step": "inventory_endpoints",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="inventory_endpoints",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Check Agent Health
# ------------------------------------------------------------------


async def check_agents(
    state: dict[str, Any],
    toolkit: EndpointProtectionManagerToolkit,
) -> dict[str, Any]:
    """Check security agent health on all endpoints."""
    logger.info("epm.node.check_agents")
    state = _to_dict(state)

    endpoints = [EndpointDevice(**e) for e in state.get("endpoints", [])]
    health = await toolkit.check_agent_health(endpoints)
    data = [h.model_dump() for h in health]

    unhealthy = sum(1 for h in health if not h.running)
    note = f"Checked {len(health)} agents, {unhealthy} unhealthy"

    try:
        from .prompts import (
            SYSTEM_AGENT_HEALTH,
            AgentHealthInsight,
        )

        ctx = json.dumps(
            {
                "agents": [
                    {
                        "endpoint": h.endpoint_id,
                        "running": h.running,
                        "def_age": h.definitions_age_days,
                        "cpu_pct": h.cpu_pct,
                        "issues": h.issues,
                    }
                    for h in health[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            AgentHealthInsight,
            await llm_structured(
                system_prompt=SYSTEM_AGENT_HEALTH,
                user_prompt=f"Agent health data:\n{ctx}",
                schema=AgentHealthInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="epm",
            node="check_agents",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="epm",
            node="check_agents",
        )

    return {
        "stage": EPMStage.ASSESS_PATCHES.value,
        "agent_health": data,
        "current_step": "check_agents",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="check_agents",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Assess Patches
# ------------------------------------------------------------------


async def assess_patches(
    state: dict[str, Any],
    toolkit: EndpointProtectionManagerToolkit,
) -> dict[str, Any]:
    """Assess patch compliance across all endpoints."""
    logger.info("epm.node.assess_patches")
    state = _to_dict(state)

    endpoints = [EndpointDevice(**e) for e in state.get("endpoints", [])]
    patches = await toolkit.assess_patches(endpoints)
    data = [p.model_dump() for p in patches]

    crit_total = sum(p.missing_critical for p in patches)
    note = f"Assessed {len(patches)} endpoints, {crit_total} critical patches missing"

    try:
        from .prompts import SYSTEM_PATCH, PatchInsight

        ctx = json.dumps(
            {
                "patches": [
                    {
                        "endpoint": p.endpoint_id,
                        "missing_critical": p.missing_critical,
                        "missing_high": p.missing_high,
                        "reboot_pending": p.reboot_pending,
                    }
                    for p in patches[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PatchInsight,
            await llm_structured(
                system_prompt=SYSTEM_PATCH,
                user_prompt=f"Patch data:\n{ctx}",
                schema=PatchInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="epm",
            node="assess_patches",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="epm",
            node="assess_patches",
        )

    return {
        "stage": EPMStage.SCAN_MALWARE.value,
        "patch_statuses": data,
        "current_step": "assess_patches",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="assess_patches",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Scan Malware
# ------------------------------------------------------------------


async def scan_malware(
    state: dict[str, Any],
    toolkit: EndpointProtectionManagerToolkit,
) -> dict[str, Any]:
    """Run malware scans across all endpoints."""
    logger.info("epm.node.scan_malware")
    state = _to_dict(state)

    endpoints = [EndpointDevice(**e) for e in state.get("endpoints", [])]
    scans = await toolkit.scan_malware(endpoints)
    data = [s.model_dump() for s in scans]

    total_threats = sum(s.threats_found for s in scans)
    note = f"Scanned {len(scans)} endpoints, {total_threats} threats detected"

    try:
        from .prompts import SYSTEM_MALWARE, MalwareInsight

        ctx = json.dumps(
            {
                "scans": [
                    {
                        "endpoint": s.endpoint_id,
                        "threats": s.threats_found,
                        "quarantined": s.threats_quarantined,
                        "names": s.threat_names,
                    }
                    for s in scans[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            MalwareInsight,
            await llm_structured(
                system_prompt=SYSTEM_MALWARE,
                user_prompt=f"Malware scan data:\n{ctx}",
                schema=MalwareInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="epm",
            node="scan_malware",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="epm",
            node="scan_malware",
        )

    return {
        "stage": EPMStage.REMEDIATE_GAPS.value,
        "malware_scans": data,
        "current_step": "scan_malware",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="scan_malware",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Remediate Gaps
# ------------------------------------------------------------------


async def remediate_gaps(
    state: dict[str, Any],
    toolkit: EndpointProtectionManagerToolkit,
) -> dict[str, Any]:
    """Remediate protection gaps across endpoints."""
    logger.info("epm.node.remediate_gaps")
    state = _to_dict(state)

    endpoints = [EndpointDevice(**e) for e in state.get("endpoints", [])]
    health = [AgentHealth(**h) for h in state.get("agent_health", [])]
    patches = [PatchStatus(**p) for p in state.get("patch_statuses", [])]
    scans = [MalwareScan(**s) for s in state.get("malware_scans", [])]

    actions = await toolkit.remediate_gaps(
        endpoints,
        health,
        patches,
        scans,
    )
    data = [a.model_dump() for a in actions]

    executed = sum(1 for a in actions if a.status == "executed")
    note = f"Generated {len(actions)} remediation actions, {executed} auto-executed"

    protected = sum(1 for e in endpoints if e.status == "protected")

    return {
        "stage": EPMStage.REPORT.value,
        "remediation_actions": data,
        "protected_count": protected,
        "at_risk_count": len(endpoints) - protected,
        "current_step": "remediate_gaps",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="remediate_gaps",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: EndpointProtectionManagerToolkit,
) -> dict[str, Any]:
    """Compile the final endpoint protection report."""
    logger.info("epm.node.report")
    state = _to_dict(state)

    total = state.get("total_endpoints", 0)
    protected = state.get("protected_count", 0)
    at_risk = state.get("at_risk_count", 0)
    action_count = len(state.get("remediation_actions", []))
    threat_count = sum(s.get("threats_found", 0) for s in state.get("malware_scans", []))

    lines = [
        "# Endpoint Protection Report",
        "",
        f"**Total endpoints:** {total}",
        f"**Protected:** {protected}",
        f"**At risk:** {at_risk}",
        f"**Threats detected:** {threat_count}",
        f"**Remediation actions:** {action_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_endpoints": total,
                "protected": protected,
                "at_risk": at_risk,
                "threats": threat_count,
                "actions": action_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Endpoint protection report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="epm",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="epm",
            node="report",
        )

    return {
        "stage": EPMStage.REPORT.value,
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
