"""IaC Security Scanner Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import IACResource, IACScanStage, Misconfiguration
from .tools import IACSecurityScannerToolkit

logger = structlog.get_logger()

_toolkit: IACSecurityScannerToolkit | None = None


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_templates(
    state: dict[str, Any],
    toolkit: IACSecurityScannerToolkit,
) -> dict[str, Any]:
    """Discover IaC template files."""
    logger.info("iac_scanner.node.discover_templates")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    targets = state.get("scan_targets", [])
    session_start = time.time()

    templates = await toolkit.discover_templates(
        tenant_id=tenant_id,
        targets=targets,
    )
    return {
        "discovered_templates": templates,
        "total_templates": len(templates),
        "stage": IACScanStage.DISCOVER_TEMPLATES.value,
        "session_start": session_start,
        "current_step": "discover_templates",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(templates)} templates"],
    }


async def parse_resources(
    state: dict[str, Any],
    toolkit: IACSecurityScannerToolkit,
) -> dict[str, Any]:
    """Parse resources from IaC templates."""
    logger.info("iac_scanner.node.parse_resources")
    state = _to_dict(state)
    templates = state.get("discovered_templates", [])
    targets = state.get("scan_targets", [])

    resources = await toolkit.parse_resources(
        templates,
        targets,
    )
    resource_dicts = [r.model_dump() for r in resources]

    return {
        "resources": resource_dicts,
        "stage": IACScanStage.PARSE_RESOURCES.value,
        "current_step": "parse_resources",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Parsed {len(resources)} resources"],
    }


async def scan_misconfigs(
    state: dict[str, Any],
    toolkit: IACSecurityScannerToolkit,
) -> dict[str, Any]:
    """Scan for misconfigurations."""
    logger.info("iac_scanner.node.scan_misconfigs")
    state = _to_dict(state)
    raw_resources = state.get("resources", [])
    resources = [IACResource(**r) if isinstance(r, dict) else r for r in raw_resources]
    targets = state.get("scan_targets", [])

    misconfigs = await toolkit.scan_misconfigs(
        resources,
        targets,
    )
    misconfig_dicts = [m.model_dump() for m in misconfigs]
    reasoning = f"Misconfiguration scan: {len(misconfigs)} findings"

    try:
        from .prompts import (
            SYSTEM_MISCONFIG_ANALYSIS,
            MisconfigAnalysisOutput,
        )

        context = json.dumps(
            {
                "count": len(misconfigs),
                "findings": misconfig_dicts[:15],
            },
            default=str,
        )
        llm_result = cast(
            MisconfigAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_MISCONFIG_ANALYSIS,
                user_prompt=f"IaC misconfigs:\n{context}",
                schema=MisconfigAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="iac_scanner",
            node="scan_misconfigs",
        )
        reasoning = f"{llm_result.summary} Priv-esc: {len(llm_result.privilege_escalation_paths)}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="iac_scanner",
            node="scan_misconfigs",
        )

    return {
        "misconfigurations": misconfig_dicts,
        "stage": IACScanStage.SCAN_MISCONFIGS.value,
        "current_step": "scan_misconfigs",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def evaluate_policies(
    state: dict[str, Any],
    toolkit: IACSecurityScannerToolkit,
) -> dict[str, Any]:
    """Evaluate findings against policies."""
    logger.info("iac_scanner.node.evaluate_policies")
    state = _to_dict(state)
    raw_misconfigs = state.get("misconfigurations", [])
    misconfigs = [Misconfiguration(**m) if isinstance(m, dict) else m for m in raw_misconfigs]
    raw_resources = state.get("resources", [])
    resources = [IACResource(**r) if isinstance(r, dict) else r for r in raw_resources]

    violations = await toolkit.evaluate_policies(
        misconfigs,
        resources,
    )
    reasoning = f"Policy eval: {len(violations)} violations"

    try:
        from .prompts import (
            SYSTEM_POLICY_ANALYSIS,
            PolicyAnalysisOutput,
        )

        context = json.dumps(
            {"violations": violations[:15]},
            default=str,
        )
        llm_result = cast(
            PolicyAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_POLICY_ANALYSIS,
                user_prompt=f"Policy violations:\n{context}",
                schema=PolicyAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="iac_scanner",
            node="evaluate_policies",
        )
        reasoning = llm_result.summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="iac_scanner",
            node="evaluate_policies",
        )

    return {
        "policy_violations": violations,
        "stage": IACScanStage.EVALUATE_POLICIES.value,
        "current_step": "evaluate_policies",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def prioritize_findings(
    state: dict[str, Any],
    toolkit: IACSecurityScannerToolkit,
) -> dict[str, Any]:
    """Prioritize all IaC findings."""
    logger.info("iac_scanner.node.prioritize")
    state = _to_dict(state)
    raw_misconfigs = state.get("misconfigurations", [])
    misconfigs = [Misconfiguration(**m) if isinstance(m, dict) else m for m in raw_misconfigs]
    violations = state.get("policy_violations", [])

    prioritized = toolkit.prioritize(misconfigs, violations)
    total = len(prioritized)
    critical = sum(1 for p in prioritized if p.get("severity") == "critical")

    return {
        "prioritized": prioritized,
        "total_findings": total,
        "critical_count": critical,
        "stage": IACScanStage.PRIORITIZE.value,
        "current_step": "prioritize",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Prioritized {total}: {critical} critical"],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: IACSecurityScannerToolkit,
) -> dict[str, Any]:
    """Generate final IaC scan report."""
    logger.info("iac_scanner.node.report")
    state = _to_dict(state)
    prioritized = state.get("prioritized", [])
    session_start = state.get("session_start", time.time())

    duration_ms = (time.time() - session_start) * 1000
    sev_dist: dict[str, int] = {}
    for p in prioritized:
        sev = p.get("severity", "medium")
        sev_dist[sev] = sev_dist.get(sev, 0) + 1

    stats = {
        "total_findings": len(prioritized),
        "critical_count": sev_dist.get("critical", 0),
        "total_templates": state.get("total_templates", 0),
        "severity_distribution": sev_dist,
        "scan_duration_ms": round(duration_ms, 2),
    }

    return {
        "stats": stats,
        "total_findings": len(prioritized),
        "critical_count": sev_dist.get("critical", 0),
        "stage": IACScanStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Report: {len(prioritized)} findings, {sev_dist.get('critical', 0)} critical"],
    }
