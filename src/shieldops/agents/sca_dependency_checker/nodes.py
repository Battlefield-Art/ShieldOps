"""SCA Dependency Checker Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import CVEMatch, DependencyRecord, SCAStage
from .tools import SCADependencyCheckerToolkit

logger = structlog.get_logger()

_toolkit: SCADependencyCheckerToolkit | None = None


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_manifests(
    state: dict[str, Any],
    toolkit: SCADependencyCheckerToolkit,
) -> dict[str, Any]:
    """Discover dependency manifest files."""
    logger.info("sca_checker.node.discover_manifests")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    targets = state.get("scan_targets", [])
    session_start = time.time()

    manifests = await toolkit.discover_manifests(
        tenant_id=tenant_id,
        targets=targets,
    )
    return {
        "manifests": manifests,
        "stage": SCAStage.DISCOVER_MANIFESTS.value,
        "session_start": session_start,
        "current_step": "discover_manifests",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(manifests)} manifests"],
    }


async def parse_dependencies(
    state: dict[str, Any],
    toolkit: SCADependencyCheckerToolkit,
) -> dict[str, Any]:
    """Parse dependencies from manifests."""
    logger.info("sca_checker.node.parse_deps")
    state = _to_dict(state)
    manifests = state.get("manifests", [])
    targets = state.get("scan_targets", [])

    deps = await toolkit.parse_dependencies(manifests, targets)
    dep_dicts = [d.model_dump() for d in deps]

    return {
        "dependencies": dep_dicts,
        "total_dependencies": len(deps),
        "stage": SCAStage.PARSE_DEPENDENCIES.value,
        "current_step": "parse_dependencies",
        "reasoning_chain": state.get("reasoning_chain", []) + [f"Parsed {len(deps)} dependencies"],
    }


async def match_cves(
    state: dict[str, Any],
    toolkit: SCADependencyCheckerToolkit,
) -> dict[str, Any]:
    """Match dependencies against CVE database."""
    logger.info("sca_checker.node.match_cves")
    state = _to_dict(state)
    raw = state.get("dependencies", [])
    deps = [DependencyRecord(**d) if isinstance(d, dict) else d for d in raw]

    matches = await toolkit.match_cves(deps)
    match_dicts = [m.model_dump() for m in matches]
    reasoning = f"CVE matching: {len(matches)} matches"

    try:
        from .prompts import SYSTEM_CVE_ANALYSIS, CVEAnalysisOutput

        context = json.dumps(
            {
                "cve_count": len(matches),
                "cves": match_dicts[:15],
            },
            default=str,
        )
        llm_result = cast(
            CVEAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_CVE_ANALYSIS,
                user_prompt=f"CVE matches:\n{context}",
                schema=CVEAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sca_checker",
            node="match_cves",
        )
        reasoning = f"{llm_result.summary} Exploitable: {len(llm_result.exploitable_cves)}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sca_checker",
            node="match_cves",
        )

    return {
        "cve_matches": match_dicts,
        "stage": SCAStage.MATCH_CVES.value,
        "current_step": "match_cves",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def check_licenses(
    state: dict[str, Any],
    toolkit: SCADependencyCheckerToolkit,
) -> dict[str, Any]:
    """Check license compatibility."""
    logger.info("sca_checker.node.check_licenses")
    state = _to_dict(state)
    raw = state.get("dependencies", [])
    deps = [DependencyRecord(**d) if isinstance(d, dict) else d for d in raw]

    violations = await toolkit.check_licenses(deps)
    reasoning = f"License check: {len(violations)} violations"

    try:
        from .prompts import (
            SYSTEM_LICENSE_ANALYSIS,
            LicenseAnalysisOutput,
        )

        context = json.dumps(
            {"violations": violations},
            default=str,
        )
        llm_result = cast(
            LicenseAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_LICENSE_ANALYSIS,
                user_prompt=f"License data:\n{context}",
                schema=LicenseAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sca_checker",
            node="check_licenses",
        )
        reasoning = llm_result.summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sca_checker",
            node="check_licenses",
        )

    return {
        "license_violations": violations,
        "stage": SCAStage.CHECK_LICENSES.value,
        "current_step": "check_licenses",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def prioritize_findings(
    state: dict[str, Any],
    toolkit: SCADependencyCheckerToolkit,
) -> dict[str, Any]:
    """Prioritize all SCA findings."""
    logger.info("sca_checker.node.prioritize")
    state = _to_dict(state)
    raw_cves = state.get("cve_matches", [])
    cves = [CVEMatch(**c) if isinstance(c, dict) else c for c in raw_cves]
    violations = state.get("license_violations", [])

    prioritized = toolkit.prioritize(cves, violations)
    total = len(prioritized)
    critical = sum(1 for p in prioritized if p.get("severity") == "critical")

    return {
        "prioritized": prioritized,
        "total_findings": total,
        "critical_count": critical,
        "stage": SCAStage.PRIORITIZE.value,
        "current_step": "prioritize",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Prioritized {total}: {critical} critical"],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: SCADependencyCheckerToolkit,
) -> dict[str, Any]:
    """Generate final SCA report."""
    logger.info("sca_checker.node.report")
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
        "total_dependencies": state.get(
            "total_dependencies",
            0,
        ),
        "severity_distribution": sev_dist,
        "scan_duration_ms": round(duration_ms, 2),
    }

    return {
        "stats": stats,
        "total_findings": len(prioritized),
        "critical_count": sev_dist.get("critical", 0),
        "stage": SCAStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Report: {len(prioritized)} findings, {sev_dist.get('critical', 0)} critical"],
    }
