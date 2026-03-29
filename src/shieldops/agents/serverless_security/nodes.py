"""Serverless Security Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    PermissionFinding,
    ServerlessFunction,
    ServerlessStage,
)
from .tools import ServerlessSecurityToolkit

logger = structlog.get_logger()

_toolkit: ServerlessSecurityToolkit | None = None


def set_toolkit(toolkit: ServerlessSecurityToolkit) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> ServerlessSecurityToolkit:
    global _toolkit
    if _toolkit is None:
        _toolkit = ServerlessSecurityToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_functions(
    state: dict[str, Any],
    toolkit: ServerlessSecurityToolkit,
) -> dict[str, Any]:
    """Discover serverless functions across platforms."""
    logger.info("serverless.node.discover")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    platforms = state.get("platforms", ["aws_lambda"])

    functions = await toolkit.discover_functions(tenant_id, platforms)
    functions_data = [f.model_dump() for f in functions]

    return {
        "stage": ServerlessStage.ANALYZE_PERMISSIONS.value,
        "functions": functions_data,
        "current_step": "discover_functions",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(functions)} functions across {', '.join(platforms)}"],
    }


async def analyze_permissions(
    state: dict[str, Any],
    toolkit: ServerlessSecurityToolkit,
) -> dict[str, Any]:
    """Analyze permissions for discovered functions."""
    logger.info("serverless.node.permissions")
    state = _to_dict(state)

    raw_fns = state.get("functions", [])
    functions = [ServerlessFunction(**f) for f in raw_fns]

    findings = await toolkit.analyze_permissions(functions)
    findings_data = [f.model_dump() for f in findings]

    reasoning_note = f"Found {len(findings)} permission issues across {len(functions)} functions"

    try:
        from .prompts import (
            SYSTEM_PERMISSION_ANALYSIS,
            PermissionAnalysisOutput,
        )

        context = json.dumps(
            {
                "functions": len(functions),
                "findings": len(findings),
                "critical": sum(1 for f in findings if f.severity == "critical"),
                "high": sum(1 for f in findings if f.severity == "high"),
            },
            default=str,
        )
        llm_result = cast(
            PermissionAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_PERMISSION_ANALYSIS,
                user_prompt=f"Permission context:\n{context}",
                schema=PermissionAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="serverless",
            node="permissions",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="serverless",
            node="permissions",
        )

    return {
        "stage": ServerlessStage.SCAN_DEPENDENCIES.value,
        "permission_findings": findings_data,
        "current_step": "analyze_permissions",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def scan_dependencies(
    state: dict[str, Any],
    toolkit: ServerlessSecurityToolkit,
) -> dict[str, Any]:
    """Scan function dependencies for vulnerabilities."""
    logger.info("serverless.node.dependencies")
    state = _to_dict(state)

    raw_fns = state.get("functions", [])
    functions = [ServerlessFunction(**f) for f in raw_fns]

    vulns = await toolkit.scan_dependencies(functions)
    vulns_data = [v.model_dump() for v in vulns]

    reasoning_note = f"Found {len(vulns)} dependency vulnerabilities"

    try:
        from .prompts import (
            SYSTEM_DEPENDENCY_SCAN,
            DependencyScanOutput,
        )

        context = json.dumps(
            {
                "total_vulns": len(vulns),
                "critical": sum(1 for v in vulns if v.severity == "critical"),
            },
            default=str,
        )
        llm_result = cast(
            DependencyScanOutput,
            await llm_structured(
                system_prompt=SYSTEM_DEPENDENCY_SCAN,
                user_prompt=f"Dependency context:\n{context}",
                schema=DependencyScanOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="serverless",
            node="dependencies",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="serverless",
            node="dependencies",
        )

    return {
        "stage": ServerlessStage.DETECT_THREATS.value,
        "dependency_vulns": vulns_data,
        "current_step": "scan_dependencies",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def detect_threats(
    state: dict[str, Any],
    toolkit: ServerlessSecurityToolkit,
) -> dict[str, Any]:
    """Detect threats targeting serverless functions."""
    logger.info("serverless.node.threats")
    state = _to_dict(state)

    raw_fns = state.get("functions", [])
    functions = [ServerlessFunction(**f) for f in raw_fns]
    raw_perms = state.get("permission_findings", [])
    perm_findings = [PermissionFinding(**p) for p in raw_perms]

    threats = await toolkit.detect_threats(functions, perm_findings)
    threats_data = [t.model_dump() for t in threats]

    return {
        "stage": ServerlessStage.ASSESS_RISK.value,
        "threat_detections": threats_data,
        "current_step": "detect_threats",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Detected {len(threats)} active threats"],
    }


async def assess_risk(
    state: dict[str, Any],
    toolkit: ServerlessSecurityToolkit,
) -> dict[str, Any]:
    """Assess overall serverless security risk."""
    logger.info("serverless.node.assess_risk")
    state = _to_dict(state)

    raw_fns = state.get("functions", [])
    raw_perms = state.get("permission_findings", [])
    raw_vulns = state.get("dependency_vulns", [])
    raw_threats = state.get("threat_detections", [])

    all_scores = [p.get("risk_score", 0.0) for p in raw_perms] + [
        t.get("risk_score", 0.0) for t in raw_threats
    ]
    risk_score = round(max(all_scores) if all_scores else 0.0, 1)

    elapsed = round(
        (time.time() - state.get("session_start", time.time())) * 1000,
        1,
    )

    stats = {
        "functions_scanned": len(raw_fns),
        "permission_findings": len(raw_perms),
        "dependency_vulns": len(raw_vulns),
        "threats_detected": len(raw_threats),
        "risk_score": risk_score,
        "platforms": state.get("platforms", []),
    }

    report_summary = (
        f"Serverless risk: {risk_score}/100."
        f" {len(raw_fns)} functions,"
        f" {len(raw_perms)} permission issues,"
        f" {len(raw_vulns)} dep vulns,"
        f" {len(raw_threats)} threats."
    )

    try:
        from .prompts import (
            SYSTEM_THREAT_ASSESSMENT,
            ThreatAssessmentOutput,
        )

        context = json.dumps(stats, default=str)
        llm_result = cast(
            ThreatAssessmentOutput,
            await llm_structured(
                system_prompt=SYSTEM_THREAT_ASSESSMENT,
                user_prompt=f"Threat context:\n{context}",
                schema=ThreatAssessmentOutput,
            ),
        )
        logger.info("llm_enhanced", agent="serverless", node="risk")
        report_summary = llm_result.summary
    except Exception:
        logger.debug("llm_fallback", agent="serverless", node="risk")

    return {
        "stage": ServerlessStage.REPORT.value,
        "risk_score": risk_score,
        "stats": stats,
        "session_duration_ms": elapsed,
        "current_step": "assess_risk",
        "reasoning_chain": state.get("reasoning_chain", []) + [report_summary],
    }
