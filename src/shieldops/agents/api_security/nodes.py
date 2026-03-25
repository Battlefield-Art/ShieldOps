"""API Security Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import APIAbuseIncident, APIEndpoint, APIVulnerability
from .tools import APISecurityToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_endpoints(
    state: dict[str, Any],
    toolkit: APISecurityToolkit,
) -> dict[str, Any]:
    """Discover API endpoints within the scan scope."""
    logger.info("api_security.node.discover_endpoints")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    scope = state.get("scan_scope", [])

    endpoints = await toolkit.discover_endpoints(tenant_id, scope or None)
    endpoint_dicts = [ep.model_dump() for ep in endpoints]

    return {
        "discovered_endpoints": endpoint_dicts,
        "stage": "analyze_traffic",
        "current_step": "discover_endpoints",
        "session_start": time.time(),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(endpoints)} API endpoints for tenant {tenant_id}"],
    }


async def analyze_traffic(
    state: dict[str, Any],
    toolkit: APISecurityToolkit,
) -> dict[str, Any]:
    """Enrich endpoints with traffic analytics."""
    logger.info("api_security.node.analyze_traffic")
    state = _to_dict(state)
    raw_endpoints = state.get("discovered_endpoints", [])

    endpoints = [APIEndpoint(**ep) for ep in raw_endpoints]
    enriched = await toolkit.analyze_traffic(endpoints)
    enriched_dicts = [ep.model_dump() for ep in enriched]

    return {
        "discovered_endpoints": enriched_dicts,
        "stage": "detect_vulnerabilities",
        "current_step": "analyze_traffic",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Analyzed traffic for {len(enriched)} endpoints"],
    }


async def detect_vulnerabilities(
    state: dict[str, Any],
    toolkit: APISecurityToolkit,
) -> dict[str, Any]:
    """Scan endpoints for OWASP API Top 10 vulnerabilities with LLM analysis."""
    logger.info("api_security.node.detect_vulnerabilities")
    state = _to_dict(state)
    raw_endpoints = state.get("discovered_endpoints", [])

    endpoints = [APIEndpoint(**ep) for ep in raw_endpoints]
    vulns = await toolkit.detect_vulnerabilities(endpoints)
    vuln_dicts = [v.model_dump() for v in vulns]

    reasoning_note = f"Detected {len(vulns)} vulnerabilities across {len(endpoints)} endpoints"

    # LLM enhancement: deeper vulnerability analysis
    try:
        from .prompts import SYSTEM_VULN_ANALYSIS, VulnAnalysisOutput

        analysis_context = json.dumps(
            {
                "endpoint_count": len(endpoints),
                "vulnerability_count": len(vulns),
                "vulnerabilities_summary": vuln_dicts[:20],
                "severity_breakdown": _severity_breakdown(vulns),
            },
            default=str,
        )
        llm_result = cast(
            VulnAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_VULN_ANALYSIS,
                user_prompt=f"API vulnerability scan results:\n{analysis_context}",
                schema=VulnAnalysisOutput,
            ),
        )
        logger.info("llm_enhanced", agent="api_security", node="detect_vulns")
        reasoning_note = f"{llm_result.summary} — {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="api_security", node="detect_vulns")

    return {
        "vulnerabilities": vuln_dicts,
        "stage": "detect_abuse",
        "current_step": "detect_vulnerabilities",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def detect_abuse(
    state: dict[str, Any],
    toolkit: APISecurityToolkit,
) -> dict[str, Any]:
    """Detect API abuse patterns with LLM-assisted analysis."""
    logger.info("api_security.node.detect_abuse")
    state = _to_dict(state)
    raw_endpoints = state.get("discovered_endpoints", [])

    endpoints = [APIEndpoint(**ep) for ep in raw_endpoints]
    incidents = await toolkit.detect_abuse(endpoints)
    incident_dicts = [inc.model_dump() for inc in incidents]

    reasoning_note = f"Detected {len(incidents)} abuse incidents"

    # LLM enhancement: abuse pattern correlation
    try:
        from .prompts import SYSTEM_ABUSE_DETECTION, AbuseDetectionOutput

        analysis_context = json.dumps(
            {
                "endpoint_count": len(endpoints),
                "incident_count": len(incidents),
                "incidents_summary": incident_dicts[:20],
            },
            default=str,
        )
        llm_result = cast(
            AbuseDetectionOutput,
            await llm_structured(
                system_prompt=SYSTEM_ABUSE_DETECTION,
                user_prompt=f"API abuse detection data:\n{analysis_context}",
                schema=AbuseDetectionOutput,
            ),
        )
        logger.info("llm_enhanced", agent="api_security", node="detect_abuse")
        reasoning_note = f"{llm_result.summary} — {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="api_security", node="detect_abuse")

    return {
        "abuse_incidents": incident_dicts,
        "stage": "enforce_policies",
        "current_step": "detect_abuse",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def enforce_policies(
    state: dict[str, Any],
    toolkit: APISecurityToolkit,
) -> dict[str, Any]:
    """Enforce security policies based on detected issues."""
    logger.info("api_security.node.enforce_policies")
    state = _to_dict(state)
    raw_vulns = state.get("vulnerabilities", [])
    raw_abuse = state.get("abuse_incidents", [])

    vulns = [APIVulnerability(**v) for v in raw_vulns]
    incidents = [APIAbuseIncident(**a) for a in raw_abuse]

    enforcements = await toolkit.enforce_policies(vulns, incidents)
    enforcement_dicts = [e.model_dump() for e in enforcements]

    reasoning_note = (
        f"Enforced {len(enforcements)} policies "
        f"({len(vulns)} vulns, {len(incidents)} abuse incidents)"
    )

    # LLM enhancement: policy recommendations
    try:
        from .prompts import SYSTEM_POLICY_ENFORCEMENT, PolicyOutput

        analysis_context = json.dumps(
            {
                "vulnerability_count": len(vulns),
                "abuse_count": len(incidents),
                "enforcements": enforcement_dicts[:20],
            },
            default=str,
        )
        llm_result = cast(
            PolicyOutput,
            await llm_structured(
                system_prompt=SYSTEM_POLICY_ENFORCEMENT,
                user_prompt=f"Policy enforcement context:\n{analysis_context}",
                schema=PolicyOutput,
            ),
        )
        logger.info("llm_enhanced", agent="api_security", node="enforce_policies")
        reasoning_note = f"{llm_result.summary} — {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="api_security", node="enforce_policies")

    return {
        "policy_enforcements": enforcement_dicts,
        "stage": "report",
        "current_step": "enforce_policies",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: APISecurityToolkit,
) -> dict[str, Any]:
    """Generate the final API security assessment report."""
    logger.info("api_security.node.generate_report")
    state = _to_dict(state)
    endpoints = state.get("discovered_endpoints", [])
    vulns = state.get("vulnerabilities", [])
    abuse = state.get("abuse_incidents", [])
    enforcements = state.get("policy_enforcements", [])
    session_start = state.get("session_start", time.time())

    duration_ms = (time.time() - session_start) * 1000

    stats: dict[str, Any] = {
        "endpoints_scanned": len(endpoints),
        "vulnerabilities_found": len(vulns),
        "abuse_incidents_found": len(abuse),
        "policies_enforced": len(enforcements),
        "severity_breakdown": _severity_breakdown_dicts(vulns),
        "duration_ms": round(duration_ms, 1),
    }

    reasoning_note = (
        f"Report: {len(endpoints)} endpoints, {len(vulns)} vulns, "
        f"{len(abuse)} abuse incidents, {len(enforcements)} enforcements"
    )

    # LLM enhancement: executive summary
    try:
        from .prompts import SYSTEM_SECURITY_SUMMARY, SecuritySummaryOutput

        report_context = json.dumps(
            {
                "stats": stats,
                "top_vulns": vulns[:10],
                "top_abuse": abuse[:10],
                "enforcements": enforcements[:10],
            },
            default=str,
        )
        llm_result = cast(
            SecuritySummaryOutput,
            await llm_structured(
                system_prompt=SYSTEM_SECURITY_SUMMARY,
                user_prompt=f"API security assessment data:\n{report_context}",
                schema=SecuritySummaryOutput,
            ),
        )
        logger.info("llm_enhanced", agent="api_security", node="generate_report")
        stats["executive_summary"] = llm_result.executive_summary
        stats["risk_score"] = llm_result.risk_score
        stats["top_risks"] = llm_result.top_risks
        stats["recommendations"] = llm_result.recommendations
        stats["compliance_gaps"] = llm_result.compliance_gaps
        reasoning_note = f"{llm_result.executive_summary[:100]} — {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="api_security", node="generate_report")

    return {
        "stats": stats,
        "stage": "report",
        "current_step": "generate_report",
        "session_duration_ms": round(duration_ms, 1),
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _severity_breakdown(
    vulns: list[APIVulnerability],
) -> dict[str, int]:
    """Count vulnerabilities by severity."""
    breakdown: dict[str, int] = {}
    for v in vulns:
        key = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
        breakdown[key] = breakdown.get(key, 0) + 1
    return breakdown


def _severity_breakdown_dicts(
    vuln_dicts: list[dict[str, Any]],
) -> dict[str, int]:
    """Count vulnerabilities by severity from raw dicts."""
    breakdown: dict[str, int] = {}
    for v in vuln_dicts:
        key = str(v.get("severity", "unknown"))
        breakdown[key] = breakdown.get(key, 0) + 1
    return breakdown
