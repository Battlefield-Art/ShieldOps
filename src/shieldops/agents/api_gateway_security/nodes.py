"""API Gateway Security Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AbuseDetection,
    APIEndpoint,
    AuthAnalysis,
    EndpointScan,
)
from .tools import APIGatewaySecurityToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict if it is a Pydantic model."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_apis(
    state: dict[str, Any],
    toolkit: APIGatewaySecurityToolkit,
) -> dict[str, Any]:
    """Discover API endpoints across configured gateways."""
    logger.info("ags.node.discover_apis")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    gateway_ids = state.get("gateway_ids", [])

    endpoints = await toolkit.discover_apis(
        tenant_id,
        gateway_ids or None,
    )
    endpoint_dicts = [ep.model_dump() for ep in endpoints]

    return {
        "discovered_endpoints": endpoint_dicts,
        "stage": "analyze_auth",
        "current_step": "discover_apis",
        "session_start": time.time(),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(endpoints)} API endpoints for tenant {tenant_id}"],
    }


async def analyze_auth(
    state: dict[str, Any],
    toolkit: APIGatewaySecurityToolkit,
) -> dict[str, Any]:
    """Analyze authentication across discovered endpoints."""
    logger.info("ags.node.analyze_auth")
    state = _to_dict(state)
    raw = state.get("discovered_endpoints", [])

    endpoints = [APIEndpoint(**ep) for ep in raw]
    analyses = await toolkit.analyze_auth(endpoints)
    analysis_dicts = [a.model_dump() for a in analyses]

    note = f"Analyzed auth for {len(analyses)} endpoints"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_AUTH_ANALYSIS,
            AuthAnalysisOutput,
        )

        ctx = json.dumps(
            {
                "endpoint_count": len(endpoints),
                "auth_analyses": analysis_dicts[:20],
                "risk_breakdown": _risk_breakdown(analyses),
            },
            default=str,
        )
        llm_result = cast(
            AuthAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_AUTH_ANALYSIS,
                user_prompt=f"Auth analysis results:\n{ctx}",
                schema=AuthAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="api_gateway_security",
            node="analyze_auth",
        )
        note = f"{llm_result.summary} — {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="api_gateway_security",
            node="analyze_auth",
        )

    return {
        "auth_analyses": analysis_dicts,
        "stage": "scan_endpoints",
        "current_step": "analyze_auth",
        "reasoning_chain": (state.get("reasoning_chain", []) + [note]),
    }


async def scan_endpoints(
    state: dict[str, Any],
    toolkit: APIGatewaySecurityToolkit,
) -> dict[str, Any]:
    """Scan endpoints for input validation and config gaps."""
    logger.info("ags.node.scan_endpoints")
    state = _to_dict(state)
    raw = state.get("discovered_endpoints", [])

    endpoints = [APIEndpoint(**ep) for ep in raw]
    scans = await toolkit.scan_endpoints(endpoints)
    scan_dicts = [s.model_dump() for s in scans]

    note = f"Scanned {len(scans)} endpoints for validation and config gaps"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_ENDPOINT_SCAN,
            EndpointScanOutput,
        )

        ctx = json.dumps(
            {
                "endpoint_count": len(endpoints),
                "scan_count": len(scans),
                "scans_summary": scan_dicts[:20],
            },
            default=str,
        )
        llm_result = cast(
            EndpointScanOutput,
            await llm_structured(
                system_prompt=SYSTEM_ENDPOINT_SCAN,
                user_prompt=f"Endpoint scan results:\n{ctx}",
                schema=EndpointScanOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="api_gateway_security",
            node="scan_endpoints",
        )
        note = f"{llm_result.summary} — {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="api_gateway_security",
            node="scan_endpoints",
        )

    return {
        "endpoint_scans": scan_dicts,
        "stage": "detect_abuse",
        "current_step": "scan_endpoints",
        "reasoning_chain": (state.get("reasoning_chain", []) + [note]),
    }


async def detect_abuse(
    state: dict[str, Any],
    toolkit: APIGatewaySecurityToolkit,
) -> dict[str, Any]:
    """Detect API abuse patterns from traffic analysis."""
    logger.info("ags.node.detect_abuse")
    state = _to_dict(state)
    raw = state.get("discovered_endpoints", [])

    endpoints = [APIEndpoint(**ep) for ep in raw]
    detections = await toolkit.detect_abuse(endpoints)
    detection_dicts = [d.model_dump() for d in detections]

    note = f"Detected {len(detections)} abuse incidents"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_ABUSE_DETECTION,
            AbuseAnalysisOutput,
        )

        ctx = json.dumps(
            {
                "endpoint_count": len(endpoints),
                "detection_count": len(detections),
                "detections_summary": detection_dicts[:20],
            },
            default=str,
        )
        llm_result = cast(
            AbuseAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_ABUSE_DETECTION,
                user_prompt=f"Abuse detection data:\n{ctx}",
                schema=AbuseAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="api_gateway_security",
            node="detect_abuse",
        )
        note = f"{llm_result.summary} — {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="api_gateway_security",
            node="detect_abuse",
        )

    return {
        "abuse_detections": detection_dicts,
        "stage": "enforce_policies",
        "current_step": "detect_abuse",
        "reasoning_chain": (state.get("reasoning_chain", []) + [note]),
    }


async def enforce_policies(
    state: dict[str, Any],
    toolkit: APIGatewaySecurityToolkit,
) -> dict[str, Any]:
    """Enforce security policies based on findings."""
    logger.info("ags.node.enforce_policies")
    state = _to_dict(state)
    raw_auth = state.get("auth_analyses", [])
    raw_scans = state.get("endpoint_scans", [])
    raw_abuse = state.get("abuse_detections", [])

    auths = [AuthAnalysis(**a) for a in raw_auth]
    scans = [EndpointScan(**s) for s in raw_scans]
    abuses = [AbuseDetection(**d) for d in raw_abuse]

    enforcements = await toolkit.enforce_policies(
        auths,
        scans,
        abuses,
    )
    enforcement_dicts = [e.model_dump() for e in enforcements]

    note = (
        f"Enforced {len(enforcements)} policies "
        f"({len(auths)} auth, {len(scans)} scan, "
        f"{len(abuses)} abuse findings)"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_POLICY_ENFORCEMENT,
            PolicyRecommendationOutput,
        )

        ctx = json.dumps(
            {
                "auth_issues": len(auths),
                "scan_issues": len(scans),
                "abuse_incidents": len(abuses),
                "enforcements": enforcement_dicts[:20],
            },
            default=str,
        )
        llm_result = cast(
            PolicyRecommendationOutput,
            await llm_structured(
                system_prompt=SYSTEM_POLICY_ENFORCEMENT,
                user_prompt=f"Policy enforcement context:\n{ctx}",
                schema=PolicyRecommendationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="api_gateway_security",
            node="enforce_policies",
        )
        note = f"{llm_result.summary} — {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="api_gateway_security",
            node="enforce_policies",
        )

    return {
        "policy_enforcements": enforcement_dicts,
        "stage": "report",
        "current_step": "enforce_policies",
        "reasoning_chain": (state.get("reasoning_chain", []) + [note]),
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: APIGatewaySecurityToolkit,
) -> dict[str, Any]:
    """Generate the final gateway security assessment report."""
    logger.info("ags.node.generate_report")
    state = _to_dict(state)
    endpoints = state.get("discovered_endpoints", [])
    auths = state.get("auth_analyses", [])
    scans = state.get("endpoint_scans", [])
    abuses = state.get("abuse_detections", [])
    enforcements = state.get("policy_enforcements", [])
    session_start = state.get("session_start", time.time())

    duration_ms = (time.time() - session_start) * 1000

    stats: dict[str, Any] = {
        "endpoints_scanned": len(endpoints),
        "auth_issues": _count_high_risk(auths),
        "scan_issues": _count_high_risk(scans),
        "abuse_incidents": len(abuses),
        "policies_enforced": len(enforcements),
        "risk_breakdown": _risk_breakdown_dicts(auths),
        "duration_ms": round(duration_ms, 1),
    }

    note = (
        f"Report: {len(endpoints)} endpoints, "
        f"{len(auths)} auth analyses, "
        f"{len(abuses)} abuse incidents, "
        f"{len(enforcements)} enforcements"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_GATEWAY_REPORT,
            GatewaySecurityReportOutput,
        )

        ctx = json.dumps(
            {
                "stats": stats,
                "top_auth_issues": auths[:10],
                "top_scan_issues": scans[:10],
                "top_abuse": abuses[:10],
                "enforcements": enforcements[:10],
            },
            default=str,
        )
        llm_result = cast(
            GatewaySecurityReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_GATEWAY_REPORT,
                user_prompt=f"Gateway security assessment:\n{ctx}",
                schema=GatewaySecurityReportOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="api_gateway_security",
            node="generate_report",
        )
        stats["executive_summary"] = llm_result.executive_summary
        stats["risk_score"] = llm_result.risk_score
        stats["top_risks"] = llm_result.top_risks
        stats["recommendations"] = llm_result.recommendations
        stats["compliance_gaps"] = llm_result.compliance_gaps
        note = f"{llm_result.executive_summary[:100]} — {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="api_gateway_security",
            node="generate_report",
        )

    return {
        "stats": stats,
        "stage": "report",
        "current_step": "generate_report",
        "session_duration_ms": round(duration_ms, 1),
        "reasoning_chain": (state.get("reasoning_chain", []) + [note]),
    }


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------


def _risk_breakdown(
    analyses: list[AuthAnalysis],
) -> dict[str, int]:
    """Count auth analyses by risk level."""
    breakdown: dict[str, int] = {}
    for a in analyses:
        key = a.risk.value if hasattr(a.risk, "value") else str(a.risk)
        breakdown[key] = breakdown.get(key, 0) + 1
    return breakdown


def _risk_breakdown_dicts(
    items: list[dict[str, Any]],
) -> dict[str, int]:
    """Count items by risk from raw dicts."""
    breakdown: dict[str, int] = {}
    for item in items:
        key = str(item.get("risk", "unknown"))
        breakdown[key] = breakdown.get(key, 0) + 1
    return breakdown


def _count_high_risk(
    items: list[dict[str, Any]],
) -> int:
    """Count items with critical or high risk."""
    return sum(1 for item in items if str(item.get("risk", "")) in ("critical", "high"))
