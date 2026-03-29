"""Email Gateway Analyzer Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import EmailHeader, GatewayStage, SPFResult
from .tools import EmailGatewayAnalyzerToolkit

logger = structlog.get_logger()

_toolkit: EmailGatewayAnalyzerToolkit | None = None


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def collect_records(
    state: dict[str, Any],
    toolkit: EmailGatewayAnalyzerToolkit,
) -> dict[str, Any]:
    """Collect DNS authentication records for domains."""
    logger.info("email_gateway.node.collect_records")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    domains = state.get("domains", [])

    if not domains:
        domains = ["company.com", "mail.company.com"]

    records = await toolkit.collect_dns_records(
        tenant_id=tenant_id,
        domains=domains,
    )
    return {
        "dns_records": [r if isinstance(r, dict) else r for r in records],
        "domains": domains,
        "stage": GatewayStage.COLLECT_RECORDS.value,
        "session_start": time.time(),
        "current_step": "collect_records",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected DNS records for {len(domains)} domains"],
    }


async def validate_auth(
    state: dict[str, Any],
    toolkit: EmailGatewayAnalyzerToolkit,
) -> dict[str, Any]:
    """Validate authentication protocols."""
    logger.info("email_gateway.node.validate_auth")
    state = _to_dict(state)
    dns_records = state.get("dns_records", [])

    results, pass_rate = await toolkit.validate_auth_protocols(dns_records)
    result_dicts = [r.model_dump() for r in results]

    reasoning_note = f"Validated {len(results)} auth records ({pass_rate:.0%} pass rate)"

    try:
        from .prompts import (
            SYSTEM_AUTH_VALIDATION,
            AuthValidationOutput,
        )

        context = json.dumps(
            {
                "results": result_dicts[:20],
                "pass_rate": pass_rate,
            },
            default=str,
        )
        llm_out = cast(
            AuthValidationOutput,
            await llm_structured(
                system_prompt=SYSTEM_AUTH_VALIDATION,
                user_prompt=f"Auth records:\n{context}",
                schema=AuthValidationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="email_gateway_analyzer",
            node="validate_auth",
        )
        reasoning_note = f"{llm_out.summary} [risk={llm_out.risk_level}]"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="email_gateway_analyzer",
            node="validate_auth",
        )

    return {
        "auth_results": result_dicts,
        "auth_pass_rate": pass_rate,
        "stage": GatewayStage.VALIDATE_AUTH.value,
        "current_step": "validate_auth",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def analyze_headers(
    state: dict[str, Any],
    toolkit: EmailGatewayAnalyzerToolkit,
) -> dict[str, Any]:
    """Analyze email headers for anomalies."""
    logger.info("email_gateway.node.analyze_headers")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")

    headers, suspicious_count = await toolkit.analyze_headers(
        tenant_id=tenant_id,
    )
    header_dicts = [h.model_dump() for h in headers]

    return {
        "headers_analyzed": header_dicts,
        "suspicious_headers_count": suspicious_count,
        "stage": GatewayStage.ANALYZE_HEADERS.value,
        "current_step": "analyze_headers",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Analyzed {len(headers)} headers, {suspicious_count} suspicious"],
    }


async def check_reputation(
    state: dict[str, Any],
    toolkit: EmailGatewayAnalyzerToolkit,
) -> dict[str, Any]:
    """Check sender domain reputation."""
    logger.info("email_gateway.node.check_reputation")
    state = _to_dict(state)
    domains = state.get("domains", [])

    scores, avg = await toolkit.check_reputation(domains)

    return {
        "reputation_scores": scores,
        "avg_reputation": avg,
        "stage": GatewayStage.CHECK_REPUTATION.value,
        "current_step": "check_reputation",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Reputation check: {len(domains)} domains, avg score {avg}"],
    }


async def detect_spoofing(
    state: dict[str, Any],
    toolkit: EmailGatewayAnalyzerToolkit,
) -> dict[str, Any]:
    """Detect spoofing attempts."""
    logger.info("email_gateway.node.detect_spoofing")
    state = _to_dict(state)
    raw_headers = state.get("headers_analyzed", [])
    raw_auth = state.get("auth_results", [])

    headers = [EmailHeader(**h) if isinstance(h, dict) else h for h in raw_headers]
    auth_results = [SPFResult(**a) if isinstance(a, dict) else a for a in raw_auth]

    spoofing = await toolkit.detect_spoofing(
        headers,
        auth_results,
    )

    reasoning_note = f"Detected {len(spoofing)} spoofing attempts"

    try:
        from .prompts import (
            SYSTEM_SPOOFING_DETECTION,
            SpoofingDetectionOutput,
        )

        context = json.dumps(
            {"spoofing_attempts": spoofing[:20]},
            default=str,
        )
        llm_out = cast(
            SpoofingDetectionOutput,
            await llm_structured(
                system_prompt=SYSTEM_SPOOFING_DETECTION,
                user_prompt=(f"Spoofing analysis:\n{context}"),
                schema=SpoofingDetectionOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="email_gateway_analyzer",
            node="detect_spoofing",
        )
        reasoning_note = f"{llm_out.summary} [threat={llm_out.threat_level}]"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="email_gateway_analyzer",
            node="detect_spoofing",
        )

    return {
        "spoofing_attempts": spoofing,
        "spoofing_detected": len(spoofing),
        "stage": GatewayStage.DETECT_SPOOFING.value,
        "current_step": "detect_spoofing",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: EmailGatewayAnalyzerToolkit,
) -> dict[str, Any]:
    """Generate final gateway analysis report."""
    logger.info("email_gateway.node.generate_report")
    state = _to_dict(state)

    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    stats = {
        "domains_analyzed": len(state.get("domains", [])),
        "auth_pass_rate": state.get("auth_pass_rate", 0.0),
        "suspicious_headers": state.get("suspicious_headers_count", 0),
        "avg_reputation": state.get("avg_reputation", 0.0),
        "spoofing_detected": state.get("spoofing_detected", 0),
        "analysis_duration_ms": round(duration_ms, 2),
    }

    return {
        "stats": stats,
        "stage": GatewayStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report: {stats['domains_analyzed']} domains, "
            f"{stats['spoofing_detected']} spoofing attempts"
        ],
    }
