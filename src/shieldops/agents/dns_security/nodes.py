"""DNS Security Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import DNSQuery, DNSSeverity, DNSStage, DNSThreat
from .prompts import (
    SYSTEM_DGA,
    SYSTEM_REPORT,
    SYSTEM_TUNNELING,
    DGAAnalysisResult,
    DNSReportResult,
    TunnelingAnalysisResult,
)
from .tools import DNSSecurityToolkit

logger = structlog.get_logger()


async def collect_dns(
    state: dict[str, Any], toolkit: DNSSecurityToolkit
) -> dict[str, Any]:
    """Collect DNS query logs for analysis."""
    logger.info("dns_security.node.collect_dns")

    tenant_id = state.get("tenant_id", "")
    queries = await toolkit.collect_dns_queries(tenant_id)
    queries_data = [q.model_dump(mode="json") for q in queries]

    return {
        "stage": DNSStage.DETECT_TUNNELING.value,
        "dns_queries": queries_data,
        "total_queries": len(queries),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(queries)} DNS queries for analysis"],
    }


async def detect_tunneling(
    state: dict[str, Any], toolkit: DNSSecurityToolkit
) -> dict[str, Any]:
    """Detect DNS tunneling patterns."""
    logger.info("dns_security.node.detect_tunneling")

    raw_queries = state.get("dns_queries", [])
    queries = [DNSQuery(**q) for q in raw_queries]
    threats = await toolkit.detect_tunneling(queries)
    threats_data = [t.model_dump() for t in threats]

    reasoning_note = f"Detected {len(threats)} tunneling indicators"

    if threats:
        try:
            context = json.dumps(
                {
                    "tunneling_threats": [
                        {"domain": t.domain, "confidence": t.confidence}
                        for t in threats[:10]
                    ],
                },
                default=str,
            )
            result = cast(
                TunnelingAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_TUNNELING,
                    user_prompt=f"Tunneling analysis context:\n{context}",
                    schema=TunnelingAnalysisResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug("llm_fallback", agent="dns_security", node="tunneling")

    existing_threats = state.get("threats", [])
    return {
        "stage": DNSStage.DETECT_DGA.value,
        "threats": existing_threats + threats_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def detect_dga(
    state: dict[str, Any], toolkit: DNSSecurityToolkit
) -> dict[str, Any]:
    """Detect DGA-generated domains."""
    logger.info("dns_security.node.detect_dga")

    raw_queries = state.get("dns_queries", [])
    queries = [DNSQuery(**q) for q in raw_queries]
    threats = await toolkit.detect_dga(queries)
    threats_data = [t.model_dump() for t in threats]

    reasoning_note = f"Detected {len(threats)} DGA domains"

    if threats:
        try:
            context = json.dumps(
                {
                    "dga_domains": [
                        {"domain": t.domain, "confidence": t.confidence}
                        for t in threats[:10]
                    ],
                },
                default=str,
            )
            result = cast(
                DGAAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_DGA,
                    user_prompt=f"DGA analysis context:\n{context}",
                    schema=DGAAnalysisResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug("llm_fallback", agent="dns_security", node="dga")

    existing_threats = state.get("threats", [])
    return {
        "stage": DNSStage.DETECT_TYPOSQUATTING.value,
        "threats": existing_threats + threats_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def detect_typosquatting(
    state: dict[str, Any], toolkit: DNSSecurityToolkit
) -> dict[str, Any]:
    """Detect typosquatting domains."""
    logger.info("dns_security.node.detect_typosquatting")

    raw_queries = state.get("dns_queries", [])
    queries = [DNSQuery(**q) for q in raw_queries]
    threats = await toolkit.detect_typosquatting(queries)
    threats_data = [t.model_dump() for t in threats]

    existing_threats = state.get("threats", [])
    all_threats = existing_threats + threats_data
    return {
        "stage": DNSStage.RESPOND.value,
        "threats": all_threats,
        "total_threats": len(all_threats),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Detected {len(threats)} typosquatting domains"],
    }


async def respond_to_threats(
    state: dict[str, Any], toolkit: DNSSecurityToolkit
) -> dict[str, Any]:
    """Respond to high-severity DNS threats."""
    logger.info("dns_security.node.respond")

    raw_threats = state.get("threats", [])
    responses: list[dict[str, Any]] = []

    for raw in raw_threats:
        severity = raw.get("severity", "info")
        if severity in (DNSSeverity.CRITICAL.value, DNSSeverity.HIGH.value):
            threat = DNSThreat(**raw)
            response = await toolkit.respond_to_threat(threat)
            responses.append(response.model_dump())

    return {
        "stage": DNSStage.REPORT.value,
        "responses": responses,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Responded to {len(responses)} high-severity DNS threats"],
    }


async def generate_report(
    state: dict[str, Any], toolkit: DNSSecurityToolkit
) -> dict[str, Any]:
    """Generate DNS security report."""
    logger.info("dns_security.node.report")

    total_queries = state.get("total_queries", 0)
    total_threats = state.get("total_threats", 0)
    responses = state.get("responses", [])
    summary = (
        f"Analyzed {total_queries} DNS queries, found {total_threats} threats, "
        f"responded to {len(responses)}"
    )

    try:
        context = json.dumps(
            {
                "total_queries": total_queries,
                "total_threats": total_threats,
                "responses": len(responses),
                "threats": state.get("threats", [])[:10],
            },
            default=str,
        )
        result = cast(
            DNSReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"DNS security report context:\n{context}",
                schema=DNSReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("llm_fallback", agent="dns_security", node="report")

    return {
        "stage": DNSStage.REPORT.value,
        "summary": summary,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
