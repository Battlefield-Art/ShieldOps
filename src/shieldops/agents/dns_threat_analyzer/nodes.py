"""DNS Threat Analyzer Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    DNSPattern,
    DNSQuery,
    DNSThreat,
    DomainClassification,
    DTAStage,
    ReasoningStep,
)
from .tools import DNSThreatAnalyzerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Collect DNS Logs
# ------------------------------------------------------------------


async def collect_dns_logs(
    state: dict[str, Any],
    toolkit: DNSThreatAnalyzerToolkit,
) -> dict[str, Any]:
    """Collect DNS query logs from resolvers."""
    logger.info("dta.node.collect_dns_logs")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    queries = await toolkit.collect_dns_logs(tenant_id)
    data = [q.model_dump() for q in queries]

    note = f"Collected {len(queries)} DNS queries"

    return {
        "stage": DTAStage.ANALYZE_PATTERNS.value,
        "dns_queries": data,
        "total_queries_analyzed": len(queries),
        "current_step": "collect_dns_logs",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="collect_dns_logs",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Analyze Patterns
# ------------------------------------------------------------------


async def analyze_patterns(
    state: dict[str, Any],
    toolkit: DNSThreatAnalyzerToolkit,
) -> dict[str, Any]:
    """Analyze DNS traffic patterns."""
    logger.info("dta.node.analyze_patterns")
    state = _to_dict(state)

    queries = [DNSQuery(**q) for q in state.get("dns_queries", [])]
    patterns = await toolkit.analyze_patterns(queries)
    data = [p.model_dump() for p in patterns]

    note = f"Identified {len(patterns)} traffic patterns"

    try:
        from .prompts import SYSTEM_ANALYZE, PatternInsight

        ctx = json.dumps(
            {
                "patterns": [
                    {
                        "domain": p.domain,
                        "queries": p.query_count,
                        "entropy": p.entropy_score,
                        "avg_ttl": p.avg_ttl,
                        "payload": p.avg_payload_bytes,
                    }
                    for p in patterns[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PatternInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"DNS patterns:\n{ctx}",
                schema=PatternInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="dta",
            node="analyze_patterns",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="dta",
            node="analyze_patterns",
        )

    return {
        "stage": DTAStage.DETECT_THREATS.value,
        "patterns": data,
        "current_step": "analyze_patterns",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="analyze_patterns",
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
    toolkit: DNSThreatAnalyzerToolkit,
) -> dict[str, Any]:
    """Detect DNS-based threats from patterns."""
    logger.info("dta.node.detect_threats")
    state = _to_dict(state)

    patterns = [DNSPattern(**p) for p in state.get("patterns", [])]
    threats = await toolkit.detect_threats(patterns)
    data = [t.model_dump() for t in threats]

    note = f"Detected {len(threats)} threats across {len(patterns)} patterns"

    return {
        "stage": DTAStage.CLASSIFY_DOMAINS.value,
        "threats": data,
        "threats_detected": len(threats),
        "current_step": "detect_threats",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_threats",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Classify Domains
# ------------------------------------------------------------------


async def classify_domains(
    state: dict[str, Any],
    toolkit: DNSThreatAnalyzerToolkit,
) -> dict[str, Any]:
    """Classify domains found in threats."""
    logger.info("dta.node.classify_domains")
    state = _to_dict(state)

    threats = [DNSThreat(**t) for t in state.get("threats", [])]
    classifications = await toolkit.classify_domains(
        threats,
    )
    data = [c.model_dump() for c in classifications]

    malicious = sum(1 for c in classifications if c.risk.value == "malicious")
    note = f"Classified {len(classifications)} domains, {malicious} malicious"

    return {
        "stage": DTAStage.ENFORCE_BLOCKS.value,
        "classifications": data,
        "current_step": "classify_domains",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="classify_domains",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Enforce Blocks
# ------------------------------------------------------------------


async def enforce_blocks(
    state: dict[str, Any],
    toolkit: DNSThreatAnalyzerToolkit,
) -> dict[str, Any]:
    """Enforce DNS blocks for malicious domains."""
    logger.info("dta.node.enforce_blocks")
    state = _to_dict(state)

    classifications = [DomainClassification(**c) for c in state.get("classifications", [])]
    enforcements = await toolkit.enforce_blocks(
        classifications,
    )
    data = [e.model_dump() for e in enforcements]

    blocked = sum(1 for e in enforcements if e.status == "enforced")
    note = f"Enforced {blocked}/{len(enforcements)} domain blocks"

    return {
        "stage": DTAStage.REPORT.value,
        "enforcements": data,
        "current_step": "enforce_blocks",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="enforce_blocks",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: DNSThreatAnalyzerToolkit,
) -> dict[str, Any]:
    """Compile the final DNS threat analysis report."""
    logger.info("dta.node.report")
    state = _to_dict(state)

    total_queries = state.get(
        "total_queries_analyzed",
        0,
    )
    threat_count = state.get("threats_detected", 0)
    class_count = len(state.get("classifications", []))
    enforce_count = len(state.get("enforcements", []))

    lines = [
        "# DNS Threat Analysis Report",
        "",
        f"**Queries analyzed:** {total_queries}",
        f"**Threats detected:** {threat_count}",
        f"**Domains classified:** {class_count}",
        f"**Blocks enforced:** {enforce_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_queries": total_queries,
                "threats": threat_count,
                "classifications": class_count,
                "enforcements": enforce_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"DNS threat report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="dta",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="dta",
            node="report",
        )

    return {
        "stage": DTAStage.REPORT.value,
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
