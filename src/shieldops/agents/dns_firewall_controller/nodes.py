"""DNS Firewall Controller Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    DFCStage,
    DNSQueryRecord,
    DomainAnalysis,
    ReasoningStep,
    ReputationResult,
    TunnelingDetection,
)
from .tools import DNSFirewallControllerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Ingest Queries
# ------------------------------------------------------------------


async def ingest_queries(
    state: dict[str, Any],
    toolkit: DNSFirewallControllerToolkit,
) -> dict[str, Any]:
    """Ingest DNS queries from resolvers."""
    logger.info("dfc.node.ingest_queries")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    queries = await toolkit.ingest_queries(tenant_id)
    data = [q.model_dump() for q in queries]

    note = f"Ingested {len(queries)} DNS queries"

    return {
        "stage": DFCStage.ANALYZE_DOMAINS.value,
        "queries": data,
        "total_queries": len(queries),
        "current_step": "ingest_queries",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="ingest_queries",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Analyze Domains
# ------------------------------------------------------------------


async def analyze_domains(
    state: dict[str, Any],
    toolkit: DNSFirewallControllerToolkit,
) -> dict[str, Any]:
    """Analyze queried domains for categorization."""
    logger.info("dfc.node.analyze_domains")
    state = _to_dict(state)

    queries = [DNSQueryRecord(**q) for q in state.get("queries", [])]
    analyses = await toolkit.analyze_domains(queries)
    data = [a.model_dump() for a in analyses]

    note = f"Analyzed {len(analyses)} unique domains"

    try:
        from .prompts import SYSTEM_ANALYZE, DomainInsight

        ctx = json.dumps(
            {
                "domains": [
                    {
                        "domain": a.domain,
                        "category": a.category,
                        "entropy": a.entropy,
                        "dga_score": a.dga_score,
                    }
                    for a in analyses[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            DomainInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Domain analysis:\n{ctx}",
                schema=DomainInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="dfc",
            node="analyze_domains",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="dfc",
            node="analyze_domains",
        )

    return {
        "stage": DFCStage.CHECK_REPUTATION.value,
        "domain_analyses": data,
        "current_step": "analyze_domains",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="analyze_domains",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Check Reputation
# ------------------------------------------------------------------


async def check_reputation(
    state: dict[str, Any],
    toolkit: DNSFirewallControllerToolkit,
) -> dict[str, Any]:
    """Check domain reputation against threat feeds."""
    logger.info("dfc.node.check_reputation")
    state = _to_dict(state)

    analyses = [DomainAnalysis(**a) for a in state.get("domain_analyses", [])]
    results = await toolkit.check_reputation(analyses)
    data = [r.model_dump() for r in results]

    blocklisted = sum(1 for r in results if r.is_blocklisted)
    note = f"Checked {len(results)} domains, {blocklisted} blocklisted"

    return {
        "stage": DFCStage.DETECT_TUNNELING.value,
        "reputation_results": data,
        "current_step": "check_reputation",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="check_reputation",
                detail=note,
                confidence=0.87,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Detect Tunneling
# ------------------------------------------------------------------


async def detect_tunneling(
    state: dict[str, Any],
    toolkit: DNSFirewallControllerToolkit,
) -> dict[str, Any]:
    """Detect DNS tunneling patterns."""
    logger.info("dfc.node.detect_tunneling")
    state = _to_dict(state)

    queries = [DNSQueryRecord(**q) for q in state.get("queries", [])]
    detections = await toolkit.detect_tunneling(queries)
    data = [d.model_dump() for d in detections]

    tunnels = sum(1 for d in detections if d.is_tunneling)
    note = f"Scanned {len(detections)} flows, {tunnels} tunneling"

    return {
        "stage": DFCStage.ENFORCE_POLICY.value,
        "tunneling_detections": data,
        "tunneling_detected": tunnels,
        "current_step": "detect_tunneling",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_tunneling",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Enforce Policy
# ------------------------------------------------------------------


async def enforce_policy(
    state: dict[str, Any],
    toolkit: DNSFirewallControllerToolkit,
) -> dict[str, Any]:
    """Enforce DNS response policy zones."""
    logger.info("dfc.node.enforce_policy")
    state = _to_dict(state)

    rep_results = [ReputationResult(**r) for r in state.get("reputation_results", [])]
    tunnel_results = [TunnelingDetection(**t) for t in state.get("tunneling_detections", [])]
    enforcements = await toolkit.enforce_dns_policy(
        rep_results,
        tunnel_results,
    )
    data = [e.model_dump() for e in enforcements]

    blocked = sum(1 for e in enforcements if e.applied)
    note = f"Enforced {blocked} DNS policy rules"

    return {
        "stage": DFCStage.REPORT.value,
        "enforcements": data,
        "domains_blocked": blocked,
        "current_step": "enforce_policy",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="enforce_policy",
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
    toolkit: DNSFirewallControllerToolkit,
) -> dict[str, Any]:
    """Compile the final DNS firewall report."""
    logger.info("dfc.node.report")
    state = _to_dict(state)

    total_q = state.get("total_queries", 0)
    blocked = state.get("domains_blocked", 0)
    tunnels = state.get("tunneling_detected", 0)
    enforce_count = len(state.get("enforcements", []))

    lines = [
        "# DNS Firewall Controller Report",
        "",
        f"**Queries processed:** {total_q}",
        f"**Domains blocked:** {blocked}",
        f"**Tunneling detected:** {tunnels}",
        f"**Policy rules enforced:** {enforce_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_queries": total_q,
                "domains_blocked": blocked,
                "tunneling": tunnels,
                "enforcements": enforce_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"DNS firewall report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="dfc",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="dfc",
            node="report",
        )

    return {
        "stage": DFCStage.REPORT.value,
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
