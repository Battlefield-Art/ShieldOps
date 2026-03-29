"""DAST Runner Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import CrawlResult, DASTStage, EndpointFinding, ScanScope
from .tools import DASTRunnerToolkit

logger = structlog.get_logger()

_toolkit: DASTRunnerToolkit | None = None


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_endpoints(
    state: dict[str, Any],
    toolkit: DASTRunnerToolkit,
) -> dict[str, Any]:
    """Discover application endpoints."""
    logger.info("dast_runner.node.discover_endpoints")
    state = _to_dict(state)
    target_url = state.get("target_url", "")
    scope = ScanScope(state.get("scan_scope", "full"))
    session_start = time.time()

    endpoints = await toolkit.discover_endpoints(
        target_url,
        scope,
    )
    ep_dicts = [e.model_dump() for e in endpoints]

    return {
        "crawl_results": ep_dicts,
        "total_endpoints": len(endpoints),
        "stage": DASTStage.DISCOVER_ENDPOINTS.value,
        "session_start": session_start,
        "current_step": "discover_endpoints",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(endpoints)} endpoints"],
    }


async def crawl_application(
    state: dict[str, Any],
    toolkit: DASTRunnerToolkit,
) -> dict[str, Any]:
    """Deep-crawl application."""
    logger.info("dast_runner.node.crawl")
    state = _to_dict(state)
    target_url = state.get("target_url", "")
    raw = state.get("crawl_results", [])
    endpoints = [CrawlResult(**e) if isinstance(e, dict) else e for e in raw]

    crawled = await toolkit.crawl_application(
        target_url,
        endpoints,
    )
    crawl_dicts = [c.model_dump() for c in crawled]
    reasoning = f"Crawled {len(crawled)} endpoints"

    try:
        from .prompts import (
            SYSTEM_CRAWL_ANALYSIS,
            CrawlAnalysisOutput,
        )

        context = json.dumps(
            {"endpoints": crawl_dicts[:15]},
            default=str,
        )
        llm_result = cast(
            CrawlAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_CRAWL_ANALYSIS,
                user_prompt=f"Crawl results:\n{context}",
                schema=CrawlAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="dast_runner",
            node="crawl",
        )
        reasoning = llm_result.summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="dast_runner",
            node="crawl",
        )

    return {
        "crawl_results": crawl_dicts,
        "stage": DASTStage.CRAWL_APPLICATION.value,
        "current_step": "crawl_application",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def test_authentication(
    state: dict[str, Any],
    toolkit: DASTRunnerToolkit,
) -> dict[str, Any]:
    """Test endpoints for auth vulnerabilities."""
    logger.info("dast_runner.node.test_auth")
    state = _to_dict(state)
    raw = state.get("crawl_results", [])
    endpoints = [CrawlResult(**e) if isinstance(e, dict) else e for e in raw]

    findings = await toolkit.test_authentication(endpoints)
    finding_dicts = [f.model_dump() for f in findings]

    return {
        "auth_findings": finding_dicts,
        "stage": DASTStage.TEST_AUTHENTICATION.value,
        "current_step": "test_authentication",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Auth testing: {len(findings)} findings"],
    }


async def fuzz_parameters(
    state: dict[str, Any],
    toolkit: DASTRunnerToolkit,
) -> dict[str, Any]:
    """Fuzz endpoint parameters."""
    logger.info("dast_runner.node.fuzz")
    state = _to_dict(state)
    raw = state.get("crawl_results", [])
    endpoints = [CrawlResult(**e) if isinstance(e, dict) else e for e in raw]

    findings = await toolkit.fuzz_parameters(endpoints)
    finding_dicts = [f.model_dump() for f in findings]

    return {
        "fuzz_findings": finding_dicts,
        "stage": DASTStage.FUZZ_PARAMETERS.value,
        "current_step": "fuzz_parameters",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Fuzzing: {len(findings)} findings"],
    }


async def analyze_responses(
    state: dict[str, Any],
    toolkit: DASTRunnerToolkit,
) -> dict[str, Any]:
    """Analyze and merge all findings."""
    logger.info("dast_runner.node.analyze_responses")
    state = _to_dict(state)
    raw_auth = state.get("auth_findings", [])
    raw_fuzz = state.get("fuzz_findings", [])
    auth = [EndpointFinding(**f) if isinstance(f, dict) else f for f in raw_auth]
    fuzz = [EndpointFinding(**f) if isinstance(f, dict) else f for f in raw_fuzz]

    all_findings = await toolkit.analyze_responses(auth, fuzz)
    all_dicts = [f.model_dump() for f in all_findings]
    total = len(all_findings)
    critical = sum(1 for f in all_findings if f.severity == "critical")
    reasoning = f"Total: {total} findings, {critical} critical"

    try:
        from .prompts import (
            SYSTEM_FUZZ_ANALYSIS,
            FuzzAnalysisOutput,
        )

        context = json.dumps(
            {"findings": all_dicts[:20]},
            default=str,
        )
        llm_result = cast(
            FuzzAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_FUZZ_ANALYSIS,
                user_prompt=f"DAST findings:\n{context}",
                schema=FuzzAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="dast_runner",
            node="analyze_responses",
        )
        reasoning = f"{llm_result.summary} {llm_result.risk_narrative[:80]}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="dast_runner",
            node="analyze_responses",
        )

    return {
        "all_findings": all_dicts,
        "total_findings": total,
        "critical_count": critical,
        "stage": DASTStage.ANALYZE_RESPONSES.value,
        "current_step": "analyze_responses",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: DASTRunnerToolkit,
) -> dict[str, Any]:
    """Generate final DAST report."""
    logger.info("dast_runner.node.report")
    state = _to_dict(state)
    all_findings = state.get("all_findings", [])
    session_start = state.get("session_start", time.time())

    sev_dist: dict[str, int] = {}
    for f in all_findings:
        sev = f.get("severity", "medium")
        sev_dist[sev] = sev_dist.get(sev, 0) + 1

    duration_ms = (time.time() - session_start) * 1000
    stats = {
        "total_findings": len(all_findings),
        "critical_count": sev_dist.get("critical", 0),
        "severity_distribution": sev_dist,
        "endpoints_tested": state.get(
            "total_endpoints",
            0,
        ),
        "scan_duration_ms": round(duration_ms, 2),
    }

    return {
        "stats": stats,
        "total_findings": len(all_findings),
        "critical_count": sev_dist.get("critical", 0),
        "stage": DASTStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Report: {len(all_findings)} findings, {sev_dist.get('critical', 0)} critical"],
    }
