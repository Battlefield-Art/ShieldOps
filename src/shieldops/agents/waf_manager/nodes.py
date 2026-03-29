"""WAF Manager — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import AttackEvent, WAFRule
from .tools import WAFManagerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def ingest_logs(
    state: dict[str, Any],
    toolkit: WAFManagerToolkit,
) -> dict[str, Any]:
    """Ingest WAF logs and load active rules."""
    logger.info("waf_manager.node.ingest_logs")
    state = _to_dict(state)
    window = state.get("time_window_hours", 24)
    session_start = time.time()

    events = await toolkit.ingest_waf_logs(
        time_window_hours=window,
    )
    rules = await toolkit.load_active_rules()

    return {
        "attack_events": [e.model_dump() for e in events],
        "active_rules": [r.model_dump() for r in rules],
        "session_start": session_start,
        "current_step": "ingest_logs",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Ingested {len(events)} events and {len(rules)} rules"],
    }


async def analyze_attacks(
    state: dict[str, Any],
    toolkit: WAFManagerToolkit,
) -> dict[str, Any]:
    """Analyze attack patterns from WAF events."""
    logger.info("waf_manager.node.analyze_attacks")
    state = _to_dict(state)
    raw_events = state.get("attack_events", [])
    events = [AttackEvent(**e) for e in raw_events]

    summary = await toolkit.analyze_attack_patterns(events)
    top_sources = summary.get("top_sources", [])

    reasoning = (
        f"Analyzed {summary.get('total_events', 0)} events: "
        f"{summary.get('unique_sources', 0)} unique sources"
    )

    # LLM enhancement
    try:
        from .prompts import SYSTEM_ATTACK_ANALYSIS, AttackAnalysisResult

        ctx = json.dumps(
            {
                "total_events": summary.get("total_events", 0),
                "categories": summary.get(
                    "category_distribution",
                    {},
                ),
                "severity": summary.get(
                    "severity_distribution",
                    {},
                ),
                "top_sources": top_sources[:5],
            },
            default=str,
        )
        llm_result = cast(
            AttackAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_ATTACK_ANALYSIS,
                user_prompt=f"WAF attack data:\n{ctx}",
                schema=AttackAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="waf_manager",
            node="analyze_attacks",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="waf_manager",
            node="analyze_attacks",
        )

    return {
        "attack_summary": summary,
        "top_attack_sources": top_sources,
        "current_step": "analyze_attacks",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def evaluate_coverage(
    state: dict[str, Any],
    toolkit: WAFManagerToolkit,
) -> dict[str, Any]:
    """Evaluate OWASP Top 10 coverage."""
    logger.info("waf_manager.node.evaluate_coverage")
    state = _to_dict(state)
    raw_rules = state.get("active_rules", [])
    rules = [WAFRule(**r) for r in raw_rules]

    gaps = await toolkit.evaluate_owasp_coverage(rules)
    covered = sum(1 for g in gaps if g.covered)
    pct = (covered / len(gaps) * 100) if gaps else 0.0

    return {
        "coverage_gaps": [g.model_dump() for g in gaps],
        "owasp_coverage_pct": round(pct, 1),
        "current_step": "evaluate_coverage",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"OWASP coverage: {pct:.1f}% ({covered}/{len(gaps)})"],
    }


async def tune_rules(
    state: dict[str, Any],
    toolkit: WAFManagerToolkit,
) -> dict[str, Any]:
    """Propose rule tuning based on analysis."""
    logger.info("waf_manager.node.tune_rules")
    state = _to_dict(state)
    raw_rules = state.get("active_rules", [])
    rules = [WAFRule(**r) for r in raw_rules]
    summary = state.get("attack_summary", {})
    raw_fps = state.get("false_positives", [])
    fp_events = [AttackEvent(**e) for e in raw_fps]

    proposals = await toolkit.propose_rule_tuning(
        rules,
        summary,
        fp_events,
    )

    reasoning = f"Proposed {len(proposals)} rule changes"

    # LLM enhancement
    try:
        from .prompts import SYSTEM_RULE_TUNING, RuleTuningResult

        ctx = json.dumps(
            {
                "rule_count": len(rules),
                "attack_summary": summary,
                "proposals": proposals[:10],
                "fp_count": len(fp_events),
            },
            default=str,
        )
        llm_result = cast(
            RuleTuningResult,
            await llm_structured(
                system_prompt=SYSTEM_RULE_TUNING,
                user_prompt=f"Rule tuning context:\n{ctx}",
                schema=RuleTuningResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="waf_manager",
            node="tune_rules",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="waf_manager",
            node="tune_rules",
        )

    return {
        "proposed_rules": proposals,
        "current_step": "tune_rules",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def reduce_false_positives(
    state: dict[str, Any],
    toolkit: WAFManagerToolkit,
) -> dict[str, Any]:
    """Detect and reduce false positives."""
    logger.info("waf_manager.node.reduce_false_positives")
    state = _to_dict(state)
    raw_events = state.get("attack_events", [])
    events = [AttackEvent(**e) for e in raw_events]
    raw_rules = state.get("active_rules", [])
    rules = [WAFRule(**r) for r in raw_rules]

    fps = await toolkit.detect_false_positives(events, rules)

    reasoning = f"Identified {len(fps)} false positives"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_FALSE_POSITIVE_ANALYSIS,
            FalsePositiveResult,
        )

        ctx = json.dumps(
            {
                "total_events": len(events),
                "fp_count": len(fps),
                "fp_samples": [f.model_dump() for f in fps[:10]],
                "rules_with_high_fp": [
                    r.model_dump() for r in rules if r.false_positive_rate > 0.15
                ][:5],
            },
            default=str,
        )
        llm_result = cast(
            FalsePositiveResult,
            await llm_structured(
                system_prompt=SYSTEM_FALSE_POSITIVE_ANALYSIS,
                user_prompt=f"False positive data:\n{ctx}",
                schema=FalsePositiveResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="waf_manager",
            node="reduce_false_positives",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="waf_manager",
            node="reduce_false_positives",
        )

    return {
        "false_positives": [f.model_dump() for f in fps],
        "current_step": "reduce_false_positives",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def auto_block(
    state: dict[str, Any],
    toolkit: WAFManagerToolkit,
) -> dict[str, Any]:
    """Auto-block malicious sources exceeding thresholds."""
    logger.info("waf_manager.node.auto_block")
    state = _to_dict(state)
    summary = state.get("attack_summary", {})

    blocked = await toolkit.auto_block_sources(summary)
    blocked_ips = [b["ip"] for b in blocked]

    return {
        "auto_blocked_ips": blocked_ips,
        "block_recommendations": blocked,
        "current_step": "auto_block",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Auto-blocked {len(blocked_ips)} IPs"],
    }


async def report(
    state: dict[str, Any],
    toolkit: WAFManagerToolkit,
) -> dict[str, Any]:
    """Generate final WAF management report."""
    logger.info("waf_manager.node.report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    events = state.get("attack_events", [])
    gaps = state.get("coverage_gaps", [])
    fps = state.get("false_positives", [])
    blocked = state.get("auto_blocked_ips", [])
    proposals = state.get("proposed_rules", [])

    return {
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report: {len(events)} events, "
            f"{len(gaps)} coverage checks, "
            f"{len(fps)} FPs, "
            f"{len(blocked)} blocked, "
            f"{len(proposals)} proposals"
        ],
    }
