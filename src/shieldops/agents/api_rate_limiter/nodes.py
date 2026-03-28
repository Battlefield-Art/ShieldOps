"""API Rate Limiter — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import AbuseDetection, ClientProfile
from .tools import APIRateLimiterToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def ingest_requests(
    state: dict[str, Any],
    toolkit: APIRateLimiterToolkit,
) -> dict[str, Any]:
    """Ingest raw API requests for analysis."""
    logger.info("api_rate_limiter.node.ingest_requests")
    state = _to_dict(state)
    raw = state.get("raw_requests", [])
    session_start = time.time()

    ingested = await toolkit.ingest_requests(raw)

    return {
        "raw_requests": [r.model_dump() for r in ingested],
        "session_start": session_start,
        "current_step": "ingest_requests",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Ingested {len(ingested)} API requests"],
    }


async def profile_clients(
    state: dict[str, Any],
    toolkit: APIRateLimiterToolkit,
) -> dict[str, Any]:
    """Build behavioral profiles for all clients."""
    logger.info("api_rate_limiter.node.profile_clients")
    state = _to_dict(state)
    window = state.get("time_window_minutes", 5)

    profiles = await toolkit.build_client_profiles(
        window_minutes=window,
    )

    endpoint_stats: dict[str, int] = {}
    for req_data in state.get("raw_requests", []):
        ep = req_data.get("endpoint", "/")
        endpoint_stats[ep] = endpoint_stats.get(ep, 0) + 1

    return {
        "client_profiles": [p.model_dump() for p in profiles],
        "endpoint_stats": endpoint_stats,
        "current_step": "profile_clients",
        "reasoning_chain": state.get("reasoning_chain", []) + [f"Profiled {len(profiles)} clients"],
    }


async def detect_abuse(
    state: dict[str, Any],
    toolkit: APIRateLimiterToolkit,
) -> dict[str, Any]:
    """Detect abuse patterns from client profiles."""
    logger.info("api_rate_limiter.node.detect_abuse")
    state = _to_dict(state)
    profile_dicts = state.get("client_profiles", [])
    profiles = [ClientProfile(**p) for p in profile_dicts]

    detections = await toolkit.detect_abuse_patterns(profiles)
    detection_dicts = [d.model_dump() for d in detections]

    threat_score = 0.0
    if detections:
        threat_score = max(d.confidence for d in detections)

    reasoning_note = f"Detected {len(detections)} abuse patterns, threat score: {threat_score:.2f}"

    # LLM enhancement
    try:
        from .prompts import SYSTEM_ABUSE_ANALYSIS, AbuseAnalysisResult

        context = json.dumps(
            {
                "client_count": len(profiles),
                "detection_count": len(detections),
                "detections_summary": detection_dicts[:15],
                "endpoint_stats": state.get("endpoint_stats", {}),
            },
            default=str,
        )
        llm_result = cast(
            AbuseAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_ABUSE_ANALYSIS,
                user_prompt=f"API traffic data:\n{context}",
                schema=AbuseAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="api_rate_limiter",
            node="detect_abuse",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="api_rate_limiter",
            node="detect_abuse",
        )

    return {
        "abuse_detections": detection_dicts,
        "threat_score": threat_score,
        "current_step": "detect_abuse",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def classify_threats(
    state: dict[str, Any],
    toolkit: APIRateLimiterToolkit,
) -> dict[str, Any]:
    """Classify threats and determine response strategy."""
    logger.info("api_rate_limiter.node.classify_threats")
    state = _to_dict(state)
    detections = state.get("abuse_detections", [])
    profiles = state.get("client_profiles", [])

    reasoning_note = f"Classified {len(detections)} threats"

    # LLM classification
    try:
        from .prompts import (
            SYSTEM_THREAT_CLASSIFICATION,
            ThreatClassificationResult,
        )

        context = json.dumps(
            {
                "detections": detections[:10],
                "client_profiles": profiles[:10],
                "threat_score": state.get("threat_score", 0.0),
            },
            default=str,
        )
        llm_result = cast(
            ThreatClassificationResult,
            await llm_structured(
                system_prompt=SYSTEM_THREAT_CLASSIFICATION,
                user_prompt=f"Threat classification:\n{context}",
                schema=ThreatClassificationResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="api_rate_limiter",
            node="classify_threats",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="api_rate_limiter",
            node="classify_threats",
        )

    return {
        "current_step": "classify_threats",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def enforce_limits(
    state: dict[str, Any],
    toolkit: APIRateLimiterToolkit,
) -> dict[str, Any]:
    """Generate and enforce adaptive rate limit rules."""
    logger.info("api_rate_limiter.node.enforce_limits")
    state = _to_dict(state)
    detection_dicts = state.get("abuse_detections", [])
    profile_dicts = state.get("client_profiles", [])

    detections = [AbuseDetection(**d) for d in detection_dicts]
    profiles = [ClientProfile(**p) for p in profile_dicts]

    rules = await toolkit.generate_adaptive_rules(detections, profiles)
    actions = await toolkit.enforce_rules(rules)
    summary = await toolkit.get_enforcement_summary()

    # LLM rule refinement
    reasoning_note = (
        f"Enforced {len(rules)} rules, "
        f"{summary['blocked_count']} blocked, "
        f"{summary['throttled_count']} throttled"
    )
    try:
        from .prompts import SYSTEM_ADAPTIVE_RULES, AdaptiveRuleResult

        context = json.dumps(
            {
                "rules": [r.model_dump() for r in rules[:10]],
                "actions": [a.model_dump() for a in actions[:10]],
                "summary": summary,
            },
            default=str,
        )
        llm_result = cast(
            AdaptiveRuleResult,
            await llm_structured(
                system_prompt=SYSTEM_ADAPTIVE_RULES,
                user_prompt=f"Rule refinement:\n{context}",
                schema=AdaptiveRuleResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="api_rate_limiter",
            node="enforce_limits",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="api_rate_limiter",
            node="enforce_limits",
        )

    return {
        "rate_limit_rules": [r.model_dump() for r in rules],
        "enforcement_actions": [a.model_dump() for a in actions],
        "blocked_clients": summary["blocked_clients"],
        "throttled_clients": summary["throttled_clients"],
        "current_step": "enforce_limits",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: APIRateLimiterToolkit,
) -> dict[str, Any]:
    """Generate final rate limiting report."""
    logger.info("api_rate_limiter.node.generate_report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    summary = {
        "total_requests": len(state.get("raw_requests", [])),
        "clients_profiled": len(state.get("client_profiles", [])),
        "abuse_patterns_detected": len(state.get("abuse_detections", [])),
        "rules_enforced": len(state.get("rate_limit_rules", [])),
        "clients_blocked": len(state.get("blocked_clients", [])),
        "clients_throttled": len(state.get("throttled_clients", [])),
        "threat_score": state.get("threat_score", 0.0),
        "duration_ms": round(duration_ms, 2),
    }

    return {
        "summary": summary,
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report: {summary['total_requests']} requests, "
            f"{summary['abuse_patterns_detected']} abuse patterns, "
            f"{summary['clients_blocked']} blocked, "
            f"{summary['clients_throttled']} throttled"
        ],
    }
