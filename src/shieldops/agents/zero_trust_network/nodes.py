"""Zero Trust Network Access — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import IdentityType, TrustDecision
from .tools import ZeroTrustNetworkToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_access_points(
    state: dict[str, Any],
    toolkit: ZeroTrustNetworkToolkit,
) -> dict[str, Any]:
    """Discover all access points in the tenant."""
    logger.info("ztna.node.discover_access_points")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    scope = state.get("scope", "full")
    session_start = time.time()

    points = await toolkit.discover_access_points(
        tenant_id=tenant_id,
        scope=scope,
    )

    return {
        "access_points": [p.model_dump() for p in points],
        "session_start": session_start,
        "current_step": "discover_access_points",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(points)} access points for tenant {tenant_id}"],
    }


async def assess_identity_trust(
    state: dict[str, Any],
    toolkit: ZeroTrustNetworkToolkit,
) -> dict[str, Any]:
    """Assess trust scores for all identities."""
    logger.info("ztna.node.assess_identity_trust")
    state = _to_dict(state)
    identity_filter = state.get("identity_filter", "")

    # Simulate identities from multiple sources
    identities = _get_identities(state, identity_filter)

    scores: list[dict[str, Any]] = []
    for ident in identities:
        id_type = IdentityType(ident.get("type", "human"))
        score = await toolkit.assess_identity_trust(
            identity_id=ident["id"],
            identity_type=id_type,
            context=ident.get("context", {}),
        )
        scores.append(score.model_dump())

    # LLM-enhanced trust analysis
    reasoning_note = f"Assessed trust for {len(scores)} identities"
    try:
        from .prompts import (
            SYSTEM_TRUST_ANALYSIS,
            TrustAnalysisResult,
        )

        analysis_ctx = json.dumps(
            {
                "identity_count": len(scores),
                "scores_summary": scores[:20],
                "identity_types": [s.get("identity_type", "") for s in scores],
            },
            default=str,
        )
        llm_result = cast(
            TrustAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_TRUST_ANALYSIS,
                user_prompt=(f"Identity trust data:\n{analysis_ctx}"),
                schema=TrustAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="zero_trust_network",
            node="assess_identity_trust",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="zero_trust_network",
            node="assess_identity_trust",
        )

    return {
        "identity_scores": scores,
        "current_step": "assess_identity_trust",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def evaluate_device_posture(
    state: dict[str, Any],
    toolkit: ZeroTrustNetworkToolkit,
) -> dict[str, Any]:
    """Evaluate device/runtime posture for identities."""
    logger.info("ztna.node.evaluate_device_posture")
    state = _to_dict(state)
    scores = state.get("identity_scores", [])

    postures: list[dict[str, Any]] = []
    for score in scores:
        identity_id = score.get("identity_id", "")
        device_id = f"dev-{identity_id[:8]}"
        posture = await toolkit.evaluate_device_posture(
            device_id=device_id,
            identity_id=identity_id,
            context=score,
        )
        postures.append(posture.model_dump())

    non_compliant = sum(1 for p in postures if not p.get("compliant", True))

    return {
        "device_postures": postures,
        "current_step": "evaluate_device_posture",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Evaluated {len(postures)} device postures, {non_compliant} non-compliant"],
    }


async def enforce_policies(
    state: dict[str, Any],
    toolkit: ZeroTrustNetworkToolkit,
) -> dict[str, Any]:
    """Enforce zero trust policies for each identity."""
    logger.info("ztna.node.enforce_policies")
    state = _to_dict(state)
    scores = state.get("identity_scores", [])
    postures = state.get("device_postures", [])
    access_points = state.get("access_points", [])

    posture_map = {p.get("identity_id", ""): p for p in postures}

    enforcements: list[dict[str, Any]] = []
    denied = 0
    challenged = 0
    quarantined = 0

    for score in scores:
        identity_id = score.get("identity_id", "")
        trust = score.get("trust_score", 0.0)
        posture = posture_map.get(identity_id, {})
        compliant = posture.get("compliant", False)

        # Enforce against each relevant access point
        for ap in access_points:
            ap_id = ap.get("access_point_id", "")
            allowed_types = ap.get("identity_types_allowed", [])
            id_type = score.get("identity_type", "")
            if allowed_types and id_type not in allowed_types:
                continue

            enforcement = await toolkit.enforce_policy(
                identity_id=identity_id,
                access_point_id=ap_id,
                trust_score=trust,
                device_compliant=compliant,
            )
            enforcements.append(enforcement.model_dump())
            if enforcement.decision == TrustDecision.DENY:
                denied += 1
            elif enforcement.decision == TrustDecision.CHALLENGE:
                challenged += 1
            elif enforcement.decision == TrustDecision.QUARANTINE:
                quarantined += 1

    # LLM-enhanced policy decisions
    reasoning_note = (
        f"Enforced {len(enforcements)} policies: "
        f"{denied} denied, {challenged} challenged, "
        f"{quarantined} quarantined"
    )
    try:
        from .prompts import (
            SYSTEM_POLICY_DECISION,
            PolicyDecisionResult,
        )

        policy_ctx = json.dumps(
            {
                "enforcement_count": len(enforcements),
                "denied": denied,
                "challenged": challenged,
                "quarantined": quarantined,
                "enforcements_sample": enforcements[:15],
            },
            default=str,
        )
        llm_result = cast(
            PolicyDecisionResult,
            await llm_structured(
                system_prompt=SYSTEM_POLICY_DECISION,
                user_prompt=(f"Policy enforcement data:\n{policy_ctx}"),
                schema=PolicyDecisionResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="zero_trust_network",
            node="enforce_policies",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="zero_trust_network",
            node="enforce_policies",
        )

    return {
        "enforcements": enforcements,
        "denied_count": denied,
        "challenged_count": challenged,
        "quarantined_count": quarantined,
        "current_step": "enforce_policies",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def monitor_sessions(
    state: dict[str, Any],
    toolkit: ZeroTrustNetworkToolkit,
) -> dict[str, Any]:
    """Monitor active sessions with continuous verification."""
    logger.info("ztna.node.monitor_sessions")
    state = _to_dict(state)
    enforcements = state.get("enforcements", [])

    sessions: list[dict[str, Any]] = []
    for enf in enforcements:
        decision = enf.get("decision", "deny")
        if decision in (
            TrustDecision.DENY.value,
            TrustDecision.QUARANTINE.value,
        ):
            continue

        identity_id = enf.get("identity_id", "")
        ap_id = enf.get("access_point_id", "")
        session_id = f"sess-{identity_id[:6]}-{ap_id[:6]}"

        # Look up identity type from scores
        scores = state.get("identity_scores", [])
        id_type_str = "human"
        for s in scores:
            if s.get("identity_id") == identity_id:
                id_type_str = s.get("identity_type", "human")
                break

        session = await toolkit.monitor_session(
            session_id=session_id,
            identity_id=identity_id,
            identity_type=IdentityType(id_type_str),
            access_point_id=ap_id,
            request_count=1,
        )
        sessions.append(session.model_dump())

    # LLM session risk analysis
    reasoning_note = f"Monitoring {len(sessions)} active sessions"
    try:
        from .prompts import (
            SYSTEM_SESSION_RISK,
            SessionRiskResult,
        )

        session_ctx = json.dumps(
            {
                "session_count": len(sessions),
                "sessions_sample": sessions[:15],
            },
            default=str,
        )
        llm_result = cast(
            SessionRiskResult,
            await llm_structured(
                system_prompt=SYSTEM_SESSION_RISK,
                user_prompt=(f"Session monitoring data:\n{session_ctx}"),
                schema=SessionRiskResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="zero_trust_network",
            node="monitor_sessions",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="zero_trust_network",
            node="monitor_sessions",
        )

    return {
        "active_sessions": sessions,
        "current_step": "monitor_sessions",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def report(
    state: dict[str, Any],
    toolkit: ZeroTrustNetworkToolkit,
) -> dict[str, Any]:
    """Generate final zero trust assessment report."""
    logger.info("ztna.node.report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    # Compute aggregate zero trust score
    scores = state.get("identity_scores", [])
    postures = state.get("device_postures", [])
    enforcements = state.get("enforcements", [])

    avg_trust = 0.0
    if scores:
        avg_trust = sum(s.get("trust_score", 0.0) for s in scores) / len(scores)

    avg_posture = 0.0
    if postures:
        avg_posture = sum(p.get("posture_score", 0.0) for p in postures) / len(postures)

    deny_rate = 0.0
    if enforcements:
        denied = sum(1 for e in enforcements if e.get("decision") == TrustDecision.DENY.value)
        deny_rate = denied / len(enforcements)

    # Composite zero trust score
    zt_score = round(
        avg_trust * 0.4 + avg_posture * 0.3 + (1.0 - deny_rate) * 0.3,
        4,
    )

    session_summary = await toolkit.get_session_summary()

    return {
        "zero_trust_score": zt_score,
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report: ZT score={zt_score}, "
            f"{len(state.get('access_points', []))} "
            f"access points, "
            f"{len(scores)} identities, "
            f"{len(enforcements)} enforcements, "
            f"{session_summary.get('active', 0)} "
            f"active sessions"
        ],
    }


def _get_identities(
    state: dict[str, Any],
    identity_filter: str,
) -> list[dict[str, Any]]:
    """Build identity list from state/defaults."""
    # In production, this pulls from identity store
    # Default identities spanning all types
    identities: list[dict[str, Any]] = [
        {
            "id": "user-admin-01",
            "type": "human",
            "context": {
                "display_name": "Admin User",
                "mfa_enabled": True,
                "credential_age_days": 15,
            },
        },
        {
            "id": "svc-deploy-pipeline",
            "type": "service_account",
            "context": {
                "display_name": "Deploy Pipeline SA",
                "mfa_enabled": False,
                "credential_age_days": 45,
            },
        },
        {
            "id": "agent-security-scanner",
            "type": "ai_agent",
            "context": {
                "display_name": "Security Scanner",
                "mfa_enabled": False,
                "tool_scope_violation": False,
            },
        },
        {
            "id": "apikey-external-partner",
            "type": "api_key",
            "context": {
                "display_name": "Partner API Key",
                "mfa_enabled": False,
                "credential_age_days": 120,
            },
        },
        {
            "id": "mcp-coding-assistant",
            "type": "mcp_client",
            "context": {
                "display_name": "Coding Assistant MCP",
                "mfa_enabled": False,
                "god_key_detected": False,
                "unauthorized_tools": False,
            },
        },
    ]
    if identity_filter:
        identities = [
            i
            for i in identities
            if identity_filter in i.get("type", "") or identity_filter in i.get("id", "")
        ]
    return identities
