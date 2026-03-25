"""Node implementations for the OAuth Grant Analyzer Agent LangGraph workflow."""

from __future__ import annotations

import time
from typing import Any, cast

import structlog

from shieldops.agents.oauth_analyzer.models import OAuthAnalyzerState
from shieldops.agents.oauth_analyzer.prompts import (
    SYSTEM_ANOMALY_DETECTION,
    SYSTEM_GRANT_RISK_ANALYSIS,
    SYSTEM_PERMISSION_CLASSIFICATION,
    SYSTEM_RECOMMENDATION_GENERATION,
    AnomalyOutput,
    GrantRiskOutput,
    PermissionOutput,
    RecommendationOutput,
)
from shieldops.agents.oauth_analyzer.tools import OAuthAnalyzerToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: OAuthAnalyzerToolkit | None = None


def set_toolkit(toolkit: OAuthAnalyzerToolkit) -> None:
    """Configure the toolkit used by all nodes."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> OAuthAnalyzerToolkit:
    if _toolkit is None:
        return OAuthAnalyzerToolkit()
    return _toolkit


def _elapsed_ms(start: float) -> int:
    return int((time.time() - start) * 1000)


# ---------------------------------------------------------------------------
# Node 1: Discover Grants
# ---------------------------------------------------------------------------


async def discover_grants(state: OAuthAnalyzerState) -> dict[str, Any]:
    """Discover OAuth grants across SaaS and cloud providers."""
    start = time.time()
    toolkit = _get_toolkit()

    logger.info(
        "oauth_analyzer.discovering_grants",
        tenant_id=state.tenant_id,
        scan_scope=state.scan_scope,
    )

    grants = await toolkit.discover_oauth_grants(
        tenant_id=state.tenant_id,
        scope=state.scan_scope or None,
    )

    reasoning = (
        f"Discovered {len(grants)} OAuth grants across "
        f"{len({g.provider for g in grants})} providers "
        f"in {_elapsed_ms(start)}ms"
    )

    return {
        "discovered_grants": grants,
        "reasoning_chain": [*state.reasoning_chain, reasoning],
        "current_step": "discover_grants",
        "session_start": start,
    }


# ---------------------------------------------------------------------------
# Node 2: Classify Permissions
# ---------------------------------------------------------------------------


async def classify_permissions(state: OAuthAnalyzerState) -> dict[str, Any]:
    """Classify each grant's actual vs needed permissions."""
    toolkit = _get_toolkit()

    logger.info(
        "oauth_analyzer.classifying_permissions",
        grant_count=len(state.discovered_grants),
    )

    classifications = await toolkit.classify_permissions(state.discovered_grants)

    # LLM enhancement
    try:
        context_lines = ["## OAuth Grants for Permission Classification"]
        for g in state.discovered_grants[:30]:
            context_lines.append(
                f"- {g.app_name} ({g.provider}): scopes={g.scopes}, "
                f"scope_level={g.permission_scope.value}, "
                f"status={g.status.value}"
            )

        result = cast(
            PermissionOutput,
            await llm_structured(
                system_prompt=SYSTEM_PERMISSION_CLASSIFICATION,
                user_prompt="\n".join(context_lines),
                schema=PermissionOutput,
            ),
        )
        reasoning = f"Classified {len(classifications)} grants. LLM: {result.summary[:120]}"
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="classify_permissions",
            error=str(exc),
        )
        overprivileged_count = sum(1 for c in classifications if c.overprivileged)
        reasoning = (
            f"Classified {len(classifications)} grants — "
            f"{overprivileged_count} overprivileged (rule-based fallback)"
        )

    return {
        "permission_classifications": classifications,
        "reasoning_chain": [*state.reasoning_chain, reasoning],
        "current_step": "classify_permissions",
    }


# ---------------------------------------------------------------------------
# Node 3: Assess Risk
# ---------------------------------------------------------------------------


async def assess_risk(state: OAuthAnalyzerState) -> dict[str, Any]:
    """Assess risk scores for all discovered grants using LLM analysis."""
    logger.info(
        "oauth_analyzer.assessing_risk",
        grant_count=len(state.discovered_grants),
    )

    context_lines = ["## Discovered OAuth Grants"]
    for g in state.discovered_grants[:30]:
        context_lines.append(
            f"- id={g.id}, app={g.app_name}, provider={g.provider}, "
            f"scopes={g.scopes[:5]}, scope_level={g.permission_scope.value}, "
            f"status={g.status.value}, risk={g.risk_score}"
        )

    context_lines.append(
        f"\n## Permission Classifications ({len(state.permission_classifications)})"
    )
    for cls in state.permission_classifications[:20]:
        context_lines.append(
            f"- grant={cls.grant_id}, overprivileged={cls.overprivileged}, "
            f"unused={cls.unused_scopes}, factors={cls.risk_factors}"
        )

    user_prompt = "\n".join(context_lines)
    updated_grants = list(state.discovered_grants)

    try:
        result = cast(
            GrantRiskOutput,
            await llm_structured(
                system_prompt=SYSTEM_GRANT_RISK_ANALYSIS,
                user_prompt=user_prompt,
                schema=GrantRiskOutput,
            ),
        )

        # Merge LLM risk scores into grants
        llm_scores = {s.get("grant_id", ""): s.get("score", 0.0) for s in result.risk_scores}
        for i, grant in enumerate(updated_grants):
            if grant.id in llm_scores:
                updated_grants[i] = grant.model_copy(update={"risk_score": llm_scores[grant.id]})

        reasoning = (
            f"LLM risk assessment: {result.risk_summary[:150]}. "
            f"{len(result.high_risk_grant_ids)} high-risk grants identified"
        )
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="assess_risk",
            error=str(exc),
        )
        # Fallback: use tool-computed risk scores as-is
        high_risk = [g for g in updated_grants if g.risk_score >= 70]
        reasoning = (
            f"Risk assessment (rule-based fallback): "
            f"{len(high_risk)} high-risk grants of {len(updated_grants)} total"
        )

    stats: dict[str, Any] = {
        "total_grants": len(updated_grants),
        "high_risk": sum(1 for g in updated_grants if g.risk_score >= 70),
        "medium_risk": sum(1 for g in updated_grants if 30 <= g.risk_score < 70),
        "low_risk": sum(1 for g in updated_grants if g.risk_score < 30),
        "providers": list({g.provider for g in updated_grants}),
    }

    return {
        "discovered_grants": updated_grants,
        "stats": stats,
        "reasoning_chain": [*state.reasoning_chain, reasoning],
        "current_step": "assess_risk",
    }


# ---------------------------------------------------------------------------
# Node 4: Detect Anomalies
# ---------------------------------------------------------------------------


async def detect_anomalies(state: OAuthAnalyzerState) -> dict[str, Any]:
    """Detect anomalies in OAuth grant behavior and configuration."""
    toolkit = _get_toolkit()

    logger.info(
        "oauth_analyzer.detecting_anomalies",
        grant_count=len(state.discovered_grants),
    )

    anomalies = await toolkit.detect_grant_anomalies(state.discovered_grants)

    # LLM enhancement
    try:
        context_lines = ["## Grants with Anomaly Signals"]
        for g in state.discovered_grants[:30]:
            context_lines.append(
                f"- {g.app_name} ({g.provider}): status={g.status.value}, "
                f"scopes={len(g.scopes)}, risk={g.risk_score}"
            )
        if anomalies:
            context_lines.append(f"\n## Tool-Detected Anomalies ({len(anomalies)})")
            for a in anomalies[:20]:
                context_lines.append(
                    f"- {a.anomaly_type}: {a.description} "
                    f"(severity={a.severity}, confidence={a.confidence})"
                )

        result = cast(
            AnomalyOutput,
            await llm_structured(
                system_prompt=SYSTEM_ANOMALY_DETECTION,
                user_prompt="\n".join(context_lines),
                schema=AnomalyOutput,
            ),
        )
        reasoning = (
            f"Detected {len(anomalies)} anomalies. "
            f"LLM threat assessment: {result.threat_assessment[:120]}"
        )
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="detect_anomalies",
            error=str(exc),
        )
        reasoning = f"Detected {len(anomalies)} anomalies (rule-based fallback)"

    return {
        "anomalies": anomalies,
        "reasoning_chain": [*state.reasoning_chain, reasoning],
        "current_step": "detect_anomalies",
    }


# ---------------------------------------------------------------------------
# Node 5: Recommend Actions
# ---------------------------------------------------------------------------


async def recommend_actions(state: OAuthAnalyzerState) -> dict[str, Any]:
    """Generate remediation recommendations for risky and anomalous grants."""
    toolkit = _get_toolkit()

    logger.info(
        "oauth_analyzer.recommending_actions",
        grant_count=len(state.discovered_grants),
        anomaly_count=len(state.anomalies),
    )

    recs = await toolkit.generate_recommendations(state.discovered_grants, state.anomalies)

    # LLM enhancement
    try:
        context_lines = ["## Grants Requiring Action"]
        for g in state.discovered_grants[:20]:
            if g.risk_score >= 50:
                context_lines.append(
                    f"- {g.app_name} ({g.provider}): risk={g.risk_score}, "
                    f"status={g.status.value}, scope={g.permission_scope.value}"
                )
        context_lines.append(f"\n## Anomalies ({len(state.anomalies)})")
        for a in state.anomalies[:15]:
            context_lines.append(f"- {a.anomaly_type}: {a.description} (severity={a.severity})")

        result = cast(
            RecommendationOutput,
            await llm_structured(
                system_prompt=SYSTEM_RECOMMENDATION_GENERATION,
                user_prompt="\n".join(context_lines),
                schema=RecommendationOutput,
            ),
        )
        reasoning = (
            f"Generated {len(recs)} recommendations. "
            f"LLM: {result.summary[:120]}. "
            f"Est. risk reduction: {result.estimated_risk_reduction_pct}%"
        )
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="recommend_actions",
            error=str(exc),
        )
        reasoning = f"Generated {len(recs)} recommendations (rule-based fallback)"

    return {
        "recommendations": recs,
        "reasoning_chain": [*state.reasoning_chain, reasoning],
        "current_step": "recommend_actions",
    }


# ---------------------------------------------------------------------------
# Node 6: Generate Report
# ---------------------------------------------------------------------------


async def generate_report(state: OAuthAnalyzerState) -> dict[str, Any]:
    """Compile final report with stats and reasoning chain."""
    logger.info(
        "oauth_analyzer.generating_report",
        grants=len(state.discovered_grants),
        anomalies=len(state.anomalies),
        recommendations=len(state.recommendations),
    )

    stats = dict(state.stats)
    stats.update(
        {
            "anomalies_found": len(state.anomalies),
            "recommendations_generated": len(state.recommendations),
            "critical_anomalies": sum(1 for a in state.anomalies if a.severity == "critical"),
            "auto_executable_recs": sum(1 for r in state.recommendations if r.auto_executable),
            "overprivileged_grants": sum(
                1 for c in state.permission_classifications if c.overprivileged
            ),
        }
    )

    reasoning = (
        f"Report complete: {len(state.discovered_grants)} grants, "
        f"{len(state.anomalies)} anomalies, "
        f"{len(state.recommendations)} recommendations"
    )

    session_duration = 0
    if state.session_start:
        session_duration = _elapsed_ms(state.session_start)

    return {
        "stats": stats,
        "reasoning_chain": [*state.reasoning_chain, reasoning],
        "current_step": "complete",
        "session_duration_ms": session_duration,
        "stage": "report",
    }
