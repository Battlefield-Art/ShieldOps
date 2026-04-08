"""Node implementations for the Dark Web Intelligence
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.dark_web_intelligence.models import (
    DarkWebIntelligenceState,
    DarkWebStage,
)
from shieldops.agents.dark_web_intelligence.prompts import (
    SYSTEM_CREDIBILITY,
    SYSTEM_FORUM_MONITOR,
    SYSTEM_REPORT,
    SYSTEM_THREAT_ANALYSIS,
    CredibilityAssessmentOutput,
    DarkWebReportOutput,
    ForumMonitorOutput,
    ThreatAnalysisOutput,
)
from shieldops.agents.dark_web_intelligence.tools import (
    DarkWebIntelligenceToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: DarkWebIntelligenceToolkit | None = None


def _get_toolkit() -> DarkWebIntelligenceToolkit:
    if _toolkit is None:
        return DarkWebIntelligenceToolkit()
    return _toolkit


# ------------------------------------------------------------------
# Node: monitor_forums
# ------------------------------------------------------------------


async def monitor_forums(
    state: DarkWebIntelligenceState,
) -> dict[str, Any]:
    """Monitor dark web forums for activity."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    forums = await toolkit.monitor_forums(
        keywords=["shieldops", "credentials"],
        tenant_id=state.tenant_id,
    )

    try:
        ctx = _json.dumps(
            {"tenant_id": state.tenant_id, "forums": forums[:5]},
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_FORUM_MONITOR,
            user_prompt=f"Monitor forums:\n{ctx}",
            schema=ForumMonitorOutput,
        )
        if llm_out.forums:  # type: ignore[union-attr]
            forums = [*forums, *llm_out.forums]  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="monitor_forums",
            count=len(llm_out.forums),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="monitor_forums")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "forum_sources": forums,
        "stage": DarkWebStage.MONITOR_FORUMS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Monitoring {len(forums)} forums ({elapsed}ms)",
        ],
        "current_step": "monitor_forums",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: collect_mentions
# ------------------------------------------------------------------


async def collect_mentions(
    state: DarkWebIntelligenceState,
) -> dict[str, Any]:
    """Collect mentions from monitored forums."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    mentions = await toolkit.collect_mentions(
        forums=state.forum_sources,
        keywords=["credentials", "data", "exploit"],
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "mentions": mentions,
        "total_mentions": len(mentions),
        "stage": DarkWebStage.COLLECT_MENTIONS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Collected {len(mentions)} mentions ({elapsed}ms)",
        ],
        "current_step": "collect_mentions",
    }


# ------------------------------------------------------------------
# Node: analyze_threats
# ------------------------------------------------------------------


async def analyze_threats(
    state: DarkWebIntelligenceState,
) -> dict[str, Any]:
    """Analyze threats from collected mentions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_threats(
        mentions=state.mentions,
    )

    try:
        ctx = _json.dumps(
            {"mentions": state.mentions[:5]},
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_THREAT_ANALYSIS,
            user_prompt=f"Analyze threats:\n{ctx}",
            schema=ThreatAnalysisOutput,
        )
        if llm_out.threats:  # type: ignore[union-attr]
            analyses = [*analyses, *llm_out.threats]  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="analyze_threats",
            count=len(llm_out.threats),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="analyze_threats")

    critical = sum(1 for a in analyses if a.get("severity") == "critical")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "threat_analyses": analyses,
        "critical_threats": critical,
        "stage": DarkWebStage.ANALYZE_THREATS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Analyzed {len(analyses)} threats, {critical} critical ({elapsed}ms)",
        ],
        "current_step": "analyze_threats",
    }


# ------------------------------------------------------------------
# Node: assess_credibility
# ------------------------------------------------------------------


async def assess_credibility(
    state: DarkWebIntelligenceState,
) -> dict[str, Any]:
    """Assess source credibility."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_credibility(
        mentions=state.mentions,
        analyses=state.threat_analyses,
    )

    try:
        ctx = _json.dumps(
            {
                "mentions": state.mentions[:5],
                "threats": state.threat_analyses[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_CREDIBILITY,
            user_prompt=f"Assess credibility:\n{ctx}",
            schema=CredibilityAssessmentOutput,
        )
        if llm_out.assessments:  # type: ignore[union-attr]
            assessments = [*assessments, *llm_out.assessments]  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="assess_credibility",
            count=len(llm_out.assessments),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_credibility",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "credibility_assessments": assessments,
        "stage": DarkWebStage.ASSESS_CREDIBILITY,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Assessed {len(assessments)} credibility ratings ({elapsed}ms)",
        ],
        "current_step": "assess_credibility",
    }


# ------------------------------------------------------------------
# Node: send_alerts
# ------------------------------------------------------------------


async def send_alerts(
    state: DarkWebIntelligenceState,
) -> dict[str, Any]:
    """Send alerts for critical threats."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    critical = [t for t in state.threat_analyses if t.get("severity") == "critical"]
    alerts = await toolkit.send_alerts(critical_threats=critical)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "alerts_sent": alerts,
        "alerts_generated": len(alerts),
        "stage": DarkWebStage.ALERT,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Sent {len(alerts)} alerts ({elapsed}ms)",
        ],
        "current_step": "send_alerts",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: DarkWebIntelligenceState,
) -> dict[str, Any]:
    """Generate dark web intelligence report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "total_mentions": state.total_mentions,
        "critical_threats": state.critical_threats,
        "alerts_generated": state.alerts_generated,
    }

    try:
        ctx = _json.dumps(
            {
                "mentions": state.total_mentions,
                "critical": state.critical_threats,
                "threats": state.threat_analyses[:10],
                "credibility": state.credibility_assessments[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate dark web report:\n{ctx}",
            schema=DarkWebReportOutput,
        )
        if isinstance(llm_out, DarkWebReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "critical_findings": llm_out.critical_findings,
                    "recommendations": llm_out.recommendations,
                    "risk_level": llm_out.risk_level,
                }
            )
        logger.info("llm_enhanced", node="generate_report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="generate_report")

    await toolkit.record_metric(
        "critical_threats",
        float(state.critical_threats),
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    return {
        "stats": report,
        "stage": DarkWebStage.REPORT,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report generated ({elapsed}ms)",
        ],
        "current_step": "complete",
    }
