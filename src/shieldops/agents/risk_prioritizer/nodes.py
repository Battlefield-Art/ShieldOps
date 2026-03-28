"""Node implementations for the Risk Prioritizer Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.risk_prioritizer.models import (
    ActionUrgency,
    PrioritizerStage,
    RiskPrioritizerState,
)
from shieldops.agents.risk_prioritizer.prompts import (
    SYSTEM_ACTION,
    SYSTEM_REPORT,
    SYSTEM_SCORE,
    ActionPlanOutput,
    PrioritizerReportOutput,
    RiskScoringOutput,
)
from shieldops.agents.risk_prioritizer.tools import (
    RiskPrioritizerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: RiskPrioritizerToolkit | None = None


def set_toolkit(
    toolkit: RiskPrioritizerToolkit,
) -> None:
    """Set the global toolkit instance."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> RiskPrioritizerToolkit:
    if _toolkit is None:
        return RiskPrioritizerToolkit()
    return _toolkit


async def collect_findings(
    state: RiskPrioritizerState,
) -> dict[str, Any]:
    """Collect findings to prioritize."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    findings = await toolkit.collect_findings(
        tenant_id=state.tenant_id,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "findings_collected": findings,
        "current_stage": (PrioritizerStage.COLLECT_FINDINGS),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Collected {len(findings)} findings ({elapsed}ms)",
        ],
    }


async def enrich_context(
    state: RiskPrioritizerState,
) -> dict[str, Any]:
    """Enrich findings with business context."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    enrichments = await toolkit.enrich_context(
        state.findings_collected,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "enrichments": enrichments,
        "current_stage": (PrioritizerStage.ENRICH_CONTEXT),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Enriched {len(enrichments)} findings ({elapsed}ms)",
        ],
    }


async def score_risk(
    state: RiskPrioritizerState,
) -> dict[str, Any]:
    """Calculate risk scores for findings."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scores = await toolkit.score_risk(
        state.findings_collected,
        state.enrichments,
    )

    # LLM enrichment for risk scoring
    for _i, score in enumerate(scores):
        finding = next(
            (f for f in state.findings_collected if f.id == score.finding_id),
            None,
        )
        if finding:
            try:
                result = await llm_structured(
                    system_prompt=SYSTEM_SCORE,
                    user_prompt=(
                        f"Finding: {finding.title}\n"
                        f"Severity: {finding.severity}\n"
                        f"CVSS: {finding.cvss_score}\n"
                        f"Asset: {finding.asset}"
                    ),
                    output_schema=RiskScoringOutput,
                )
                score.composite_score = result.composite_score
                score.exploitability = result.exploitability
                score.blast_radius = result.blast_radius
            except Exception:
                logger.warning(
                    "risk_prioritizer.score_fallback",
                    finding_id=score.finding_id,
                )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "risk_scores": scores,
        "current_stage": PrioritizerStage.SCORE_RISK,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Scored {len(scores)} findings ({elapsed}ms)",
        ],
    }


async def rank_findings(
    state: RiskPrioritizerState,
) -> dict[str, Any]:
    """Rank findings by risk score."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    ranked = await toolkit.rank_findings(
        state.findings_collected,
        state.risk_scores,
    )

    critical = sum(1 for r in ranked if r.urgency == ActionUrgency.IMMEDIATE)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "ranked_findings": ranked,
        "critical_count": critical,
        "current_stage": (PrioritizerStage.RANK_FINDINGS),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Ranked {len(ranked)} findings, {critical} critical ({elapsed}ms)",
        ],
    }


async def generate_action_plan(
    state: RiskPrioritizerState,
) -> dict[str, Any]:
    """Generate action plans for ranked findings."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    plans = await toolkit.generate_action_plans(
        state.ranked_findings,
    )

    # LLM enrichment for action plans
    for plan in plans[:10]:
        finding = next(
            (f for f in state.findings_collected if f.id == plan.finding_id),
            None,
        )
        if finding:
            try:
                result = await llm_structured(
                    system_prompt=SYSTEM_ACTION,
                    user_prompt=(
                        f"Finding: {finding.title}\nUrgency: {plan.urgency}\nAsset: {finding.asset}"
                    ),
                    output_schema=ActionPlanOutput,
                )
                plan.recommended_action = result.recommended_action
                plan.estimated_effort_hours = result.estimated_effort_hours
                plan.assigned_team = result.assigned_team
            except Exception:
                logger.warning("risk_prioritizer.action_fallback")

    immediate = sum(1 for p in plans if p.urgency == ActionUrgency.IMMEDIATE)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "action_plans": plans,
        "immediate_actions": immediate,
        "current_stage": (PrioritizerStage.GENERATE_ACTION_PLAN),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Generated {len(plans)} action plans, {immediate} immediate ({elapsed}ms)",
        ],
    }


async def generate_report(
    state: RiskPrioritizerState,
) -> dict[str, Any]:
    """Generate prioritizer report."""
    start = datetime.now(UTC)

    try:
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(
                f"Findings: "
                f"{len(state.findings_collected)}\n"
                f"Critical: {state.critical_count}\n"
                f"Immediate actions: "
                f"{state.immediate_actions}\n"
                f"Action plans: "
                f"{len(state.action_plans)}"
            ),
            output_schema=PrioritizerReportOutput,
        )
        summary = result.executive_summary
    except Exception:
        logger.warning("risk_prioritizer.report_fallback")
        summary = (
            f"Prioritized "
            f"{len(state.findings_collected)} findings, "
            f"{state.critical_count} critical, "
            f"{state.immediate_actions} immediate"
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "current_stage": PrioritizerStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report: {summary[:100]} ({elapsed}ms)",
        ],
        "session_duration_ms": (state.session_duration_ms + elapsed),
    }
