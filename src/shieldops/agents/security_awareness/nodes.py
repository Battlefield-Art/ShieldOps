"""Node implementations for the Security Awareness Agent LangGraph workflow.

Each node is an async function that:
1. Calls toolkit tools for baseline, simulation, training, and scoring
2. Uses the LLM to enhance analysis and reporting
3. Updates the awareness state
4. Records reasoning steps in the audit trail
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.security_awareness.models import (
    AwarenessStage,
    SecurityAwarenessState,
)
from shieldops.agents.security_awareness.prompts import (
    SYSTEM_ANALYZE_SIMULATIONS,
    SYSTEM_ANALYZE_TRAINING,
    SYSTEM_ASSESS_BASELINE,
    SYSTEM_RECOMMEND,
    SYSTEM_REPORT,
    SYSTEM_SCORE_RISK,
    BaselineOutput,
    RecommendationOutput,
    ReportOutput,
    RiskScoringOutput,
    SimulationAnalysisOutput,
    TrainingAnalysisOutput,
)
from shieldops.agents.security_awareness.tools import (
    SecurityAwarenessToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit reference, set by the runner.
_toolkit: SecurityAwarenessToolkit | None = None


def set_toolkit(toolkit: SecurityAwarenessToolkit) -> None:
    """Configure the toolkit used by all nodes."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> SecurityAwarenessToolkit:
    if _toolkit is None:
        return SecurityAwarenessToolkit()
    return _toolkit


async def assess_baseline(
    state: SecurityAwarenessState,
) -> dict[str, Any]:
    """Assess current security awareness baseline."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "awareness.assess_baseline",
        tenant_id=state.tenant_id,
    )

    phishing, training = await toolkit.assess_baseline(
        state.tenant_id,
    )

    user_prompt = (
        f"Tenant: {state.tenant_id}\n"
        f"Phishing results: {len(phishing)} records\n"
        f"Training records: {len(training)} records\n"
        f"Departments: {len({p.department for p in phishing})}\n"
        f"Click rate: "
        f"{sum(1 for p in phishing if p.clicked_link)}"
        f"/{len(phishing)}"
    )

    llm_summary = f"Baseline: {len(phishing)} phishing, {len(training)} training records."

    try:
        result = cast(
            BaselineOutput,
            await llm_structured(
                system_prompt=SYSTEM_ASSESS_BASELINE,
                user_prompt=user_prompt,
                schema=BaselineOutput,
            ),
        )
        llm_summary = (
            f"LLM baseline: posture={result.overall_readiness}"
            f", susceptibility="
            f"{result.phishing_susceptibility_pct:.0f}%. "
            f"Gaps: {'; '.join(result.training_gap_areas[:3])}"
        )
    except Exception as e:
        logger.error(
            "llm_assess_baseline_failed",
            error=str(e),
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    reasoning = f"[assess_baseline] {llm_summary} ({elapsed}ms)"

    return {
        "phishing_results": phishing,
        "training_records": training,
        "stage": AwarenessStage.ASSESS_BASELINE,
        "reasoning_chain": [
            *state.reasoning_chain,
            reasoning,
        ],
    }


async def run_simulations(
    state: SecurityAwarenessState,
) -> dict[str, Any]:
    """Run phishing simulations and analyze results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    updated = await toolkit.run_simulations(
        state.simulation_type,
        state.phishing_results,
    )

    click_count = sum(1 for p in updated if p.clicked_link)
    total = len(updated)
    fail_pct = (click_count / total * 100) if total else 0

    user_prompt = (
        f"Simulation type: {state.simulation_type.value}\n"
        f"Total results: {total}\n"
        f"Click rate: {click_count}/{total} "
        f"({fail_pct:.1f}%)\n"
        f"Departments tested: "
        f"{len({p.department for p in updated})}"
    )

    llm_summary = f"Ran {state.simulation_type.value}: {fail_pct:.1f}% fail rate."

    try:
        result = cast(
            SimulationAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE_SIMULATIONS,
                user_prompt=user_prompt,
                schema=SimulationAnalysisOutput,
            ),
        )
        llm_summary = (
            f"LLM simulation analysis: "
            f"fail={result.failure_rate_pct:.0f}%, "
            f"trend={result.improvement_vs_prior}. "
            f"Patterns: "
            f"{'; '.join(result.top_failure_patterns[:2])}"
        )
    except Exception as e:
        logger.error(
            "llm_analyze_simulations_failed",
            error=str(e),
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    reasoning = f"[run_simulations] {llm_summary} ({elapsed}ms)"

    return {
        "phishing_results": updated,
        "stage": AwarenessStage.RUN_SIMULATIONS,
        "reasoning_chain": [
            *state.reasoning_chain,
            reasoning,
        ],
    }


async def track_training(
    state: SecurityAwarenessState,
) -> dict[str, Any]:
    """Track and analyze training completion."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    updated = await toolkit.track_training(
        state.training_records,
    )

    passed = sum(1 for t in updated if t.passed)
    overdue = sum(1 for t in updated if t.overdue)
    total = len(updated)
    completion_pct = (passed / total * 100) if total else 0

    user_prompt = (
        f"Training records: {total}\n"
        f"Completed: {passed} ({completion_pct:.1f}%)\n"
        f"Overdue: {overdue}\n"
        f"Avg score: "
        f"{sum(t.score_pct for t in updated if t.passed) / max(passed, 1):.1f}%"
    )

    llm_summary = f"Training: {completion_pct:.1f}% complete, {overdue} overdue."

    try:
        result = cast(
            TrainingAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE_TRAINING,
                user_prompt=user_prompt,
                schema=TrainingAnalysisOutput,
            ),
        )
        llm_summary = (
            f"LLM training: "
            f"completion={result.completion_rate_pct:.0f}%, "
            f"avg_score={result.avg_score_pct:.0f}%, "
            f"effectiveness={result.effectiveness_rating}"
        )
    except Exception as e:
        logger.error(
            "llm_analyze_training_failed",
            error=str(e),
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    reasoning = f"[track_training] {llm_summary} ({elapsed}ms)"

    return {
        "training_records": updated,
        "stage": AwarenessStage.TRACK_TRAINING,
        "reasoning_chain": [
            *state.reasoning_chain,
            reasoning,
        ],
    }


async def score_risk(
    state: SecurityAwarenessState,
) -> dict[str, Any]:
    """Calculate per-user and per-department risk scores."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scores, summaries = await toolkit.score_risk(
        state.phishing_results,
        state.training_records,
    )

    overall = sum(s.risk_score for s in scores) / len(scores) if scores else 0

    user_prompt = (
        f"Users scored: {len(scores)}\n"
        f"Departments: {len(summaries)}\n"
        f"Overall avg risk: {overall:.1f}\n"
        f"High/Critical: "
        f"{sum(1 for s in scores if s.risk_tier in ('critical', 'high'))}"
    )

    llm_summary = f"Risk scored {len(scores)} users, avg={overall:.1f}."

    try:
        result = cast(
            RiskScoringOutput,
            await llm_structured(
                system_prompt=SYSTEM_SCORE_RISK,
                user_prompt=user_prompt,
                schema=RiskScoringOutput,
            ),
        )
        llm_summary = (
            f"LLM risk: "
            f"high_risk={result.high_risk_user_count}, "
            f"avg={result.avg_risk_score:.0f}. "
            f"Factors: "
            f"{'; '.join(result.top_risk_factors[:2])}"
        )
    except Exception as e:
        logger.error(
            "llm_score_risk_failed",
            error=str(e),
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    reasoning = f"[score_risk] {llm_summary} ({elapsed}ms)"

    return {
        "risk_scores": scores,
        "department_summaries": summaries,
        "overall_score": round(overall, 1),
        "stage": AwarenessStage.SCORE_RISK,
        "reasoning_chain": [
            *state.reasoning_chain,
            reasoning,
        ],
    }


async def recommend(
    state: SecurityAwarenessState,
) -> dict[str, Any]:
    """Generate improvement recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    recs = await toolkit.generate_recommendations(
        state.risk_scores,
        state.department_summaries,
    )

    user_prompt = (
        f"Overall score: {state.overall_score:.1f}\n"
        f"Risk scores: {len(state.risk_scores)} users\n"
        f"Departments: {len(state.department_summaries)}\n"
        f"Toolkit recommendations:\n" + "\n".join(f"- {r}" for r in recs)
    )

    llm_summary = f"Generated {len(recs)} recommendations."

    try:
        result = cast(
            RecommendationOutput,
            await llm_structured(
                system_prompt=SYSTEM_RECOMMEND,
                user_prompt=user_prompt,
                schema=RecommendationOutput,
            ),
        )
        recs = result.recommendations
        llm_summary = (
            f"LLM recommendations: {len(recs)} items. Quick wins: {len(result.quick_wins)}"
        )
    except Exception as e:
        logger.error(
            "llm_recommend_failed",
            error=str(e),
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    reasoning = f"[recommend] {llm_summary} ({elapsed}ms)"

    return {
        "recommendations": recs,
        "stage": AwarenessStage.RECOMMEND,
        "reasoning_chain": [
            *state.reasoning_chain,
            reasoning,
        ],
    }


async def report(
    state: SecurityAwarenessState,
) -> dict[str, Any]:
    """Generate final security awareness report."""
    start = datetime.now(UTC)

    context_lines = [
        f"Overall score: {state.overall_score:.1f}",
        f"Users scored: {len(state.risk_scores)}",
        f"Departments: {len(state.department_summaries)}",
        f"Phishing results: {len(state.phishing_results)}",
        f"Training records: {len(state.training_records)}",
        f"Recommendations: {len(state.recommendations)}",
        "",
        "Reasoning chain:",
        *[f"  {r}" for r in state.reasoning_chain],
    ]
    user_prompt = "\n".join(context_lines)

    report_summary = (
        f"Security awareness assessment complete. "
        f"Overall risk score: {state.overall_score:.1f}/100. "
        f"{len(state.risk_scores)} users evaluated, "
        f"{len(state.recommendations)} recommendations."
    )

    try:
        result = cast(
            ReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=user_prompt,
                schema=ReportOutput,
            ),
        )
        report_summary = (
            f"{result.executive_summary}\n\n"
            f"Score: {result.overall_score:.0f}/100.\n"
            f"Findings: "
            f"{'; '.join(result.key_findings[:3])}\n"
            f"Actions: "
            f"{'; '.join(result.action_items[:3])}"
        )
    except Exception as e:
        logger.error("llm_report_failed", error=str(e))

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    total_duration = (
        sum(int(r.split("(")[-1].rstrip("ms)")) for r in state.reasoning_chain if r.endswith("ms)"))
        + elapsed
    )

    reasoning = f"[report] Generated final report ({elapsed}ms)"

    return {
        "report_summary": report_summary,
        "stage": AwarenessStage.REPORT,
        "duration_ms": total_duration,
        "reasoning_chain": [
            *state.reasoning_chain,
            reasoning,
        ],
    }
