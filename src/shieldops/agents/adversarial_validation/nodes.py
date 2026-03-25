"""Node implementations for the Adversarial Validation Agent LangGraph workflow."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.adversarial_validation.models import (
    AdversarialValidationState,
    PatternUpdate,
    ValidationOutcome,
    ValidationStage,
)
from shieldops.agents.adversarial_validation.prompts import (
    SYSTEM_EFFECTIVENESS_ASSESSMENT,
    SYSTEM_PATTERN_UPDATE,
    SYSTEM_RETEST_SELECTION,
    SYSTEM_VALIDATION_REPORT,
    EffectivenessAssessmentOutput,
    PatternUpdateOutput,
    RetestSelectionOutput,
    ValidationReportOutput,
)
from shieldops.agents.adversarial_validation.tools import (
    AdversarialValidationToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AdversarialValidationToolkit | None = None


def set_toolkit(toolkit: AdversarialValidationToolkit) -> None:
    """Inject the toolkit instance used by all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> AdversarialValidationToolkit:
    if _toolkit is None:
        return AdversarialValidationToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# ------------------------------------------------------------------
# Node 1: collect_findings
# ------------------------------------------------------------------
async def collect_findings(
    state: AdversarialValidationState,
) -> dict[str, Any]:
    """Collect red-team findings that have been addressed by blue team."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "adversarial_validation.collect_findings",
        tenant_id=state.tenant_id,
    )

    findings = await toolkit.collect_red_team_findings(state.tenant_id)

    return {
        "red_team_findings": findings,
        "stage": ValidationStage.SELECT_RETESTS,
        "reasoning_chain": [
            f"Collected {len(findings)} red-team findings with blue-team "
            f"fixes for tenant {state.tenant_id}"
        ],
        "current_step": "collect_findings",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node 2: select_retests
# ------------------------------------------------------------------
async def select_retests(
    state: AdversarialValidationState,
) -> dict[str, Any]:
    """Use LLM to prioritize which findings to retest."""
    logger.info(
        "adversarial_validation.select_retests",
        finding_count=len(state.red_team_findings),
    )

    context_lines = [
        "## Red-Team Findings Awaiting Revalidation",
    ]
    for f in state.red_team_findings:
        context_lines.append(
            f"- {f.id}: {f.technique_name} ({f.technique_id}) "
            f"target={f.target} severity={f.severity} "
            f"fix={f.blue_team_fix_id}"
        )

    user_prompt = "\n".join(context_lines)

    selected_ids: list[str] = []
    rationale = ""
    try:
        result = cast(
            RetestSelectionOutput,
            await llm_structured(
                system_prompt=SYSTEM_RETEST_SELECTION,
                user_prompt=user_prompt,
                schema=RetestSelectionOutput,
            ),
        )
        selected_ids = result.selected_finding_ids
        rationale = result.prioritization_rationale
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="select_retests",
            error=str(exc),
        )
        # Fallback: select all findings, prioritize by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            state.red_team_findings,
            key=lambda f: severity_order.get(f.severity, 9),
        )
        selected_ids = [f.id for f in sorted_findings]
        rationale = "Fallback: all findings selected, ordered by severity"

    # Filter to selected findings
    selected_findings = [f for f in state.red_team_findings if f.id in selected_ids]
    # If LLM returned IDs we don't recognize, keep all findings
    if not selected_findings:
        selected_findings = list(state.red_team_findings)

    chain_entry = (
        f"Selected {len(selected_findings)}/{len(state.red_team_findings)} "
        f"findings for retest. {rationale[:120]}"
    )

    return {
        "red_team_findings": selected_findings,
        "stage": ValidationStage.EXECUTE_VALIDATION,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "select_retests",
    }


# ------------------------------------------------------------------
# Node 3: execute_validation
# ------------------------------------------------------------------
async def execute_validation(
    state: AdversarialValidationState,
) -> dict[str, Any]:
    """Re-run attacks against patched defenses."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "adversarial_validation.execute_validation",
        finding_count=len(state.red_team_findings),
    )

    tests = await toolkit.execute_validation_tests(state.red_team_findings)

    blocked = sum(
        1 for t in tests if t.outcome in (ValidationOutcome.BLOCKED, ValidationOutcome.DETECTED)
    )
    bypassed = sum(1 for t in tests if t.outcome == ValidationOutcome.BYPASSED)

    chain_entry = (
        f"Executed {len(tests)} validation tests: "
        f"{blocked} blocked/detected, {bypassed} bypassed "
        f"in {_elapsed_ms(start)}ms"
    )

    return {
        "validation_tests": tests,
        "stage": ValidationStage.ASSESS_EFFECTIVENESS,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "execute_validation",
    }


# ------------------------------------------------------------------
# Node 4: assess_effectiveness
# ------------------------------------------------------------------
async def assess_effectiveness(
    state: AdversarialValidationState,
) -> dict[str, Any]:
    """Assess per-defense-type effectiveness using toolkit + LLM."""
    toolkit = _get_toolkit()

    logger.info(
        "adversarial_validation.assess_effectiveness",
        test_count=len(state.validation_tests),
    )

    # Toolkit provides the quantitative scores
    scores = await toolkit.assess_defense_effectiveness(state.validation_tests)

    # LLM enriches with analysis
    context_lines = ["## Validation Test Results"]
    for t in state.validation_tests:
        context_lines.append(
            f"- {t.id}: technique={t.technique_id} target={t.target} "
            f"defense={t.defense_type.value} outcome={t.outcome.value} "
            f"confidence={t.confidence}"
        )
    context_lines.append("\n## Computed Effectiveness Scores")
    for s in scores:
        context_lines.append(
            f"- {s.defense_type.value}: {s.effectiveness_pct}% "
            f"({s.tests_blocked}/{s.tests_run}) "
            f"regression={s.regression_detected}"
        )

    user_prompt = "\n".join(context_lines)

    try:
        result = cast(
            EffectivenessAssessmentOutput,
            await llm_structured(
                system_prompt=SYSTEM_EFFECTIVENESS_ASSESSMENT,
                user_prompt=user_prompt,
                schema=EffectivenessAssessmentOutput,
            ),
        )
        overall = result.overall_effectiveness_pct
        regressions_found = len(result.regressions)
        # Merge LLM recommendations into toolkit scores
        for score in scores:
            for pd in result.per_defense:
                if pd.get("defense_type") == score.defense_type.value:
                    llm_recs = pd.get("recommendations", [])
                    if isinstance(llm_recs, list):
                        score.recommendations.extend(llm_recs)
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="assess_effectiveness",
            error=str(exc),
        )
        total_run = sum(s.tests_run for s in scores)
        total_blocked = sum(s.tests_blocked for s in scores)
        overall = round((total_blocked / total_run) * 100, 1) if total_run else 0.0
        regressions_found = sum(1 for s in scores if s.regression_detected)

    chain_entry = (
        f"Defense effectiveness: {overall}% overall, "
        f"{regressions_found} regressions detected "
        f"across {len(scores)} defense types"
    )

    return {
        "effectiveness_scores": scores,
        "overall_effectiveness": overall,
        "regressions_found": regressions_found,
        "stage": ValidationStage.UPDATE_PATTERNS,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "assess_effectiveness",
    }


# ------------------------------------------------------------------
# Node 5: update_patterns
# ------------------------------------------------------------------
async def update_patterns(
    state: AdversarialValidationState,
) -> dict[str, Any]:
    """Feed results back into attack/defense pattern databases."""
    toolkit = _get_toolkit()

    logger.info(
        "adversarial_validation.update_patterns",
        regressions=state.regressions_found,
    )

    # Toolkit generates the base pattern updates
    updates = await toolkit.update_attack_defense_patterns(state.effectiveness_scores)

    # LLM enriches with additional flywheel insights
    context_lines = ["## Effectiveness Scores"]
    for s in state.effectiveness_scores:
        context_lines.append(
            f"- {s.defense_type.value}: {s.effectiveness_pct}% regression={s.regression_detected}"
        )
    context_lines.append(f"\n## Current Pattern Updates: {len(updates)}")
    for u in updates:
        context_lines.append(f"- [{u.source}] {u.pattern_type}: {u.old_pattern} → {u.new_pattern}")

    user_prompt = "\n".join(context_lines)

    try:
        result = cast(
            PatternUpdateOutput,
            await llm_structured(
                system_prompt=SYSTEM_PATTERN_UPDATE,
                user_prompt=user_prompt,
                schema=PatternUpdateOutput,
            ),
        )
        from uuid import uuid4

        for llm_update in result.updates:
            updates.append(
                PatternUpdate(
                    id=f"pu-llm-{uuid4().hex[:8]}",
                    pattern_type=llm_update.get("pattern_type", "unknown"),
                    old_pattern=llm_update.get("old_pattern", ""),
                    new_pattern=llm_update.get("new_pattern", ""),
                    source=llm_update.get("source", "validation"),
                    applied=False,
                )
            )
        flywheel_detail = result.flywheel_summary
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="update_patterns",
            error=str(exc),
        )
        flywheel_detail = f"Generated {len(updates)} pattern updates from toolkit analysis"

    chain_entry = f"Data flywheel: {len(updates)} pattern updates. {flywheel_detail[:120]}"

    return {
        "pattern_updates": updates,
        "stage": ValidationStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "update_patterns",
    }


# ------------------------------------------------------------------
# Node 6: report
# ------------------------------------------------------------------
async def report(
    state: AdversarialValidationState,
) -> dict[str, Any]:
    """Generate the final adversarial validation report."""
    logger.info(
        "adversarial_validation.report",
        findings=len(state.red_team_findings),
        tests=len(state.validation_tests),
        effectiveness=state.overall_effectiveness,
        regressions=state.regressions_found,
    )

    context_lines = [
        "## Adversarial Validation Summary",
        f"- Findings retested: {len(state.red_team_findings)}",
        f"- Validation tests: {len(state.validation_tests)}",
        f"- Overall effectiveness: {state.overall_effectiveness}%",
        f"- Regressions found: {state.regressions_found}",
        f"- Pattern updates: {len(state.pattern_updates)}",
        "",
        "## Per-Defense Effectiveness",
    ]
    for s in state.effectiveness_scores:
        context_lines.append(
            f"- {s.defense_type.value}: {s.effectiveness_pct}% "
            f"({s.tests_blocked}/{s.tests_run}) "
            f"regression={s.regression_detected}"
        )
    context_lines.append("\n## Reasoning Chain")
    for entry in state.reasoning_chain:
        context_lines.append(f"- {entry}")

    user_prompt = "\n".join(context_lines)

    try:
        result = cast(
            ValidationReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_VALIDATION_REPORT,
                user_prompt=user_prompt,
                schema=ValidationReportOutput,
            ),
        )
        report_summary = result.executive_summary
        top_recs = result.top_recommendations
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="report",
            error=str(exc),
        )
        report_summary = (
            f"Adversarial validation complete: "
            f"{state.overall_effectiveness}% effective, "
            f"{state.regressions_found} regressions, "
            f"{len(state.pattern_updates)} flywheel updates."
        )
        top_recs = []
        for s in state.effectiveness_scores:
            top_recs.extend(s.recommendations)

    session_duration = 0
    if state.session_start:
        session_duration = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    stats = {
        "findings_retested": len(state.red_team_findings),
        "validation_tests": len(state.validation_tests),
        "overall_effectiveness_pct": state.overall_effectiveness,
        "regressions_found": state.regressions_found,
        "pattern_updates": len(state.pattern_updates),
        "top_recommendations": top_recs[:5],
        "report_summary": report_summary[:500],
    }

    chain_entry = (
        f"Report generated: {state.overall_effectiveness}% effective, "
        f"{state.regressions_found} regressions, "
        f"{len(state.pattern_updates)} flywheel updates"
    )

    return {
        "stats": stats,
        "stage": ValidationStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "complete",
        "session_duration_ms": session_duration,
    }
