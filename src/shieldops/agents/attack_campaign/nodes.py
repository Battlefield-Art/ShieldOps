"""Node implementations for the Attack Campaign Agent LangGraph workflow."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.attack_campaign.models import (
    AttackCampaignState,
    CampaignStage,
    ReasoningStep,
    SimulationStep,
    TTPSelection,
)
from shieldops.agents.attack_campaign.prompts import (
    SYSTEM_CAMPAIGN_PLANNING,
    SYSTEM_CAMPAIGN_REPORT,
    SYSTEM_DEFENSE_ASSESSMENT,
    SYSTEM_TTP_ANALYSIS,
    CampaignPlanOutput,
    CampaignReportOutput,
    DefenseGapOutput,
    TTPAnalysisOutput,
)
from shieldops.agents.attack_campaign.tools import (
    MAX_SIMULATION_STEPS,
    AttackCampaignToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AttackCampaignToolkit | None = None


def set_toolkit(toolkit: AttackCampaignToolkit) -> None:
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> AttackCampaignToolkit:
    if _toolkit is None:
        return AttackCampaignToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# ── Node: plan_campaign ───────────────────────────────────────────────────


async def plan_campaign(state: AttackCampaignState) -> dict[str, Any]:
    """Plan the campaign: select candidate TTPs based on target scope."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "attack_campaign.plan_campaign",
        campaign_id=state.campaign_id,
        mode=state.simulation_mode,
    )

    selections = await toolkit.plan_campaign(state.target_scope, state.simulation_mode)

    # Enhance with LLM reasoning
    context_lines = [
        "## Target Scope",
        *[f"- {k}: {v}" for k, v in state.target_scope.items()],
        "",
        f"## Simulation Mode: {state.simulation_mode}",
        "",
        "## Candidate TTPs",
        *[
            f"- {s.technique_id} ({s.technique_name}): {s.tactic}, sev={s.severity}"
            for s in selections
        ],
    ]
    user_prompt = "\n".join(context_lines)

    output_summary: str
    try:
        result = cast(
            CampaignPlanOutput,
            await llm_structured(
                system_prompt=SYSTEM_CAMPAIGN_PLANNING,
                user_prompt=user_prompt,
                schema=CampaignPlanOutput,
            ),
        )
        output_summary = (
            f"Plan ready: {len(selections)} TTPs, "
            f"sequence={len(result.attack_sequence)} steps. "
            f"{result.rationale[:120]}"
        )
    except Exception as e:
        logger.error("attack_campaign.plan_llm_failed", error=str(e))
        output_summary = f"Plan created (LLM enhancement skipped): {e}"

    step = ReasoningStep(
        step_number=1,
        action="plan_campaign",
        input_summary=f"Scope: {list(state.target_scope.keys())}, mode={state.simulation_mode}",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="toolkit.plan_campaign + llm",
    )

    return {
        "ttp_selections": selections,
        "stage": CampaignStage.SELECT_TTPS,
        "reasoning_chain": [step],
        "current_step": "plan_campaign",
        "session_start": start,
    }


# ── Node: select_ttps ────────────────────────────────────────────────────


async def select_ttps(state: AttackCampaignState) -> dict[str, Any]:
    """Refine and prioritise the TTP selections via LLM analysis."""
    start = datetime.now(UTC)

    logger.info(
        "attack_campaign.select_ttps",
        ttp_count=len(state.ttp_selections),
    )

    context_lines = [
        "## Candidate TTPs",
        *[
            f"- {t.technique_id} ({t.technique_name}): tactic={t.tactic}, "
            f"severity={t.severity}, platforms={t.platform}"
            for t in state.ttp_selections
        ],
        "",
        "## Target Scope",
        *[f"- {k}: {v}" for k, v in state.target_scope.items()],
    ]
    user_prompt = "\n".join(context_lines)

    output_summary: str
    prioritized = list(state.ttp_selections)
    try:
        result = cast(
            TTPAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_TTP_ANALYSIS,
                user_prompt=user_prompt,
                schema=TTPAnalysisOutput,
            ),
        )
        # Re-order selections by LLM priority if mapping is available
        id_to_ttp = {t.technique_id: t for t in state.ttp_selections}
        reordered: list[TTPSelection] = []
        for entry in result.prioritized_ttps:
            tid = entry.get("technique_id", "")
            if tid in id_to_ttp:
                reordered.append(id_to_ttp.pop(tid))
        # Append any remaining
        reordered.extend(id_to_ttp.values())
        prioritized = reordered

        output_summary = (
            f"Prioritized {len(prioritized)} TTPs. Gaps: {result.gaps}. {result.summary[:100]}"
        )
    except Exception as e:
        logger.error("attack_campaign.select_ttps_llm_failed", error=str(e))
        output_summary = f"TTPs kept in original order (LLM failed): {e}"

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="select_ttps",
        input_summary=f"{len(state.ttp_selections)} candidate TTPs",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="llm",
    )

    return {
        "ttp_selections": prioritized,
        "stage": CampaignStage.EXECUTE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "select_ttps",
    }


# ── Node: execute_simulation ─────────────────────────────────────────────


async def execute_simulation(state: AttackCampaignState) -> dict[str, Any]:
    """Execute simulation steps for each selected TTP (blast-radius limited)."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    target = state.target_scope.get("target", "default-target")
    mode = state.simulation_mode

    logger.info(
        "attack_campaign.execute_simulation",
        campaign_id=state.campaign_id,
        ttp_count=len(state.ttp_selections),
        mode=mode,
    )

    steps: list[SimulationStep] = []
    # Enforce blast-radius limit
    ttps_to_run = state.ttp_selections[:MAX_SIMULATION_STEPS]

    for ttp in ttps_to_run:
        sim_step = await toolkit.execute_simulation_step(
            ttp=ttp,
            target=target,
            mode=mode,
            campaign_id=state.campaign_id,
        )
        steps.append(sim_step)

    succeeded = sum(1 for s in steps if s.success)
    blocked = sum(1 for s in steps if s.blocked_by)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_simulation",
        input_summary=(f"Executing {len(ttps_to_run)} TTPs in {mode} mode against {target}"),
        output_summary=(f"Executed {len(steps)} steps: {succeeded} succeeded, {blocked} blocked"),
        duration_ms=_elapsed_ms(start),
        tool_used="toolkit.execute_simulation_step",
    )

    return {
        "simulation_steps": steps,
        "stage": CampaignStage.COLLECT_RESULTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_simulation",
    }


# ── Node: collect_results ────────────────────────────────────────────────


async def collect_results(state: AttackCampaignState) -> dict[str, Any]:
    """Aggregate and enrich simulation step results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "attack_campaign.collect_results",
        step_count=len(state.simulation_steps),
    )

    enriched = await toolkit.collect_step_results(state.simulation_steps)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_results",
        input_summary=f"Collecting results for {len(state.simulation_steps)} steps",
        output_summary=f"Collected {len(enriched)} enriched results",
        duration_ms=_elapsed_ms(start),
        tool_used="toolkit.collect_step_results",
    )

    return {
        "simulation_steps": enriched,
        "stage": CampaignStage.ASSESS_DEFENSES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_results",
    }


# ── Node: assess_defenses ────────────────────────────────────────────────


async def assess_defenses(state: AttackCampaignState) -> dict[str, Any]:
    """Evaluate defense coverage, enriched by LLM gap analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "attack_campaign.assess_defenses",
        step_count=len(state.simulation_steps),
    )

    assessments = await toolkit.assess_defense_coverage(state.simulation_steps)

    # LLM enrichment for gap analysis
    context_lines = ["## Defense Assessments"]
    for a in assessments:
        context_lines.append(
            f"- {a.ttp_id}: detection={a.detection_coverage:.0%}, "
            f"prevention={a.prevention_coverage:.0%}, "
            f"response={a.response_time_ms}ms, gaps={a.gaps}"
        )

    context_lines.append("")
    context_lines.append("## Simulation Steps")
    for s in state.simulation_steps[:30]:
        context_lines.append(
            f"- {s.ttp_id} ({s.phase}): success={s.success}, blocked_by={s.blocked_by or 'none'}"
        )

    user_prompt = "\n".join(context_lines)

    output_summary: str
    try:
        result = cast(
            DefenseGapOutput,
            await llm_structured(
                system_prompt=SYSTEM_DEFENSE_ASSESSMENT,
                user_prompt=user_prompt,
                schema=DefenseGapOutput,
            ),
        )
        # Merge LLM recommendations into assessments
        for gap in result.gaps:
            ttp_id = gap.get("ttp_id", "")
            for a in assessments:
                if a.ttp_id == ttp_id:
                    desc = gap.get("description", "")
                    if desc and desc not in a.gaps:
                        a.gaps.append(desc)

        output_summary = (
            f"Posture: {result.overall_posture}. "
            f"{len(result.gaps)} gaps, {len(result.priority_recommendations)} recs. "
            f"Weakest: {result.weakest_areas[:3]}"
        )
    except Exception as e:
        logger.error("attack_campaign.assess_defenses_llm_failed", error=str(e))
        output_summary = f"Assessment done (LLM failed): {e}"

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_defenses",
        input_summary=f"Assessing {len(assessments)} TTPs",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="toolkit.assess_defense_coverage + llm",
    )

    return {
        "defense_assessments": assessments,
        "stage": CampaignStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_defenses",
    }


# ── Node: generate_report ────────────────────────────────────────────────


async def generate_report(state: AttackCampaignState) -> dict[str, Any]:
    """Generate the final campaign result and enrich with LLM report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "attack_campaign.generate_report",
        campaign_id=state.campaign_id,
        steps=len(state.simulation_steps),
        assessments=len(state.defense_assessments),
    )

    campaign_result = await toolkit.generate_campaign_result(
        campaign_id=state.campaign_id,
        name=state.campaign_name,
        steps=state.simulation_steps,
        assessments=state.defense_assessments,
    )

    # LLM enhancement for executive report
    context_lines = [
        "## Campaign Metrics",
        f"- Total steps: {campaign_result.total_steps}",
        f"- Blocked: {campaign_result.steps_blocked}",
        f"- Succeeded: {campaign_result.steps_succeeded}",
        f"- Detection rate: {campaign_result.detection_rate:.1%}",
        f"- Prevention rate: {campaign_result.prevention_rate:.1%}",
        f"- Mean detection time: {campaign_result.mean_detection_time_ms:.0f}ms",
        "",
        "## MITRE Coverage",
        *[
            f"- {phase}: tested={data.get('tested', 0)}, blocked={data.get('blocked', 0)}"
            for phase, data in campaign_result.mitre_coverage.items()
        ],
        "",
        "## Defense Assessments",
        *[
            f"- {a.ttp_id}: gaps={a.gaps}, recs={a.recommendations}"
            for a in state.defense_assessments[:20]
        ],
    ]
    user_prompt = "\n".join(context_lines)

    output_summary: str
    try:
        result = cast(
            CampaignReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_CAMPAIGN_REPORT,
                user_prompt=user_prompt,
                schema=CampaignReportOutput,
            ),
        )
        output_summary = f"Risk: {result.risk_rating}. {result.executive_summary[:150]}"
    except Exception as e:
        logger.error("attack_campaign.report_llm_failed", error=str(e))
        output_summary = f"Report generated (LLM failed): {e}"

    session_duration = 0
    if state.session_start:
        session_duration = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=f"Generating report for campaign {state.campaign_id}",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="toolkit.generate_campaign_result + llm",
    )

    return {
        "campaign_result": campaign_result,
        "stage": CampaignStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
        "session_duration_ms": session_duration,
    }
