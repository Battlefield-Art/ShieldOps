"""Node implementations for APT Emulator Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.apt_emulator.models import (
    APTEmulatorState,
    CampaignResult,
    EmulatorStage,
)
from shieldops.agents.apt_emulator.prompts import (
    SYSTEM_CAMPAIGN_DESIGN,
    SYSTEM_CAMPAIGN_REPORT,
    SYSTEM_RECON_ANALYSIS,
    CampaignDesignOutput,
    CampaignReportOutput,
    ReconAnalysisOutput,
)
from shieldops.agents.apt_emulator.tools import (
    APTEmulatorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: APTEmulatorToolkit | None = None


def _get_toolkit() -> APTEmulatorToolkit:
    if _toolkit is None:
        return APTEmulatorToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


def _count_results(
    results: list[Any],
    attr: str = "result",
) -> tuple[int, int]:
    """Count blocked and evaded results."""
    blocked = sum(
        1
        for r in results
        if getattr(r, attr, None) in (CampaignResult.BLOCKED, CampaignResult.DETECTED)
    )
    evaded = sum(1 for r in results if getattr(r, attr, None) == CampaignResult.EVADED)
    return blocked, evaded


# -------------------------------------------------------
# Node 1: design_campaign
# -------------------------------------------------------
async def design_campaign(
    state: APTEmulatorState,
) -> dict[str, Any]:
    """Design the APT emulation campaign."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "apt_emulator.design_campaign",
        tenant_id=state.tenant_id,
    )

    campaign = await toolkit.design_campaign(
        apt_group=state.campaign.apt_group or "APT29",
        target_env=(state.campaign.target_environment or "production"),
    )

    # LLM enrichment
    user_prompt = (
        f"APT Group: {campaign.apt_group}\n"
        f"Target: {campaign.target_environment}\n"
        f"Techniques: {', '.join(campaign.techniques)}"
    )
    try:
        result = cast(
            CampaignDesignOutput,
            await llm_structured(
                system_prompt=SYSTEM_CAMPAIGN_DESIGN,
                user_prompt=user_prompt,
                schema=CampaignDesignOutput,
            ),
        )
        campaign.techniques = result.techniques[:12]
        campaign.objectives = result.objectives[:8]
        campaign.safety_constraints = result.safety_constraints[:6]
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="design_campaign",
            error=str(exc),
        )

    return {
        "campaign": campaign,
        "stage": EmulatorStage.EXECUTE_RECON,
        "reasoning_chain": [
            f"Designed campaign '{campaign.campaign_name}'"
            f" with {len(campaign.techniques)} techniques"
        ],
        "current_step": "design_campaign",
        "session_start": start,
    }


# -------------------------------------------------------
# Node 2: execute_recon
# -------------------------------------------------------
async def execute_recon(
    state: APTEmulatorState,
) -> dict[str, Any]:
    """Execute safe reconnaissance simulation."""
    toolkit = _get_toolkit()

    logger.info(
        "apt_emulator.execute_recon",
        campaign_id=state.campaign.id,
    )

    results = await toolkit.execute_recon(state.campaign)

    # LLM analysis
    lines = ["## Recon Results"]
    for r in results:
        lines.append(f"- {r.technique_id}: {r.result.value} services={r.exposed_services}")
    user_prompt = "\n".join(lines)

    try:
        analysis = cast(
            ReconAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_RECON_ANALYSIS,
                user_prompt=user_prompt,
                schema=ReconAnalysisOutput,
            ),
        )
        risk_note = analysis.risk_assessment[:120]
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="execute_recon",
            error=str(exc),
        )
        risk_note = f"{len(results)} recon probes executed"

    blocked, evaded = _count_results(results)
    chain_entry = f"Recon: {len(results)} probes, {blocked} detected, {evaded} evaded. {risk_note}"

    return {
        "recon_results": results,
        "phases_blocked": state.phases_blocked + blocked,
        "phases_evaded": state.phases_evaded + evaded,
        "stage": EmulatorStage.SIMULATE_ACCESS,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "execute_recon",
    }


# -------------------------------------------------------
# Node 3: simulate_access
# -------------------------------------------------------
async def simulate_access(
    state: APTEmulatorState,
) -> dict[str, Any]:
    """Simulate initial access attempts."""
    toolkit = _get_toolkit()

    logger.info(
        "apt_emulator.simulate_access",
        campaign_id=state.campaign.id,
    )

    results = await toolkit.simulate_access(state.campaign)
    blocked, evaded = _count_results(results)

    chain_entry = f"Initial access: {len(results)} attempts, {blocked} blocked, {evaded} evaded"

    return {
        "access_results": results,
        "phases_blocked": state.phases_blocked + blocked,
        "phases_evaded": state.phases_evaded + evaded,
        "stage": EmulatorStage.TEST_PERSISTENCE,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "simulate_access",
    }


# -------------------------------------------------------
# Node 4: test_persistence
# -------------------------------------------------------
async def test_persistence(
    state: APTEmulatorState,
) -> dict[str, Any]:
    """Test persistence mechanism detection."""
    toolkit = _get_toolkit()

    logger.info(
        "apt_emulator.test_persistence",
        campaign_id=state.campaign.id,
    )

    results = await toolkit.test_persistence(state.campaign)
    blocked, evaded = _count_results(results)

    chain_entry = f"Persistence: {len(results)} tests, {blocked} blocked, {evaded} evaded"

    return {
        "persistence_results": results,
        "phases_blocked": state.phases_blocked + blocked,
        "phases_evaded": state.phases_evaded + evaded,
        "stage": EmulatorStage.TEST_LATERAL,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "test_persistence",
    }


# -------------------------------------------------------
# Node 5: test_lateral
# -------------------------------------------------------
async def test_lateral(
    state: APTEmulatorState,
) -> dict[str, Any]:
    """Test lateral movement detection."""
    toolkit = _get_toolkit()

    logger.info(
        "apt_emulator.test_lateral",
        campaign_id=state.campaign.id,
    )

    results = await toolkit.test_lateral_movement(state.campaign)
    blocked, evaded = _count_results(results)

    chain_entry = f"Lateral movement: {len(results)} tests, {blocked} blocked, {evaded} evaded"

    return {
        "lateral_results": results,
        "phases_blocked": state.phases_blocked + blocked,
        "phases_evaded": state.phases_evaded + evaded,
        "stage": EmulatorStage.TEST_EXFIL,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "test_lateral",
    }


# -------------------------------------------------------
# Node 6: test_exfil
# -------------------------------------------------------
async def test_exfil(
    state: APTEmulatorState,
) -> dict[str, Any]:
    """Test exfiltration detection."""
    toolkit = _get_toolkit()

    logger.info(
        "apt_emulator.test_exfil",
        campaign_id=state.campaign.id,
    )

    results = await toolkit.test_exfiltration(state.campaign)
    blocked, evaded = _count_results(results)

    chain_entry = f"Exfiltration: {len(results)} tests, {blocked} blocked, {evaded} evaded"

    return {
        "exfil_results": results,
        "phases_blocked": state.phases_blocked + blocked,
        "phases_evaded": state.phases_evaded + evaded,
        "stage": EmulatorStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "test_exfil",
    }


# -------------------------------------------------------
# Node 7: report
# -------------------------------------------------------
async def report(
    state: APTEmulatorState,
) -> dict[str, Any]:
    """Generate the final APT emulation report."""
    logger.info(
        "apt_emulator.report",
        phases_blocked=state.phases_blocked,
        phases_evaded=state.phases_evaded,
    )

    total = state.phases_blocked + state.phases_evaded
    score = round(state.phases_blocked / total * 100, 1) if total else 0.0

    lines = [
        "## APT Emulation Campaign Report",
        f"- APT Group: {state.campaign.apt_group}",
        f"- Phases blocked: {state.phases_blocked}",
        f"- Phases evaded: {state.phases_evaded}",
        f"- Defense score: {score}%",
        "",
        "## Phase Results",
    ]
    for entry in state.reasoning_chain:
        lines.append(f"- {entry}")

    user_prompt = "\n".join(lines)

    try:
        result = cast(
            CampaignReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_CAMPAIGN_REPORT,
                user_prompt=user_prompt,
                schema=CampaignReportOutput,
            ),
        )
        summary = result.executive_summary
        recs = result.top_recommendations
        grade = result.overall_grade
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="report",
            error=str(exc),
        )
        summary = (
            f"APT emulation complete: {score}% "
            f"defense score, "
            f"{state.phases_blocked} blocked, "
            f"{state.phases_evaded} evaded."
        )
        recs = []
        grade = (
            "A"
            if score >= 90
            else "B"
            if score >= 75
            else "C"
            if score >= 60
            else "D"
            if score >= 40
            else "F"
        )

    duration = 0
    if state.session_start:
        duration = _elapsed_ms(state.session_start)

    stats = {
        "campaign_name": state.campaign.campaign_name,
        "apt_group": state.campaign.apt_group,
        "phases_blocked": state.phases_blocked,
        "phases_evaded": state.phases_evaded,
        "defense_score_pct": score,
        "grade": grade,
        "summary": summary[:500],
        "recommendations": recs[:5],
    }

    chain_entry = f"Report: {score}% defense score, grade {grade}"

    return {
        "overall_score": score,
        "stats": stats,
        "stage": EmulatorStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "complete",
        "session_duration_ms": duration,
    }
