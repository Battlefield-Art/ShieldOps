"""Node implementations for the Risk Quantification
Platform Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.risk_quantification_platform.models import (
    RiskQuantificationState,
    RiskStage,
)
from shieldops.agents.risk_quantification_platform.prompts import (
    SYSTEM_ASSET_IDENTIFICATION,
    SYSTEM_LOSS_MODEL,
    SYSTEM_REPORT,
    SYSTEM_THREAT_ASSESSMENT,
    AssetIdentificationOutput,
    LossModelOutput,
    RiskReportOutput,
    ThreatAssessmentOutput,
)
from shieldops.agents.risk_quantification_platform.tools import (
    RiskQuantificationPlatformToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: RiskQuantificationPlatformToolkit | None = None


def _get_toolkit() -> RiskQuantificationPlatformToolkit:
    if _toolkit is None:
        return RiskQuantificationPlatformToolkit()
    return _toolkit


# ------------------------------------------------------------------
# Node: identify_assets
# ------------------------------------------------------------------


async def identify_assets(
    state: RiskQuantificationState,
) -> dict[str, Any]:
    """Discover and classify assets for FAIR analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assets = await toolkit.identify_assets(
        scope={"tenant_id": state.tenant_id},
        tenant_id=state.tenant_id,
    )

    try:
        ctx = _json.dumps(
            {"tenant_id": state.tenant_id, "existing": assets[:5]},
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ASSET_IDENTIFICATION,
            user_prompt=f"Identify assets:\n{ctx}",
            schema=AssetIdentificationOutput,
        )
        if llm_out.assets:  # type: ignore[union-attr]
            assets = [*assets, *llm_out.assets]  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="identify_assets",
            count=len(llm_out.assets),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="identify_assets")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "assets": assets,
        "assets_analyzed": len(assets),
        "stage": RiskStage.IDENTIFY_ASSETS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Identified {len(assets)} assets ({elapsed}ms)",
        ],
        "current_step": "identify_assets",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: assess_threats
# ------------------------------------------------------------------


async def assess_threats(
    state: RiskQuantificationState,
) -> dict[str, Any]:
    """Assess threats using FAIR methodology."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_threats(
        assets=state.assets,
        scope={"tenant_id": state.tenant_id},
    )

    try:
        ctx = _json.dumps(
            {"assets": state.assets[:5], "count": len(state.assets)},
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_THREAT_ASSESSMENT,
            user_prompt=f"Assess threats:\n{ctx}",
            schema=ThreatAssessmentOutput,
        )
        if llm_out.threat_scenarios:  # type: ignore[union-attr]
            assessments = [*assessments, *llm_out.threat_scenarios]  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="assess_threats",
            count=len(llm_out.threat_scenarios),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="assess_threats")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "threat_assessments": assessments,
        "stage": RiskStage.ASSESS_THREATS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Assessed {len(assessments)} threats ({elapsed}ms)",
        ],
        "current_step": "assess_threats",
    }


# ------------------------------------------------------------------
# Node: model_loss
# ------------------------------------------------------------------


async def model_loss(
    state: RiskQuantificationState,
) -> dict[str, Any]:
    """Model loss magnitude per FAIR categories."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    models = await toolkit.model_loss(
        threat_assessments=state.threat_assessments,
        assets=state.assets,
    )

    try:
        ctx = _json.dumps(
            {
                "threats": state.threat_assessments[:5],
                "assets": state.assets[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_LOSS_MODEL,
            user_prompt=f"Model losses:\n{ctx}",
            schema=LossModelOutput,
        )
        if isinstance(llm_out, LossModelOutput):
            rand_id = random.randint(1000, 9999)  # noqa: S311
            models.append(
                {
                    "id": f"llm-loss-{rand_id}",
                    "primary_loss": llm_out.primary_loss,
                    "secondary_loss": llm_out.secondary_loss,
                    "dominant_category": llm_out.dominant_category,
                    "ale": llm_out.annualized_loss_expectancy,
                }
            )
        logger.info("llm_enhanced", node="model_loss")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="model_loss")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "loss_models": models,
        "stage": RiskStage.MODEL_LOSS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Modeled {len(models)} loss scenarios ({elapsed}ms)",
        ],
        "current_step": "model_loss",
    }


# ------------------------------------------------------------------
# Node: calculate_risk
# ------------------------------------------------------------------


async def calculate_risk(
    state: RiskQuantificationState,
) -> dict[str, Any]:
    """Calculate risk scores and ALE."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scores = await toolkit.calculate_risk(
        loss_models=state.loss_models,
        threat_assessments=state.threat_assessments,
    )

    total_ale = sum(s.get("annualized_loss_expectancy", 0) for s in scores)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "risk_scores": scores,
        "total_ale": total_ale,
        "stage": RiskStage.CALCULATE_RISK,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Calculated {len(scores)} risk scores, ALE=${total_ale:,.0f} ({elapsed}ms)",
        ],
        "current_step": "calculate_risk",
    }


# ------------------------------------------------------------------
# Node: prioritize
# ------------------------------------------------------------------


async def prioritize(
    state: RiskQuantificationState,
) -> dict[str, Any]:
    """Prioritize risks by ALE."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    prioritized = await toolkit.prioritize_risks(
        risk_scores=state.risk_scores,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "prioritized_risks": prioritized,
        "stage": RiskStage.PRIORITIZE,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Prioritized {len(prioritized)} risks ({elapsed}ms)",
        ],
        "current_step": "prioritize",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: RiskQuantificationState,
) -> dict[str, Any]:
    """Generate final FAIR risk quantification report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "total_ale": state.total_ale,
        "assets_analyzed": state.assets_analyzed,
        "risk_count": len(state.risk_scores),
    }

    try:
        ctx = _json.dumps(
            {
                "total_ale": state.total_ale,
                "assets_analyzed": state.assets_analyzed,
                "prioritized_risks": state.prioritized_risks[:10],
                "loss_models": state.loss_models[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate risk report:\n{ctx}",
            schema=RiskReportOutput,
        )
        if isinstance(llm_out, RiskReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "top_risks": llm_out.top_risks,
                    "recommendations": llm_out.recommendations,
                    "risk_tier": llm_out.risk_tier,
                }
            )
        logger.info("llm_enhanced", node="generate_report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="generate_report")

    await toolkit.record_metric("total_ale", state.total_ale)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    return {
        "stats": report,
        "stage": RiskStage.REPORT,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report generated ({elapsed}ms)",
        ],
        "current_step": "complete",
    }
