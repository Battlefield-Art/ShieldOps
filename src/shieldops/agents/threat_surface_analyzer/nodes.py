"""Node implementations for the Threat Surface Analyzer LangGraph workflow.

Each node is an async function that:
1. Queries external systems via the toolkit
2. Uses the LLM to analyze and reason about data
3. Updates the TSA state with findings
4. Records its reasoning step in the audit trail
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.threat_surface_analyzer.models import (
    AssetExposure,
    ReasoningStep,
    RiskAssessment,
    RiskCategory,
    ThreatSurfaceAnalyzerState,
    TSAStage,
)
from shieldops.agents.threat_surface_analyzer.prompts import (
    SYSTEM_ASSESS_RISKS,
    SYSTEM_DISCOVER_ASSETS,
    SYSTEM_MAP_EXPOSURE,
    SYSTEM_PRIORITIZE,
    SYSTEM_RECOMMEND_MITIGATIONS,
    AssetDiscoveryAnalysis,
    ExposureMappingAnalysis,
    MitigationAnalysis,
    PrioritizationAnalysis,
    RiskAssessmentAnalysis,
)
from shieldops.agents.threat_surface_analyzer.tools import (
    ThreatSurfaceAnalyzerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit, set by runner at startup.
_toolkit: ThreatSurfaceAnalyzerToolkit | None = None


def _get_toolkit() -> ThreatSurfaceAnalyzerToolkit:
    if _toolkit is None:
        return ThreatSurfaceAnalyzerToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# ---- Node: discover_assets ----


async def discover_assets(
    state: ThreatSurfaceAnalyzerState,
) -> dict[str, Any]:
    """Discover assets across cloud, on-prem, and SaaS environments."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "tsa_discovering_assets",
        request_id=state.request_id,
    )

    environments = state.config.get("environments", ["cloud", "on_prem", "saas"])
    assets = await toolkit.discover_assets(
        tenant_id=state.tenant_id,
        environments=environments,
    )

    output_summary = f"Discovered {len(assets)} assets across {len(environments)} environments."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "assets_discovered": len(assets),
                "environments": environments,
                "asset_types": list({a.asset_type for a in assets}),
                "exposure_types": list({a.exposure_type.value for a in assets}),
            },
            default=str,
        )
        llm_result = cast(
            AssetDiscoveryAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_DISCOVER_ASSETS,
                user_prompt=f"Asset discovery results:\n{ctx}",
                schema=AssetDiscoveryAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(assets)} assets discovered."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="discover_assets",
        )

    step = ReasoningStep(
        step_number=1,
        action="discover_assets",
        input_summary=f"Scanning {len(environments)} environments for assets",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="asset_discovery",
    )

    return {
        "assets": [a.model_dump() for a in assets],
        "stage": TSAStage.MAP_EXPOSURE,
        "session_start": start,
        "reasoning_chain": [step],
        "current_step": "discover_assets",
    }


# ---- Node: map_exposure ----


async def map_exposure(
    state: ThreatSurfaceAnalyzerState,
) -> dict[str, Any]:
    """Map exposures from discovered assets to threat vectors."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assets = [AssetExposure.model_validate(a) for a in state.assets]

    logger.info(
        "tsa_mapping_exposures",
        request_id=state.request_id,
        asset_count=len(assets),
    )

    vectors = await toolkit.map_exposures(assets)

    output_summary = f"Mapped {len(assets)} assets into {len(vectors)} threat vectors."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "assets": len(assets),
                "vectors": len(vectors),
                "attack_paths": [v.attack_path for v in vectors[:5]],
                "avg_exploitability": round(
                    sum(v.exploitability for v in vectors) / max(len(vectors), 1),
                    2,
                ),
            },
            default=str,
        )
        llm_result = cast(
            ExposureMappingAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_MAP_EXPOSURE,
                user_prompt=f"Exposure mapping results:\n{ctx}",
                schema=ExposureMappingAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Surface rating: {llm_result.attack_surface_rating}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="map_exposure",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="map_exposure",
        input_summary=f"Mapping exposures from {len(assets)} assets",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="exposure_mapper",
    )

    return {
        "exposures": [v.model_dump() for v in vectors],
        "stage": TSAStage.ASSESS_RISKS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_exposure",
    }


# ---- Node: assess_risks ----


async def assess_risks(
    state: ThreatSurfaceAnalyzerState,
) -> dict[str, Any]:
    """Assess risks for each mapped threat vector."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    from shieldops.agents.threat_surface_analyzer.models import ThreatVector

    vectors = [ThreatVector.model_validate(v) for v in state.exposures]

    logger.info(
        "tsa_assessing_risks",
        request_id=state.request_id,
        vector_count=len(vectors),
    )

    assessments = await toolkit.assess_risks(vectors)

    critical = sum(1 for a in assessments if a.risk_category == RiskCategory.CRITICAL)
    high = sum(1 for a in assessments if a.risk_category == RiskCategory.HIGH)
    avg_score = round(
        sum(a.risk_score for a in assessments) / max(len(assessments), 1),
        2,
    )

    output_summary = (
        f"Assessed {len(assessments)} risks. "
        f"{critical} critical, {high} high. "
        f"Avg score: {avg_score}."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "total": len(assessments),
                "critical": critical,
                "high": high,
                "avg_score": avg_score,
                "categories": [a.risk_category.value for a in assessments],
            },
            default=str,
        )
        llm_result = cast(
            RiskAssessmentAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_ASSESS_RISKS,
                user_prompt=f"Risk assessment results:\n{ctx}",
                schema=RiskAssessmentAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Overall risk: {llm_result.overall_risk}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risks",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_risks",
        input_summary=f"Assessing risks for {len(vectors)} threat vectors",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="risk_assessor",
    )

    return {
        "risks": [a.model_dump() for a in assessments],
        "critical_count": critical,
        "high_count": high,
        "overall_risk_score": avg_score,
        "stage": TSAStage.PRIORITIZE_THREATS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_risks",
    }


# ---- Node: prioritize_threats ----


async def prioritize_threats(
    state: ThreatSurfaceAnalyzerState,
) -> dict[str, Any]:
    """Prioritize assessed threats by risk score and business impact."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = [RiskAssessment.model_validate(r) for r in state.risks]

    logger.info(
        "tsa_prioritizing_threats",
        request_id=state.request_id,
        assessment_count=len(assessments),
    )

    priorities = await toolkit.prioritize_threats(assessments)

    output_summary = (
        f"Prioritized {len(priorities)} threats. "
        f"{state.critical_count} critical, "
        f"{state.high_count} high priority."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "total": len(priorities),
                "critical": state.critical_count,
                "high": state.high_count,
                "top_scores": [p["risk_score"] for p in priorities[:5]],
            },
            default=str,
        )
        llm_result = cast(
            PrioritizationAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_PRIORITIZE,
                user_prompt=f"Threat prioritization:\n{ctx}",
                schema=PrioritizationAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {llm_result.critical_count} critical."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="prioritize_threats",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="prioritize_threats",
        input_summary=f"Prioritizing {len(assessments)} assessed threats",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="threat_prioritizer",
    )

    return {
        "priorities": priorities,
        "stage": TSAStage.RECOMMEND_MITIGATIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "prioritize_threats",
    }


# ---- Node: recommend_mitigations ----


async def recommend_mitigations(
    state: ThreatSurfaceAnalyzerState,
) -> dict[str, Any]:
    """Recommend specific mitigations for prioritized threats."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = [RiskAssessment.model_validate(r) for r in state.risks]

    logger.info(
        "tsa_recommending_mitigations",
        request_id=state.request_id,
        priority_count=len(state.priorities),
    )

    mitigations = await toolkit.recommend_mitigations(state.priorities, assessments)

    output_summary = (
        f"Recommended {len(mitigations)} mitigations for "
        f"{len(state.priorities)} prioritized threats."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "priorities": len(state.priorities),
                "mitigations": len(mitigations),
                "actions": [m.action for m in mitigations[:5]],
            },
            default=str,
        )
        llm_result = cast(
            MitigationAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_RECOMMEND_MITIGATIONS,
                user_prompt=f"Mitigation recommendations:\n{ctx}",
                schema=MitigationAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(mitigations)} mitigations."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend_mitigations",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="recommend_mitigations",
        input_summary=(f"Recommending mitigations for {len(state.priorities)} threats"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="mitigation_recommender",
    )

    return {
        "mitigations": [m.model_dump() for m in mitigations],
        "stage": TSAStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_mitigations",
    }


# ---- Node: generate_report ----


async def generate_report(
    state: ThreatSurfaceAnalyzerState,
) -> dict[str, Any]:
    """Final reporting node -- summarize the threat surface analysis."""
    start = datetime.now(UTC)

    session_duration_ms = 0
    if state.session_start:
        session_duration_ms = _elapsed_ms(state.session_start)

    output_summary = (
        f"TSA cycle complete. "
        f"{len(state.assets)} assets, "
        f"{len(state.exposures)} exposures, "
        f"{len(state.risks)} risks, "
        f"{state.critical_count} critical, "
        f"{len(state.mitigations)} mitigations. "
        f"Duration: {session_duration_ms}ms."
    )

    logger.info(
        "tsa_report",
        request_id=state.request_id,
        summary=output_summary,
    )

    report = {
        "request_id": state.request_id,
        "tenant_id": state.tenant_id,
        "assets_discovered": len(state.assets),
        "exposures_mapped": len(state.exposures),
        "risks_assessed": len(state.risks),
        "critical_count": state.critical_count,
        "high_count": state.high_count,
        "mitigations_recommended": len(state.mitigations),
        "overall_risk_score": state.overall_risk_score,
        "duration_ms": session_duration_ms,
        "summary": output_summary,
    }

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary="Generating final threat surface report",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": session_duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
