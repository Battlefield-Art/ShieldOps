"""Node implementations for the Exposure Management Agent."""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.exposure_management.models import (
    AssetInventory,
    AttackSurface,
    ExposureAssessment,
    ExposureManagementState,
    ExposureReasoningStep,
    ExposureSeverity,
    RemediationRecommendation,
    RiskPrioritization,
    SurfaceType,
)
from shieldops.agents.exposure_management.prompts import (
    SYSTEM_ASSESS,
    SYSTEM_DISCOVER,
    SYSTEM_PRIORITIZE,
    SYSTEM_REMEDIATE,
    ExposureAssessmentOutput,
    PrioritizationOutput,
    RemediationOutput,
    SurfaceDiscoveryOutput,
)
from shieldops.agents.exposure_management.tools import (
    ExposureManagementToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ExposureManagementToolkit | None = None


def _get_toolkit() -> ExposureManagementToolkit:
    if _toolkit is None:
        return ExposureManagementToolkit()
    return _toolkit


# ── Node: discover_attack_surface ───────────────────────


async def discover_attack_surface(
    state: ExposureManagementState,
) -> dict[str, Any]:
    """Discover attack surfaces across all surface types."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_surfaces = await toolkit.discover_surfaces(
        state.scan_config,
    )
    ai_surfaces = await toolkit.scan_ai_surfaces(
        state.scan_config,
    )
    raw_surfaces.extend(ai_surfaces)

    surfaces = [AttackSurface(**s) for s in raw_surfaces if isinstance(s, dict)]

    # Seed default surfaces when none discovered
    scope = state.scan_config.get("scope", "")
    if not surfaces and scope:
        for st in SurfaceType:
            surfaces.append(
                AttackSurface(
                    surface_id=f"sf-{st.value[:4]}-001",
                    surface_type=st.value,
                    name=f"{st.value} ({scope})",
                    risk_score=40.0,
                )
            )

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "scope": scope,
                "surfaces_found": len(surfaces),
                "surface_types": [s.surface_type for s in surfaces],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DISCOVER,
            user_prompt=(f"Surface discovery context:\n{ctx}"),
            schema=SurfaceDiscoveryOutput,
        )
        logger.info(
            "llm_enhanced",
            node="discover_attack_surface",
            ai_surfaces=getattr(llm_out, "ai_surfaces", 0),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="discover_attack_surface",
        )

    step = ExposureReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="discover_attack_surface",
        input_summary=f"Scanning scope={scope}",
        output_summary=(f"Discovered {len(surfaces)} surfaces"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="surface_scanner",
    )

    await toolkit.record_exposure_metric("surfaces_discovered", float(len(surfaces)))

    return {
        "surfaces_discovered": surfaces,
        "surface_count": len(surfaces),
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_stage": "discover_attack_surface",
        "session_start": start,
    }


# ── Node: enumerate_assets ─────────────────────────────


async def enumerate_assets(
    state: ExposureManagementState,
) -> dict[str, Any]:
    """Enumerate assets across discovered surfaces."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    surface_dicts = [s.model_dump() for s in state.surfaces_discovered]
    raw_assets = await toolkit.enumerate_assets(
        surface_dicts,
    )

    # Classify AI assets
    classified = await toolkit.classify_ai_assets(
        raw_assets,
    )
    assets = [AssetInventory(**a) for a in classified if isinstance(a, dict)]

    # Seed default assets per surface
    if not assets:
        for sf in state.surfaces_discovered:
            assets.append(
                AssetInventory(
                    asset_id=f"ast-{sf.surface_id}",
                    surface_type=sf.surface_type,
                    hostname=sf.name,
                    is_ai_asset=(sf.surface_type == SurfaceType.AI_ENDPOINT),
                    risk_score=sf.risk_score,
                )
            )

    ai_count = sum(1 for a in assets if a.is_ai_asset)

    step = ExposureReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="enumerate_assets",
        input_summary=(f"Enumerating {state.surface_count} surfaces"),
        output_summary=(f"Found {len(assets)} assets ({ai_count} AI)"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="asset_enumerator",
    )

    await toolkit.record_exposure_metric("assets_enumerated", float(len(assets)))

    return {
        "assets_enumerated": assets,
        "asset_count": len(assets),
        "ai_exposure_count": ai_count,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_stage": "enumerate_assets",
    }


# ── Node: assess_exposures ─────────────────────────────


async def assess_exposures(
    state: ExposureManagementState,
) -> dict[str, Any]:
    """Assess exposures with CVSS/EPSS scoring."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    asset_dicts = [a.model_dump() for a in state.assets_enumerated]
    raw_exposures = await toolkit.assess_exposures(
        asset_dicts,
    )

    # Map attack paths
    attack_paths = await toolkit.map_attack_paths(
        raw_exposures,
    )
    path_map = {p.get("exposure_id", ""): p for p in attack_paths if isinstance(p, dict)}

    exposures = []
    for exp in raw_exposures:
        if not isinstance(exp, dict):
            continue
        eid = exp.get("exposure_id", "")
        if eid in path_map:
            exp["attack_path"] = path_map[eid].get("path", "")
            exp["blast_radius"] = path_map[eid].get("blast_radius", "")
        exposures.append(ExposureAssessment(**exp))

    # Check CISA KEV
    exp_ids = [e.exposure_id for e in exposures]
    if exp_ids:
        kev_results = await toolkit.check_cisa_kev(
            exp_ids,
        )
        for exp in exposures:
            exp.cisa_kev = kev_results.get(exp.exposure_id, False)

    # Compute total exposure score
    scores = [e.cvss_score for e in exposures]
    total_score = round(sum(scores) / len(scores), 2) if scores else 0.0

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "assessment_id": state.assessment_id,
                "asset_count": len(asset_dicts),
                "exposures_found": len(exposures),
                "ai_assets": state.ai_exposure_count,
                "total_score": total_score,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ASSESS,
            user_prompt=(f"Exposure assessment context:\n{ctx}"),
            schema=ExposureAssessmentOutput,
        )
        if hasattr(llm_out, "risk_score") and llm_out.risk_score > 0:
            total_score = round(
                (total_score + llm_out.risk_score) / 2,
                2,
            )
        logger.info(
            "llm_enhanced",
            node="assess_exposures",
            llm_risk=getattr(llm_out, "risk_score", 0.0),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_exposures",
        )

    step = ExposureReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_exposures",
        input_summary=(f"Assessing {len(asset_dicts)} assets"),
        output_summary=(f"Found {len(exposures)} exposures, score={total_score}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="exposure_assessor",
    )

    return {
        "exposures_assessed": exposures,
        "total_exposure_score": total_score,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_stage": "assess_exposures",
    }


# ── Node: prioritize_risks ─────────────────────────────


async def prioritize_risks(
    state: ExposureManagementState,
) -> dict[str, Any]:
    """Prioritize risks using composite scoring."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    exp_dicts = [e.model_dump() for e in state.exposures_assessed]
    business_ctx = state.scan_config.get("business_context", {})
    raw_ranked = await toolkit.prioritize_risks(exp_dicts, business_ctx)

    prioritized = []
    for rank_idx, entry in enumerate(raw_ranked, 1):
        if not isinstance(entry, dict):
            continue
        entry["rank"] = rank_idx
        # Compute composite score
        epss = entry.get("epss_score", 0.0)
        cvss = entry.get("cvss_score", 0.0)
        biz = entry.get("business_impact_score", 50.0)
        kev = 100.0 if entry.get("cisa_kev") else 0.0
        composite = epss * 0.3 + cvss * 0.25 + (biz / 100) * 0.25 + (kev / 100) * 0.2
        entry["composite_score"] = round(composite * 100, 2)
        # Assign SLA
        if composite >= 0.7:
            entry["recommended_sla_hours"] = 4
        elif composite >= 0.5:
            entry["recommended_sla_hours"] = 24
        elif composite >= 0.3:
            entry["recommended_sla_hours"] = 72
        else:
            entry["recommended_sla_hours"] = 168
        prioritized.append(RiskPrioritization(**entry))

    critical = sum(
        1 for p in prioritized if p.severity in (ExposureSeverity.CRITICAL, ExposureSeverity.HIGH)
    )

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "total_risks": len(prioritized),
                "critical_high": critical,
                "top_scores": [p.composite_score for p in prioritized[:5]],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_PRIORITIZE,
            user_prompt=(f"Prioritization context:\n{ctx}"),
            schema=PrioritizationOutput,
        )
        logger.info(
            "llm_enhanced",
            node="prioritize_risks",
            top_summary=getattr(llm_out, "top_risk_summary", "")[:80],
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="prioritize_risks",
        )

    step = ExposureReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="prioritize_risks",
        input_summary=(f"Prioritizing {len(exp_dicts)} exposures"),
        output_summary=(f"Ranked {len(prioritized)} risks, critical/high={critical}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="risk_prioritizer",
    )

    return {
        "prioritized_risks": prioritized,
        "critical_count": critical,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_stage": "prioritize_risks",
    }


# ── Node: recommend_remediation ─────────────────────────


async def recommend_remediation(
    state: ExposureManagementState,
) -> dict[str, Any]:
    """Generate remediation recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    risk_dicts = [r.model_dump() for r in state.prioritized_risks]
    raw_recs = await toolkit.generate_recommendations(
        risk_dicts,
    )

    recommendations = [RemediationRecommendation(**r) for r in raw_recs if isinstance(r, dict)]

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "risk_count": len(risk_dicts),
                "critical_count": state.critical_count,
                "ai_exposures": state.ai_exposure_count,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REMEDIATE,
            user_prompt=(f"Remediation context:\n{ctx}"),
            schema=RemediationOutput,
        )
        logger.info(
            "llm_enhanced",
            node="recommend_remediation",
            quick_wins=getattr(llm_out, "quick_wins", 0),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend_remediation",
        )

    step = ExposureReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="recommend_remediation",
        input_summary=(f"Generating recommendations for {state.critical_count} critical risks"),
        output_summary=(f"Created {len(recommendations)} recommendations"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="remediation_engine",
    )

    return {
        "remediation_recommendations": recommendations,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_stage": "recommend_remediation",
    }


# ── Node: report ───────────────────────────────────────


async def report(
    state: ExposureManagementState,
) -> dict[str, Any]:
    """Finalize assessment and record metrics."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    await toolkit.record_exposure_metric("assessment_duration_ms", float(duration_ms))
    await toolkit.record_exposure_metric(
        "total_exposure_score",
        state.total_exposure_score,
    )
    await toolkit.record_exposure_metric(
        "critical_count",
        float(state.critical_count),
    )
    await toolkit.record_exposure_metric(
        "ai_exposure_count",
        float(state.ai_exposure_count),
    )

    step = ExposureReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary=(f"Finalizing assessment {state.assessment_id}"),
        output_summary=(f"Complete in {duration_ms}ms, score={state.total_exposure_score}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_stage": "complete",
    }
