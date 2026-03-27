"""IT Asset Intelligence Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AssetRiskReport,
    AssetStage,
    CriticalityClassification,
    ITAsset,
    ReasoningStep,
    RiskPosture,
    SecurityPosture,
    ThreatCorrelation,
)
from .tools import ITAssetIntelligenceToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Discover Assets
# ------------------------------------------------------------------


async def discover_assets(
    state: dict[str, Any],
    toolkit: ITAssetIntelligenceToolkit,
) -> dict[str, Any]:
    """Discover IT assets across the tenant."""
    logger.info("it_asset_intel.node.discover_assets")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    assets = await toolkit.discover_assets(tenant_id)
    assets_data = [a.model_dump() for a in assets]

    note = f"Discovered {len(assets)} assets for tenant '{tenant_id}'"

    try:
        from .prompts import (
            SYSTEM_DISCOVER,
            AssetDiscoveryInsight,
        )

        ctx = json.dumps(
            {
                "total": len(assets),
                "assets": [
                    {
                        "id": a.id,
                        "category": a.category.value,
                        "managed": a.managed,
                        "os": a.os_version,
                    }
                    for a in assets[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            AssetDiscoveryInsight,
            await llm_structured(
                system_prompt=SYSTEM_DISCOVER,
                user_prompt=f"Assets:\n{ctx}",
                schema=AssetDiscoveryInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="it_asset_intel",
            node="discover_assets",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="it_asset_intel",
            node="discover_assets",
        )

    return {
        "stage": AssetStage.CLASSIFY_CRITICALITY.value,
        "assets": assets_data,
        "total_assets": len(assets),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="discover_assets",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Classify Criticality
# ------------------------------------------------------------------


async def classify_criticality(
    state: dict[str, Any],
    toolkit: ITAssetIntelligenceToolkit,
) -> dict[str, Any]:
    """Classify criticality of discovered assets."""
    logger.info("it_asset_intel.node.classify_criticality")
    state = _to_dict(state)

    raw = state.get("assets", [])
    assets = [ITAsset(**a) for a in raw]
    classifications = await toolkit.classify_criticality(assets)
    data = [c.model_dump() for c in classifications]

    note = f"Classified {len(classifications)} assets by criticality"

    try:
        from .prompts import (
            SYSTEM_CLASSIFY,
            CriticalityInsight,
        )

        ctx = json.dumps(
            {
                "classifications": [
                    {
                        "asset_id": c.asset_id,
                        "score": c.criticality_score,
                        "tier": c.tier,
                        "impact": c.business_impact,
                    }
                    for c in classifications[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            CriticalityInsight,
            await llm_structured(
                system_prompt=SYSTEM_CLASSIFY,
                user_prompt=(f"Criticality data:\n{ctx}"),
                schema=CriticalityInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="it_asset_intel",
            node="classify_criticality",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="it_asset_intel",
            node="classify_criticality",
        )

    return {
        "stage": (AssetStage.ASSESS_SECURITY_POSTURE.value),
        "classifications": data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="classify_criticality",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Assess Security Posture
# ------------------------------------------------------------------


async def assess_security_posture(
    state: dict[str, Any],
    toolkit: ITAssetIntelligenceToolkit,
) -> dict[str, Any]:
    """Assess security posture for each asset."""
    logger.info("it_asset_intel.node.assess_security_posture")
    state = _to_dict(state)

    assets = [ITAsset(**a) for a in state.get("assets", [])]
    postures = await toolkit.assess_security_posture(assets)
    data = [p.model_dump() for p in postures]

    crit = sum(1 for p in postures if p.posture == RiskPosture.CRITICAL)
    note = f"Assessed {len(postures)} postures ({crit} critical)"

    try:
        from .prompts import (
            SYSTEM_POSTURE,
            PostureInsight,
        )

        ctx = json.dumps(
            {
                "postures": [
                    {
                        "asset_id": p.asset_id,
                        "vulns": p.vulnerability_count,
                        "patch_pct": (p.patch_compliance_pct),
                        "posture": p.posture.value,
                    }
                    for p in postures[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PostureInsight,
            await llm_structured(
                system_prompt=SYSTEM_POSTURE,
                user_prompt=f"Posture data:\n{ctx}",
                schema=PostureInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="it_asset_intel",
            node="assess_security_posture",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="it_asset_intel",
            node="assess_security_posture",
        )

    return {
        "stage": (AssetStage.CORRELATE_WITH_THREATS.value),
        "postures": data,
        "critical_count": crit,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="assess_security_posture",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Correlate with Threats
# ------------------------------------------------------------------


async def correlate_with_threats(
    state: dict[str, Any],
    toolkit: ITAssetIntelligenceToolkit,
) -> dict[str, Any]:
    """Correlate assets with threat intelligence."""
    logger.info("it_asset_intel.node.correlate_with_threats")
    state = _to_dict(state)

    assets = [ITAsset(**a) for a in state.get("assets", [])]
    postures = [SecurityPosture(**p) for p in state.get("postures", [])]
    correlations = await toolkit.correlate_threats(assets, postures)
    data = [c.model_dump() for c in correlations]

    active = sum(c.active_threats for c in correlations)
    note = f"Correlated {len(correlations)} assets, {active} active threats"

    try:
        from .prompts import (
            SYSTEM_THREAT,
            ThreatInsight,
        )

        ctx = json.dumps(
            {
                "correlations": [
                    {
                        "asset_id": c.asset_id,
                        "threats": c.active_threats,
                        "surface": (c.attack_surface_score),
                        "vector": c.exposure_vector,
                    }
                    for c in correlations[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ThreatInsight,
            await llm_structured(
                system_prompt=SYSTEM_THREAT,
                user_prompt=f"Threat data:\n{ctx}",
                schema=ThreatInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="it_asset_intel",
            node="correlate_with_threats",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="it_asset_intel",
            node="correlate_with_threats",
        )

    return {
        "stage": (AssetStage.GENERATE_RISK_REPORT.value),
        "correlations": data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="correlate_with_threats",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Generate Risk Report
# ------------------------------------------------------------------


async def generate_risk_report(
    state: dict[str, Any],
    toolkit: ITAssetIntelligenceToolkit,
) -> dict[str, Any]:
    """Generate composite risk reports per asset."""
    logger.info("it_asset_intel.node.generate_risk_report")
    state = _to_dict(state)

    assets = [ITAsset(**a) for a in state.get("assets", [])]
    classifications = [CriticalityClassification(**c) for c in state.get("classifications", [])]
    postures = [SecurityPosture(**p) for p in state.get("postures", [])]
    correlations = [ThreatCorrelation(**c) for c in state.get("correlations", [])]

    reports = await toolkit.generate_risk_reports(assets, classifications, postures, correlations)
    data = [r.model_dump() for r in reports]

    return {
        "stage": AssetStage.REPORT.value,
        "risk_reports": data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="generate_risk_report",
                detail=(f"Generated {len(reports)} risk reports"),
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def report(
    state: dict[str, Any],
    toolkit: ITAssetIntelligenceToolkit,
) -> dict[str, Any]:
    """Compile the final IT asset intelligence report."""
    logger.info("it_asset_intel.node.report")
    state = _to_dict(state)

    total = state.get("total_assets", 0)
    critical = state.get("critical_count", 0)
    risk_reports = [AssetRiskReport(**r) for r in state.get("risk_reports", [])]

    lines = [
        "# IT Asset Intelligence Report",
        "",
        f"**Total assets:** {total}",
        f"**Critical postures:** {critical}",
        "",
        "## Top Risk Assets",
    ]
    sorted_reports = sorted(
        risk_reports,
        key=lambda r: r.composite_risk,
        reverse=True,
    )
    for i, r in enumerate(sorted_reports[:10], 1):
        lines.append(
            f"{i}. {r.asset_name} "
            f"({r.category.value}) — "
            f"risk: {r.composite_risk}, "
            f"posture: {r.posture.value}"
        )
        for rec in r.recommendations:
            lines.append(f"   - {rec}")

    return {
        "stage": AssetStage.REPORT.value,
        "report": "\n".join(lines),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
