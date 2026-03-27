"""Data Intelligence Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AIClassification,
    DataDiscovery,
    DataIntelStage,
    DataLineage,
    DataRisk,
    ProtectionPlan,
    ReasoningStep,
)
from .tools import DataIntelligenceToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Discover Data
# ------------------------------------------------------------------


async def discover_data(
    state: dict[str, Any],
    toolkit: DataIntelligenceToolkit,
) -> dict[str, Any]:
    """Discover data sources across the tenant."""
    logger.info("data_intel.node.discover_data")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    sources = await toolkit.discover_data(tenant_id)
    data = [s.model_dump() for s in sources]

    note = f"Discovered {len(sources)} data sources"

    try:
        from .prompts import (
            SYSTEM_DISCOVER,
            DiscoveryInsight,
        )

        ctx = json.dumps(
            {
                "sources": [
                    {
                        "name": s.name,
                        "domain": s.domain.value,
                        "size_gb": s.size_gb,
                        "encrypted": s.encrypted,
                    }
                    for s in sources[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            DiscoveryInsight,
            await llm_structured(
                system_prompt=SYSTEM_DISCOVER,
                user_prompt=f"Data sources:\n{ctx}",
                schema=DiscoveryInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_intel",
            node="discover_data",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_intel",
            node="discover_data",
        )

    return {
        "stage": (DataIntelStage.CLASSIFY_WITH_AI.value),
        "discoveries": data,
        "total_sources": len(sources),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="discover_data",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Classify with AI
# ------------------------------------------------------------------


async def classify_with_ai(
    state: dict[str, Any],
    toolkit: DataIntelligenceToolkit,
) -> dict[str, Any]:
    """Classify data sources using AI."""
    logger.info("data_intel.node.classify_with_ai")
    state = _to_dict(state)

    sources = [DataDiscovery(**s) for s in state.get("discoveries", [])]
    classifications = await toolkit.classify_with_ai(sources)
    data = [c.model_dump() for c in classifications]

    pii = sum(1 for c in classifications if c.pii_detected)
    note = f"Classified {len(classifications)} sources, {pii} with PII"

    try:
        from .prompts import (
            SYSTEM_CLASSIFY,
            ClassificationInsight,
        )

        ctx = json.dumps(
            {
                "classifications": [
                    {
                        "id": c.data_id,
                        "sensitivity": (c.sensitivity_level),
                        "pii": c.pii_detected,
                        "frameworks": (c.regulatory_frameworks),
                    }
                    for c in classifications[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ClassificationInsight,
            await llm_structured(
                system_prompt=SYSTEM_CLASSIFY,
                user_prompt=(f"Classifications:\n{ctx}"),
                schema=ClassificationInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_intel",
            node="classify_with_ai",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_intel",
            node="classify_with_ai",
        )

    return {
        "stage": (DataIntelStage.MAP_DATA_LINEAGE.value),
        "classifications": data,
        "pii_sources": pii,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="classify_with_ai",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Map Data Lineage
# ------------------------------------------------------------------


async def map_data_lineage(
    state: dict[str, Any],
    toolkit: DataIntelligenceToolkit,
) -> dict[str, Any]:
    """Map data lineage for discovered sources."""
    logger.info("data_intel.node.map_lineage")
    state = _to_dict(state)

    sources = [DataDiscovery(**s) for s in state.get("discoveries", [])]
    lineages = await toolkit.map_lineage(sources)
    data = [lineage_item.model_dump() for lineage_item in lineages]

    cross = sum(1 for lineage_item in lineages if lineage_item.cross_border)
    note = f"Mapped {len(lineages)} lineages, {cross} cross-border"

    try:
        from .prompts import (
            SYSTEM_LINEAGE,
            LineageInsight,
        )

        ctx = json.dumps(
            {
                "lineages": [
                    {
                        "id": lineage_item.data_id,
                        "sources": lineage_item.source_systems,
                        "consumers": (lineage_item.downstream_consumers),
                        "cross_border": (lineage_item.cross_border),
                    }
                    for lineage_item in lineages[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            LineageInsight,
            await llm_structured(
                system_prompt=SYSTEM_LINEAGE,
                user_prompt=f"Lineages:\n{ctx}",
                schema=LineageInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_intel",
            node="map_lineage",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_intel",
            node="map_lineage",
        )

    return {
        "stage": (DataIntelStage.ASSESS_DATA_RISK.value),
        "lineages": data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="map_data_lineage",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Assess Data Risk
# ------------------------------------------------------------------


async def assess_data_risk(
    state: dict[str, Any],
    toolkit: DataIntelligenceToolkit,
) -> dict[str, Any]:
    """Assess data risk for each source."""
    logger.info("data_intel.node.assess_risk")
    state = _to_dict(state)

    sources = [DataDiscovery(**s) for s in state.get("discoveries", [])]
    classifications = [AIClassification(**c) for c in state.get("classifications", [])]
    lineages = [DataLineage(**lineage_item) for lineage_item in state.get("lineages", [])]

    risks = await toolkit.assess_risk(sources, classifications, lineages)
    data = [r.model_dump() for r in risks]

    high = sum(1 for r in risks if r.risk_score >= 7.0)
    note = f"Assessed {len(risks)} data risks, {high} high-risk"

    try:
        from .prompts import (
            SYSTEM_RISK,
            RiskInsight,
        )

        ctx = json.dumps(
            {
                "risks": [
                    {
                        "id": r.data_id,
                        "score": r.risk_score,
                        "exposure": r.exposure_type,
                        "gaps": r.compliance_gaps,
                    }
                    for r in risks[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RiskInsight,
            await llm_structured(
                system_prompt=SYSTEM_RISK,
                user_prompt=f"Risk data:\n{ctx}",
                schema=RiskInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_intel",
            node="assess_risk",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_intel",
            node="assess_risk",
        )

    return {
        "stage": (DataIntelStage.RECOMMEND_PROTECTION.value),
        "risks": data,
        "high_risk_count": high,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="assess_data_risk",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Recommend Protection
# ------------------------------------------------------------------


async def recommend_protection(
    state: dict[str, Any],
    toolkit: DataIntelligenceToolkit,
) -> dict[str, Any]:
    """Generate protection recommendations."""
    logger.info("data_intel.node.recommend")
    state = _to_dict(state)

    sources = [DataDiscovery(**s) for s in state.get("discoveries", [])]
    risks = [DataRisk(**r) for r in state.get("risks", [])]
    classifications = [AIClassification(**c) for c in state.get("classifications", [])]

    plans = await toolkit.recommend_protection(sources, risks, classifications)
    data = [p.model_dump() for p in plans]

    return {
        "stage": DataIntelStage.REPORT.value,
        "plans": data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="recommend_protection",
                detail=(f"Generated {len(plans)} protection plans"),
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def report(
    state: dict[str, Any],
    toolkit: DataIntelligenceToolkit,
) -> dict[str, Any]:
    """Compile the final data intelligence report."""
    logger.info("data_intel.node.report")
    state = _to_dict(state)

    total = state.get("total_sources", 0)
    high_risk = state.get("high_risk_count", 0)
    pii = state.get("pii_sources", 0)
    plans = [ProtectionPlan(**p) for p in state.get("plans", [])]

    lines = [
        "# Data Intelligence Report",
        "",
        f"**Data sources discovered:** {total}",
        f"**High risk sources:** {high_risk}",
        f"**Sources with PII:** {pii}",
        "",
        "## Protection Plans",
    ]
    sorted_plans = sorted(
        plans,
        key=lambda p: p.risk_score,
        reverse=True,
    )
    for i, p in enumerate(sorted_plans[:10], 1):
        recs = ", ".join(r.value for r in p.recommendations)
        lines.append(
            f"{i}. {p.data_name} — risk: {p.risk_score}, priority: {p.priority}, actions: {recs}"
        )

    return {
        "stage": DataIntelStage.REPORT.value,
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
