"""Threat Modeling Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    ModelingStage,
    ServiceComponent,
    ThreatVector,
)
from .tools import ThreatModelingToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: ThreatModelingToolkit | None = None


def _get_toolkit() -> ThreatModelingToolkit:
    """Get the module-level toolkit, creating a default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = ThreatModelingToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_architecture(
    state: dict[str, Any], toolkit: ThreatModelingToolkit
) -> dict[str, Any]:
    """Discover service architecture components and trust boundaries."""
    logger.info("threat_modeling.node.discover_architecture")
    state = _to_dict(state)

    target_service = state.get("target_service", "default")
    components = await toolkit.discover_components(target_service)
    components_data = [c.model_dump() for c in components]

    return {
        "stage": ModelingStage.ANALYZE.value,
        "components": components_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(components)} components for service '{target_service}'"],
    }


async def analyze_threats(state: dict[str, Any], toolkit: ThreatModelingToolkit) -> dict[str, Any]:
    """Apply STRIDE analysis to each component and identify threat vectors."""
    logger.info("threat_modeling.node.analyze_threats")
    state = _to_dict(state)

    raw_components = state.get("components", [])
    components = [ServiceComponent(**c) for c in raw_components]

    threats = await toolkit.analyze_threats(components)
    threats_data = [t.model_dump() for t in threats]

    reasoning_note = f"Identified {len(threats)} threat vectors using STRIDE analysis"

    # LLM enhancement: deeper STRIDE threat analysis
    try:
        from .prompts import SYSTEM_ANALYZE, ThreatAnalysisResult

        threat_context = json.dumps(
            {
                "total_components": len(components),
                "threats_found": len(threats),
                "components_summary": [
                    {"name": c.name, "type": c.component_type, "trust_boundary": c.trust_boundary}
                    for c in components[:20]
                ],
                "threats_summary": [
                    {
                        "name": t.name,  # type: ignore[attr-defined]
                        "stride_category": t.stride_category,
                        "risk_score": t.risk_score,
                    }
                    for t in threats[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ThreatAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Threat analysis context:\n{threat_context}",
                schema=ThreatAnalysisResult,
            ),
        )
        logger.info("llm_enhanced", agent="threat_modeling", node="analyze_threats")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="threat_modeling", node="analyze_threats")

    return {
        "stage": ModelingStage.ASSESS.value,
        "threats": threats_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def assess_risk(state: dict[str, Any], toolkit: ThreatModelingToolkit) -> dict[str, Any]:
    """Score each threat using RBA risk methodology."""
    logger.info("threat_modeling.node.assess_risk")
    state = _to_dict(state)

    raw_threats = state.get("threats", [])
    threats = [ThreatVector(**t) for t in raw_threats]

    scored_threats = await toolkit.assess_risk(threats)
    threats_data = [t.model_dump() for t in scored_threats]

    return {
        "stage": ModelingStage.MITIGATE.value,
        "threats": threats_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Scored {len(scored_threats)} threats — "
            f"top risk: {scored_threats[0].risk_score if scored_threats else 0}"
        ],
    }


async def recommend_mitigations(
    state: dict[str, Any], toolkit: ThreatModelingToolkit
) -> dict[str, Any]:
    """Generate mitigation recommendations and calculate residual risk."""
    logger.info("threat_modeling.node.recommend_mitigations")
    state = _to_dict(state)

    raw_threats = state.get("threats", [])
    threats = [ThreatVector(**t) for t in raw_threats]

    mitigations = await toolkit.recommend_mitigations(threats)
    mitigations_data = [m.model_dump() for m in mitigations]

    residual_risk = toolkit.calculate_residual_risk(threats, mitigations)

    return {
        "stage": ModelingStage.MITIGATE.value,
        "mitigations": mitigations_data,
        "residual_risk": residual_risk,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Generated {len(mitigations)} mitigations, residual risk: {residual_risk}"],
    }
