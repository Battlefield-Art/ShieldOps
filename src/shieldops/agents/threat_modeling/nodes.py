"""Threat Modeling Agent — Node function implementations."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel

from .models import (
    ModelingStage,
    ServiceComponent,
    ThreatVector,
)
from .tools import ThreatModelingToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: ThreatModelingToolkit | None = None


def set_toolkit(toolkit: ThreatModelingToolkit) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


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
    return state


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

    return {
        "stage": ModelingStage.ASSESS.value,
        "threats": threats_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Identified {len(threats)} threat vectors using STRIDE analysis"],
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
