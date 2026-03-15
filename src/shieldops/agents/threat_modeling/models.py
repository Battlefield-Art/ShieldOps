"""Threat Modeling Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ModelingStage(StrEnum):
    DISCOVER = "discover"
    ANALYZE = "analyze"
    ASSESS = "assess"
    MITIGATE = "mitigate"


class StrideCategory(StrEnum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class ThreatLikelihood(StrEnum):
    VERY_LIKELY = "very_likely"
    LIKELY = "likely"
    POSSIBLE = "possible"
    UNLIKELY = "unlikely"
    RARE = "rare"


class ServiceComponent(BaseModel):
    """A component within a service architecture."""

    name: str = ""
    component_type: str = ""
    trust_boundary: str = ""
    data_flows: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)


class ThreatVector(BaseModel):
    """A threat identified through STRIDE analysis."""

    id: str = ""
    stride_category: StrideCategory = StrideCategory.SPOOFING
    component: str = ""
    description: str = ""
    likelihood: ThreatLikelihood = ThreatLikelihood.POSSIBLE
    impact_score: float = Field(default=0.0, ge=0.0, le=100.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    mitre_technique: str = ""


class Mitigation(BaseModel):
    """A recommended mitigation for a specific threat."""

    threat_id: str = ""
    description: str = ""
    control_type: str = ""
    effort: str = ""
    effectiveness: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ThreatModelingState(BaseModel):
    """Main state for the Threat Modeling agent graph."""

    request_id: str = ""
    stage: ModelingStage = ModelingStage.DISCOVER

    # Target service to model
    target_service: str = ""

    # Discovered architecture components
    components: list[ServiceComponent] = Field(default_factory=list)

    # Identified threats
    threats: list[ThreatVector] = Field(default_factory=list)

    # Recommended mitigations
    mitigations: list[Mitigation] = Field(default_factory=list)

    # Residual risk after mitigations
    residual_risk: float = Field(default=0.0, ge=0.0, le=100.0)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
