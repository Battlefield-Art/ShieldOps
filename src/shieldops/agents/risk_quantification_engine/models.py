"""State models for the Risk Quantification Engine Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RQEStage(StrEnum):
    """Stages of the risk quantification workflow."""

    IDENTIFY_ASSETS = "identify_assets"
    MODEL_THREATS = "model_threats"
    CALCULATE_EXPOSURE = "calculate_exposure"
    ESTIMATE_LOSS = "estimate_loss"
    PRIORITIZE_RISKS = "prioritize_risks"
    REPORT = "report"


class RiskCategory(StrEnum):
    """Categories of organizational risk."""

    OPERATIONAL = "operational"
    FINANCIAL = "financial"
    REPUTATIONAL = "reputational"
    REGULATORY = "regulatory"
    STRATEGIC = "strategic"
    TECHNOLOGY = "technology"


class RiskTolerance(StrEnum):
    """Risk tolerance levels for the organization."""

    AGGRESSIVE = "aggressive"
    MODERATE = "moderate"
    CONSERVATIVE = "conservative"
    MINIMAL = "minimal"
    ZERO = "zero"


class RiskQuantificationEngineState(BaseModel):
    """Full state for risk quantification workflow."""

    request_id: str = ""
    stage: RQEStage = RQEStage.IDENTIFY_ASSETS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    stats: dict[str, Any] = Field(
        default_factory=dict,
    )
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
