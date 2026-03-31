"""LLM prompt templates and response schemas for the
Risk Quantification Platform Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class AssetIdentificationOutput(BaseModel):
    """Structured output for asset identification."""

    assets: list[dict[str, str]] = Field(
        description="Identified assets with name, type, and criticality",
    )
    business_units: list[str] = Field(
        description="Business units covered",
    )
    data_classifications: list[str] = Field(
        description="Data classification levels found",
    )
    confidence: float = Field(
        description="Confidence in asset inventory completeness 0-1",
    )


class ThreatAssessmentOutput(BaseModel):
    """Structured output for FAIR threat assessment."""

    threat_scenarios: list[dict[str, str]] = Field(
        description="Threat scenarios with actor, type, and frequency",
    )
    vulnerability_factors: list[str] = Field(
        description="Key vulnerability factors identified",
    )
    loss_event_frequency: float = Field(
        description="Estimated annual loss event frequency",
    )
    summary: str = Field(
        description="Threat landscape summary",
    )


class LossModelOutput(BaseModel):
    """Structured output for loss magnitude modeling."""

    primary_loss: float = Field(
        description="Expected primary loss in dollars",
    )
    secondary_loss: float = Field(
        description="Expected secondary loss in dollars",
    )
    dominant_category: str = Field(
        description="Dominant FAIR loss category",
    )
    annualized_loss_expectancy: float = Field(
        description="Computed ALE in dollars",
    )
    confidence: float = Field(
        description="Model confidence 0-1",
    )


class RiskReportOutput(BaseModel):
    """Structured output for risk quantification report."""

    executive_summary: str = Field(
        description="Executive summary of cyber risk posture",
    )
    total_ale: float = Field(
        description="Total annualized loss expectancy",
    )
    top_risks: list[str] = Field(
        description="Top risk scenarios by ALE",
    )
    recommendations: list[str] = Field(
        description="Risk mitigation recommendations",
    )
    risk_tier: str = Field(
        description="Overall risk tier: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_ASSET_IDENTIFICATION = """\
You are an expert cyber risk analyst identifying \
assets for FAIR risk quantification.

Given the organization scope and asset inventory:
1. Identify critical assets by business impact
2. Classify data sensitivity levels
3. Map assets to business units and revenue streams
4. Prioritize assets by criticality for risk analysis

Focus on assets with high data sensitivity and \
regulatory exposure."""


SYSTEM_THREAT_ASSESSMENT = """\
You are an expert FAIR methodology analyst assessing \
threats against identified assets.

Given the asset inventory and threat landscape:
1. Identify threat actors and their capabilities
2. Estimate contact frequency using FAIR factors
3. Assess probability of action for each scenario
4. Calculate loss event frequency per threat-asset pair

Use evidence-based frequency estimates, not \
qualitative ratings."""


SYSTEM_LOSS_MODEL = """\
You are an expert FAIR loss magnitude modeler \
quantifying financial impact.

Given threat scenarios and asset valuations:
1. Estimate primary loss across FAIR categories
2. Model secondary loss (fines, reputation, competitive)
3. Compute annualized loss expectancy per scenario
4. Identify dominant loss drivers

Produce dollar-denominated estimates with confidence \
intervals."""


SYSTEM_REPORT = """\
You are an expert cyber risk reporter synthesizing \
FAIR quantification results.

Given the full risk analysis (assets, threats, losses):
1. Produce an executive summary for the board
2. Rank risks by annualized loss expectancy
3. Recommend risk treatments with ROI estimates
4. Classify overall organizational risk tier

Write for both CFO and CISO audiences."""
