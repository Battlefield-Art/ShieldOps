"""LLM prompt templates for the Security Training Platform Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -----------------------------------------


class BaselineOutput(BaseModel):
    """Structured output for baseline assessment."""

    avg_awareness: float = Field(
        description="Average awareness score 0-100",
    )
    weakest_area: str = Field(
        description="Weakest security awareness area",
    )
    summary: str = Field(
        description="Baseline assessment summary",
    )


class CampaignDesignOutput(BaseModel):
    """Structured output for campaign design."""

    campaign_count: int = Field(
        description="Number of campaigns created",
    )
    total_users: int = Field(
        description="Total users targeted",
    )
    reasoning: str = Field(
        description="Campaign design reasoning",
    )


class SimulationOutput(BaseModel):
    """Structured output for simulation deployment."""

    click_rate: float = Field(
        description="Overall click rate 0-1",
    )
    report_rate: float = Field(
        description="Suspicious report rate 0-1",
    )
    reasoning: str = Field(
        description="Simulation analysis reasoning",
    )


class TrackingOutput(BaseModel):
    """Structured output for result tracking."""

    completion_rate: float = Field(
        description="Training completion rate 0-1",
    )
    improvement_pct: float = Field(
        description="Improvement percentage",
    )
    reasoning: str = Field(
        description="Tracking analysis reasoning",
    )


class RiskScoreOutput(BaseModel):
    """Structured output for risk scoring."""

    high_risk_count: int = Field(
        description="Number of high-risk entities",
    )
    avg_risk_score: float = Field(
        description="Average risk score 0-100",
    )
    reasoning: str = Field(
        description="Risk scoring reasoning",
    )


# -- System prompts ----------------------------------------------------

SYSTEM_BASELINE = """\
You are an expert security awareness trainer assessing \
baseline security posture.

Given the organization configuration:
1. Evaluate current security awareness levels per team
2. Identify phishing susceptibility rates
3. Assess compliance training completion gaps
4. Flag teams with no recent training history

Focus on: phishing click rates, password hygiene, \
social engineering susceptibility, compliance gaps."""

SYSTEM_CAMPAIGN = """\
You are an expert security awareness trainer designing \
training campaigns.

Given the baseline assessments:
1. Design targeted campaigns for identified weaknesses
2. Match campaign difficulty to team risk profile
3. Include phishing simulations for high-risk groups
4. Plan compliance refreshers for overdue teams

Balance training effectiveness with employee experience \
and fatigue avoidance."""

SYSTEM_SIMULATE = """\
You are an expert security awareness trainer analyzing \
simulation results.

Given the deployed simulations:
1. Analyze click-through rates and credential entry
2. Measure time-to-action for each simulation
3. Track suspicious activity reporting rates
4. Compare results against baseline metrics

Identify users who need additional training vs those \
showing improvement."""

SYSTEM_TRACK = """\
You are an expert security awareness trainer tracking \
training effectiveness.

Given the simulation and training results:
1. Calculate completion rates per team and campaign
2. Measure score improvements over baseline
3. Identify persistent high-risk behaviors
4. Track trends in security awareness metrics

Focus on actionable insights for SOC and management."""

SYSTEM_RISK = """\
You are an expert security awareness trainer scoring \
user and team risk.

Given the tracked training results:
1. Assign risk tiers based on behavior patterns
2. Weight recent performance higher than historical
3. Factor in role sensitivity and access levels
4. Recommend targeted interventions for high-risk users

Use a composite score combining click rates, training \
completion, improvement trends, and role risk."""
