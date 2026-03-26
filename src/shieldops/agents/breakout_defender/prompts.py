"""LLM prompt templates and response schemas for the Breakout Defender Agent."""

from pydantic import BaseModel, Field


class InitialAccessOutput(BaseModel):
    """Structured output for initial access detection."""

    phase_detected: str = Field(
        description="Kill chain phase: initial_access, "
        "privilege_escalation, lateral_movement, "
        "data_staging, exfiltration",
    )
    confidence: float = Field(
        description="Detection confidence 0.0-1.0",
    )
    mitre_techniques: list[str] = Field(
        description="MITRE ATT&CK technique IDs",
    )
    reasoning: str = Field(
        description="Analysis reasoning",
    )


class BreakoutRiskOutput(BaseModel):
    """Structured output for breakout risk assessment."""

    risk_score: float = Field(
        description="Breakout risk score 0-100",
    )
    estimated_breakout_minutes: float = Field(
        description="Estimated time to breakout in minutes",
    )
    auto_contain: bool = Field(
        description="Whether to auto-contain without approval",
    )
    containment_actions: list[dict[str, str]] = Field(
        description="Recommended containment actions",
    )
    reasoning: str = Field(
        description="Risk assessment reasoning",
    )


class ContainmentVerifyOutput(BaseModel):
    """Structured output for containment verification."""

    verified: bool = Field(
        description="Whether containment is verified effective",
    )
    residual_risk: float = Field(
        description="Residual risk score 0-100 after containment",
    )
    gaps: list[str] = Field(
        description="Any containment gaps identified",
    )
    reasoning: str = Field(
        description="Verification reasoning",
    )


SYSTEM_DETECT = """\
You are an expert eCrime breakout detection analyst. \
Your mission is to detect initial access attempts and \
classify them into kill chain phases in under 60 seconds.

Given the incoming security signals:
1. Identify the kill chain phase (initial_access, \
privilege_escalation, lateral_movement, data_staging, \
exfiltration)
2. Map signals to MITRE ATT&CK techniques
3. Assess detection confidence
4. Flag cross-cloud pivot indicators

CrowdStrike reports 29-minute average breakout time. \
We must detect and respond in under 5 minutes."""


SYSTEM_ASSESS_RISK = """\
You are an expert breakout risk assessor. Evaluate the \
risk of an active breakout attempt and recommend \
containment strategy.

Given signals, lateral movement paths, and current phase:
1. Score breakout risk (0-100)
2. Estimate time to full breakout in minutes
3. Determine if auto-containment is warranted \
(confidence > 0.85 = auto-contain, 0.5-0.85 = approval, \
< 0.5 = monitor)
4. Recommend specific containment actions

Prioritize speed over perfection. A missed containment \
window is worse than a false positive."""


SYSTEM_VERIFY = """\
You are an expert containment verification analyst. \
Verify that containment actions have effectively \
stopped the breakout attempt.

Given the containment orders executed and current state:
1. Verify each containment action succeeded
2. Identify any residual risk or bypass vectors
3. Check for persistence mechanisms
4. Assess whether the attacker can re-establish access

Be thorough — attackers often have backup access paths."""
