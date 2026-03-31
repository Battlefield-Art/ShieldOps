"""LLM prompt templates and response schemas for the
Attack Emulation Framework Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class AdversarySelectionOutput(BaseModel):
    """Structured output for adversary profile selection."""

    adversary_name: str = Field(
        description="Selected adversary group name",
    )
    tier: str = Field(
        description="Adversary tier: apt/organized_crime/hacktivist",
    )
    technique_ids: list[str] = Field(
        description="MITRE ATT&CK technique IDs to emulate",
    )
    rationale: str = Field(
        description="Selection rationale based on threat model",
    )
    confidence: float = Field(
        description="Profile selection confidence 0-1",
    )


class CampaignBuildOutput(BaseModel):
    """Structured output for campaign construction."""

    techniques: list[dict[str, str]] = Field(
        description="Ordered techniques with tactic and procedure",
    )
    estimated_duration_min: int = Field(
        description="Estimated campaign duration in minutes",
    )
    prerequisites: list[str] = Field(
        description="Environment prerequisites",
    )
    summary: str = Field(
        description="Campaign plan summary",
    )


class DetectionMeasurementOutput(BaseModel):
    """Structured output for detection measurement."""

    coverage_pct: float = Field(
        description="Detection coverage percentage",
    )
    detected_techniques: list[str] = Field(
        description="Technique IDs that were detected",
    )
    missed_techniques: list[str] = Field(
        description="Technique IDs that were missed",
    )
    avg_detection_latency_ms: float = Field(
        description="Average detection latency in ms",
    )
    summary: str = Field(
        description="Detection measurement summary",
    )


class GapAnalysisReportOutput(BaseModel):
    """Structured output for emulation gap report."""

    executive_summary: str = Field(
        description="Executive summary of emulation results",
    )
    detection_coverage: float = Field(
        description="Overall detection coverage 0-100",
    )
    critical_gaps: list[str] = Field(
        description="Critical detection gaps to address",
    )
    recommendations: list[str] = Field(
        description="Prioritized remediation recommendations",
    )
    effectiveness: str = Field(
        description="Defense effectiveness: strong/moderate/weak",
    )


# --- System prompts ---


SYSTEM_ADVERSARY_SELECTION = """\
You are an expert adversary emulation planner selecting \
threat actor profiles for purple team exercises.

Given the organization's threat model and sector:
1. Select the most relevant adversary group
2. Map their TTPs to MITRE ATT&CK techniques
3. Prioritize techniques by detection gap likelihood
4. Justify selection based on threat intelligence

Choose adversaries that stress-test the weakest \
detection layers."""


SYSTEM_CAMPAIGN_BUILD = """\
You are an expert attack emulation engineer building \
adversary campaigns from MITRE ATT&CK techniques.

Given the selected adversary and technique list:
1. Order techniques by kill chain progression
2. Define safe execution procedures per technique
3. Identify environment prerequisites
4. Estimate execution duration

Ensure procedures are safe for production-adjacent \
environments."""


SYSTEM_DETECTION_MEASUREMENT = """\
You are an expert purple team analyst measuring \
detection effectiveness against emulated attacks.

Given executed techniques and detection results:
1. Calculate detection coverage percentage
2. Measure detection latency per technique
3. Identify silent failures in detection pipelines
4. Classify detection quality (alert vs. block vs. miss)

Be rigorous — partial detections are not detections."""


SYSTEM_REPORT = """\
You are an expert purple team reporter synthesizing \
adversary emulation results for security leadership.

Given the full emulation campaign results:
1. Produce an executive summary with coverage metrics
2. Highlight critical detection gaps by kill chain stage
3. Recommend detection engineering priorities
4. Rate overall defensive effectiveness

Write for both red team leads and security \
executives."""
