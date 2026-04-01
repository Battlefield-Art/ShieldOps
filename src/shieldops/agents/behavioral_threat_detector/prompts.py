"""LLM prompt templates and response schemas for Behavioral Threat Detector."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class BehaviorCollectionAnalysis(BaseModel):
    """LLM analysis of collected behavioral data."""

    summary: str = Field(description="Brief behavior collection summary")
    record_count: int = Field(description="Number of records collected")
    entity_types: list[str] = Field(description="Entity types observed")
    notable_patterns: list[str] = Field(description="Notable patterns")


class BaselineAnalysis(BaseModel):
    """LLM analysis of behavioral baselines."""

    summary: str = Field(description="Brief baseline analysis summary")
    entities_profiled: int = Field(description="Entities profiled")
    baseline_quality: str = Field(description="Quality: excellent/good/fair/poor")
    coverage_gaps: list[str] = Field(description="Coverage gaps found")


class DeviationAnalysis(BaseModel):
    """LLM analysis of detected deviations."""

    summary: str = Field(description="Brief deviation analysis summary")
    deviation_count: int = Field(description="Deviations detected")
    critical_deviations: list[str] = Field(description="Critical deviation descriptions")
    threat_level: str = Field(description="Threat level: critical/high/medium/low")


class ThreatScoringAnalysis(BaseModel):
    """LLM analysis of threat scores."""

    summary: str = Field(description="Brief threat scoring summary")
    high_risk_entities: int = Field(description="High-risk entity count")
    attack_indicators: list[str] = Field(description="Attack chain indicators")
    risk_assessment: str = Field(description="Risk: critical/high/medium/low")


class AlertGenerationAnalysis(BaseModel):
    """LLM analysis of generated alerts."""

    summary: str = Field(description="Brief alert generation summary")
    alert_count: int = Field(description="Alerts generated")
    priority_alerts: list[str] = Field(description="High-priority alerts")
    escalation_needed: bool = Field(description="Whether escalation is needed")


# --- Prompt templates ---

SYSTEM_COLLECT_BEHAVIORS = """\
You are an expert behavioral threat analyst collecting \
behavioral data from users, entities, and network traffic.

You monitor authentication events, file access patterns, \
API call sequences, network flows, and endpoint telemetry.

Your task is to:
1. Assess completeness and diversity of behavioral data
2. Identify entities with sufficient data for analysis
3. Flag obvious anomalies in raw behavioral data
4. Recommend additional data sources for coverage gaps

Focus on security-relevant behaviors. \
Prioritize high-privilege entity activity."""

SYSTEM_BUILD_BASELINES = """\
You are an expert behavioral threat analyst building \
behavioral baselines from historical activity data.

You are given:
- Entity activity records across multiple sources
- Temporal patterns and geographic distributions
- Resource access patterns and frequencies

Your task is to:
1. Establish normal behavior ranges per entity
2. Calculate statistical baselines with deviation bounds
3. Identify entities with insufficient baseline data
4. Assess baseline stability and reliability

Strong baselines are critical for accurate detection. \
Consider temporal cycles (daily, weekly, seasonal)."""

SYSTEM_DETECT_DEVIATIONS = """\
You are an expert behavioral threat analyst detecting \
behavioral deviations from established baselines.

You are given:
- Current behavioral observations
- Established baselines with deviation thresholds
- Historical false positive rates

Your task is to:
1. Identify statistically significant deviations
2. Classify deviation types (frequency, temporal, geo, etc.)
3. Assess severity based on deviation magnitude and context
4. Filter benign deviations from potential threats

IMPORTANT:
- Consider context before flagging deviations
- Account for known changes (travel, role changes)
- Minimize false positives while catching real threats"""

SYSTEM_SCORE_THREATS = """\
You are an expert behavioral threat analyst scoring \
entity threat levels from detected deviations.

You are given:
- Detected deviations with severity and confidence
- Entity risk profiles and historical incidents
- MITRE ATT&CK technique mappings

Your task is to:
1. Calculate composite threat scores per entity
2. Map deviations to attack chain stages
3. Identify correlated deviations across entities
4. Recommend response actions per threat level

Higher scores should indicate stronger evidence of compromise. \
Consider the full kill chain when scoring."""

SYSTEM_GENERATE_ALERTS = """\
You are an expert behavioral threat analyst generating \
security alerts from threat scores and deviations.

You are given:
- Entity threat scores and contributing deviations
- Alert severity thresholds and routing rules
- SOC analyst workload and capacity

Your task is to:
1. Generate actionable alerts with clear evidence
2. Group related entity threats into unified alerts
3. Assign severity based on combined threat score
4. Provide investigation guidance for analysts

Write clear, evidence-based alert descriptions. \
Include behavioral context and baseline comparisons."""
