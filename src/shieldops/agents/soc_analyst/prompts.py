"""LLM prompt templates and response schemas for the SOC Analyst Agent."""

from pydantic import BaseModel, Field


class TriageOutput(BaseModel):
    """Structured output for alert triage."""

    triage_score: float = Field(description="Triage priority score 0-100")
    tier: int = Field(description="SOC tier assignment: 1, 2, or 3")
    should_suppress: bool = Field(description="Whether to suppress this alert")
    reasoning: str = Field(description="Triage reasoning")


class AttackNarrativeOutput(BaseModel):
    """Structured output for attack narrative generation."""

    narrative: str = Field(description="Human-readable attack narrative")
    mitre_techniques: list[str] = Field(description="Identified MITRE ATT&CK technique IDs")
    confidence: float = Field(description="Confidence in the narrative 0-1")
    severity: str = Field(description="Overall severity: critical/high/medium/low")


class ClassificationOutput(BaseModel):
    """Structured output for true/false positive classification."""

    classification: str = Field(
        description="Classification: true_positive, false_positive, or needs_investigation"
    )
    confidence: float = Field(description="Confidence score 0-1")
    reasoning: str = Field(description="Reasoning behind the classification")
    key_signals: list[str] = Field(
        default_factory=list,
        description="Key signals that drove the classification decision",
    )


class ContainmentOutput(BaseModel):
    """Structured output for containment recommendations."""

    recommendations: list[dict[str, str]] = Field(
        description="List of containment actions with action, target, urgency, risk_level"
    )
    auto_executable: bool = Field(description="Whether recommendations can be auto-executed")
    reasoning: str = Field(description="Containment reasoning")


SYSTEM_TRIAGE = """\
You are an expert SOC analyst performing alert triage.

Given the alert data and context, determine:
1. Triage priority score (0-100, higher = more urgent)
2. SOC tier assignment (1 = routine, 2 = complex, 3 = critical/APT)
3. Whether to suppress (obvious false positive or known benign)

Consider: alert severity, source reputation, historical patterns, asset criticality."""


SYSTEM_NARRATIVE = """\
You are an expert SOC analyst reconstructing an attack narrative.

Given the correlated events, threat intelligence, and MITRE ATT&CK mappings:
1. Build a coherent attack narrative explaining what happened
2. Identify all relevant MITRE ATT&CK techniques
3. Assess overall severity and confidence

Focus on timeline, attacker intent, and impact."""


SYSTEM_CLASSIFICATION = """\
You are an expert SOC analyst classifying an enriched alert as true positive, false positive, \
or needs_investigation.

Given the enriched alert data including threat intelligence, correlated events, and IOC matches:
1. Classify as true_positive, false_positive, or needs_investigation
2. Provide a confidence score (0-1)
3. List the key signals that drove your decision

Consider: IOC match count, threat feed hits, reputation scores, correlated event count, \
asset criticality, historical false positive rate for this alert type."""


SYSTEM_CONTAINMENT = """\
You are an expert SOC analyst recommending containment actions.

Given the attack narrative, affected assets, and threat assessment:
1. Recommend specific containment actions
2. Prioritize by urgency and risk
3. Indicate which actions can be safely automated

Follow the principle of least disruption while ensuring threat containment."""
