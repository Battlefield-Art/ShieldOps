"""LLM prompt templates for the Incident Prediction Model Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class SignalCollectionOutput(BaseModel):
    """Structured output for signal collection."""

    total_signals: int = Field(description="Total signals collected")
    high_severity: int = Field(description="High-severity signals")
    summary: str = Field(description="Collection summary")


class PatternAnalysisOutput(BaseModel):
    """Structured output for pattern analysis."""

    patterns_found: int = Field(description="Patterns identified")
    recurring_count: int = Field(description="Recurring patterns")
    reasoning: str = Field(description="Pattern analysis reasoning")


class PredictionBuildOutput(BaseModel):
    """Structured output for prediction building."""

    predictions_made: int = Field(description="Predictions generated")
    high_probability: int = Field(description="High-probability predictions")
    reasoning: str = Field(description="Prediction reasoning")


class ConfidenceAssessOutput(BaseModel):
    """Structured output for confidence assessment."""

    avg_confidence: float = Field(description="Average confidence score 0-1")
    high_confidence_count: int = Field(description="High-confidence predictions")
    reasoning: str = Field(description="Confidence assessment reasoning")


class PreventionOutput(BaseModel):
    """Structured output for prevention recommendations."""

    plans_created: int = Field(description="Prevention plans created")
    total_actions: int = Field(description="Total preventive actions")
    reasoning: str = Field(description="Prevention reasoning")


# ── System prompts ────────────────────────────────────

SYSTEM_COLLECT_SIGNALS = """\
You are an expert incident prediction engineer collecting \
security signals.

Given the configuration and time window:
1. Gather alerts, log anomalies, and metric spikes
2. Collect threat intelligence indicators and vulnerability data
3. Identify behavioral signals from user and service activity
4. Correlate related signals by time and entity

Focus on: signal completeness, temporal alignment, \
correlation accuracy."""

SYSTEM_ANALYZE_PATTERNS = """\
You are an expert incident prediction engineer analyzing \
historical patterns.

Given the collected signals:
1. Match current signals against historical incident patterns
2. Identify recurring patterns and their frequency
3. Calculate average impact and time-to-incident for each pattern
4. Detect emerging patterns not previously cataloged

Prioritize patterns with high historical impact and frequency."""

SYSTEM_BUILD_PREDICTIONS = """\
You are an expert incident prediction engineer building \
predictions.

Given patterns and current signals:
1. Generate incident predictions with probability scores
2. Estimate impact severity and blast radius
3. Calculate time horizon for each prediction
4. Link contributing signals to each prediction

Focus on: prediction accuracy, actionable time horizons, \
impact estimation."""

SYSTEM_ASSESS_CONFIDENCE = """\
You are an expert incident prediction engineer assessing \
prediction confidence.

Given the predictions:
1. Evaluate data quality and signal coverage
2. Assess historical accuracy of similar predictions
3. Factor in environmental changes and model drift
4. Assign confidence levels with supporting factors

Focus on: calibrated confidence, transparent reasoning, \
uncertainty quantification."""

SYSTEM_RECOMMEND_PREVENTIONS = """\
You are an expert incident prediction engineer recommending \
prevention measures.

Given predictions and confidence scores:
1. Design prevention plans for high-confidence predictions
2. Prioritize by risk reduction and implementation effort
3. Recommend automated vs manual preventive actions
4. Estimate effort and expected risk reduction

Focus on: actionability, cost-effectiveness, \
risk-based prioritization."""
