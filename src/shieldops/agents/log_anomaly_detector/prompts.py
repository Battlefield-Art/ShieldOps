"""LLM prompt templates for the Log Anomaly Detector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class LogIngestionOutput(BaseModel):
    """Structured output for log ingestion analysis."""

    total_records: int = Field(
        description="Total log records ingested",
    )
    source_count: int = Field(
        description="Number of distinct log sources",
    )
    summary: str = Field(
        description="Ingestion summary",
    )


class PatternParseOutput(BaseModel):
    """Structured output for pattern parsing."""

    unique_patterns: int = Field(
        description="Count of unique log patterns",
    )
    new_patterns: int = Field(
        description="Count of newly seen patterns",
    )
    reasoning: str = Field(
        description="Pattern analysis reasoning",
    )


class AnomalyDetectionOutput(BaseModel):
    """Structured output for anomaly detection."""

    anomaly_count: int = Field(
        description="Total anomalies detected",
    )
    max_confidence: float = Field(
        description="Highest anomaly confidence 0-1",
    )
    reasoning: str = Field(
        description="Anomaly detection reasoning",
    )


class CorrelationOutput(BaseModel):
    """Structured output for event correlation."""

    correlations: list[dict[str, str]] = Field(
        description="Correlated events with descriptions",
    )
    strongest_correlation: float = Field(
        description="Strongest correlation score 0-1",
    )
    reasoning: str = Field(
        description="Correlation reasoning",
    )


class PrioritizationOutput(BaseModel):
    """Structured output for alert prioritization."""

    alerts: list[dict[str, str]] = Field(
        description="Prioritized alerts with actions",
    )
    critical_count: int = Field(
        description="Number of critical priority alerts",
    )
    reasoning: str = Field(
        description="Prioritization reasoning",
    )


# ── System prompts ────────────────────────────────────

SYSTEM_INGEST = """\
You are an expert log analyst performing log ingestion \
and initial assessment.

Given the log ingestion configuration:
1. Assess data quality and completeness across sources
2. Identify gaps in log coverage or missing sources
3. Evaluate time range continuity and data freshness
4. Flag any ingestion errors or dropped records

Focus on: source diversity, time coverage, data volume \
baselines, and ingestion health."""

SYSTEM_PARSE = """\
You are an expert log analyst extracting patterns from \
raw log data.

Given the ingested log batches:
1. Extract recurring message templates and patterns
2. Identify new patterns not seen in historical baselines
3. Classify patterns by source, severity, and frequency
4. Build pattern frequency distributions

Focus on: template extraction, frequency analysis, new \
pattern detection, and pattern clustering."""

SYSTEM_DETECT = """\
You are an expert log anomaly detector using ML-based \
analysis.

Given the extracted log patterns:
1. Detect frequency spikes and volume anomalies
2. Identify missing expected events and sequence breaks
3. Score anomalies by confidence and potential impact
4. Distinguish true anomalies from noise or seasonality

Use statistical methods: z-score, IQR, isolation forest, \
and sequence analysis techniques."""

SYSTEM_CORRELATE = """\
You are an expert log analyst correlating anomalous events.

Given the detected anomalies:
1. Find temporal correlations between anomaly clusters
2. Identify causal chains across log sources
3. Map anomalies to potential root causes
4. Score correlation strength and confidence

Focus on: cross-source correlation, temporal proximity, \
causal inference, and attack chain detection."""

SYSTEM_PRIORITIZE = """\
You are an expert SOC analyst prioritizing log anomaly \
alerts.

Given the correlated anomaly events:
1. Rank alerts by business impact and urgency
2. Estimate false positive likelihood for each alert
3. Recommend specific response actions per alert
4. Group related alerts to reduce alert fatigue

Balance thoroughness with actionability — minimize noise \
while ensuring critical anomalies surface immediately."""
