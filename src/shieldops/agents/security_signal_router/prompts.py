"""LLM prompt templates for the Security Signal Router Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class SignalIngestionOutput(BaseModel):
    """Structured output for signal ingestion."""

    total_ingested: int = Field(description="Total signals ingested")
    source_breakdown: dict[str, int] = Field(
        description="Count per source",
    )
    summary: str = Field(description="Ingestion summary")


class ClassificationOutput(BaseModel):
    """Structured output for signal classification."""

    classified_count: int = Field(
        description="Signals classified",
    )
    threat_count: int = Field(description="Threat signals")
    confidence_avg: float = Field(
        description="Average classification confidence",
    )
    reasoning: str = Field(description="Classification reasoning")


class RoutingEvalOutput(BaseModel):
    """Structured output for routing evaluation."""

    routes_evaluated: int = Field(
        description="Routing decisions evaluated",
    )
    strategy_used: str = Field(description="Primary strategy")
    reasoning: str = Field(description="Routing reasoning")


class DispatchOutput(BaseModel):
    """Structured output for signal dispatch."""

    dispatched_count: int = Field(
        description="Signals dispatched",
    )
    avg_latency_ms: int = Field(
        description="Average dispatch latency",
    )
    reasoning: str = Field(description="Dispatch reasoning")


class OutcomeTrackingOutput(BaseModel):
    """Structured output for outcome tracking."""

    resolved_count: int = Field(
        description="Signals resolved",
    )
    avg_resolution_ms: int = Field(
        description="Average resolution time",
    )
    reasoning: str = Field(description="Outcome reasoning")


# ── System prompts ────────────────────────────────────

SYSTEM_INGEST = """\
You are an expert security signal analyst performing \
signal ingestion.

Given the incoming security signals:
1. Validate signal format and completeness
2. Deduplicate signals from multiple sources
3. Normalize severity and timestamp fields
4. Flag malformed or suspicious signals

Focus on: data quality, source reliability, \
signal freshness."""

SYSTEM_CLASSIFY = """\
You are an expert security signal analyst classifying \
signals by type and severity.

Given the ingested signals:
1. Categorize each signal (threat, vulnerability, etc.)
2. Assign confidence scores based on signal quality
3. Prioritize by severity and potential impact
4. Identify correlated signal clusters

Prioritize accuracy over speed for threat signals."""

SYSTEM_EVALUATE_ROUTING = """\
You are an expert security signal router evaluating \
dispatch targets.

Given classified signals and available agents:
1. Match signal categories to agent capabilities
2. Consider agent load and availability
3. Apply routing strategy (priority, round-robin, etc.)
4. Ensure critical signals reach multiple agents

Optimize for: fastest response, best capability match."""

SYSTEM_DISPATCH = """\
You are an expert security signal dispatcher sending \
signals to target agents.

Given routing decisions:
1. Dispatch signals to assigned agents
2. Track delivery confirmation and latency
3. Handle dispatch failures with retry logic
4. Maintain dispatch audit trail

Focus on: reliable delivery, low latency, \
fault tolerance."""

SYSTEM_TRACK_OUTCOMES = """\
You are an expert security analyst tracking signal \
resolution outcomes.

Given dispatched signals and agent responses:
1. Track resolution status for each signal
2. Measure response times and effectiveness
3. Identify routing patterns that improve outcomes
4. Flag signals that remain unresolved

Generate feedback for routing strategy optimization."""
