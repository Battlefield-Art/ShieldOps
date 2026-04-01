"""LLM prompt templates for the Security Chaos Orchestrator Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class ExperimentPlanOutput(BaseModel):
    """Structured output for experiment planning."""

    total_experiments: int = Field(description="Total experiments planned")
    high_risk_count: int = Field(description="High-risk experiments")
    summary: str = Field(description="Planning summary")


class BlastRadiusOutput(BaseModel):
    """Structured output for blast radius definition."""

    total_services_affected: int = Field(description="Total services in blast radius")
    max_impact_pct: float = Field(description="Maximum impact percentage")
    reasoning: str = Field(description="Blast radius reasoning")


class FailureInjectionOutput(BaseModel):
    """Structured output for failure injection."""

    injections_executed: int = Field(description="Injections executed")
    failures_triggered: int = Field(description="Failures triggered")
    reasoning: str = Field(description="Injection reasoning")


class ObservationOutput(BaseModel):
    """Structured output for behavior observation."""

    anomalies_detected: int = Field(description="Anomalies detected")
    max_deviation_pct: float = Field(description="Max deviation percentage")
    reasoning: str = Field(description="Observation reasoning")


class ResilienceOutput(BaseModel):
    """Structured output for resilience analysis."""

    fragile_count: int = Field(description="Fragile services count")
    avg_recovery_ms: int = Field(description="Average recovery time ms")
    reasoning: str = Field(description="Resilience reasoning")


# ── System prompts ────────────────────────────────────

SYSTEM_PLAN_EXPERIMENTS = """\
You are an expert security chaos engineer planning experiments.

Given the target environment:
1. Identify critical security controls to test
2. Design experiments that stress failure modes
3. Prioritize by risk and business impact
4. Ensure experiments cover diverse failure types

Focus on: authentication, authorization, network isolation, \
data protection, monitoring blind spots."""

SYSTEM_DEFINE_BLAST_RADIUS = """\
You are an expert security chaos engineer defining blast radii.

Given planned experiments:
1. Map all affected services and dependencies
2. Calculate maximum impact percentage
3. Define rollback procedures for each experiment
4. Flag experiments exceeding acceptable risk thresholds

Ensure: no production data loss, quick rollback capability, \
stakeholder notification plans."""

SYSTEM_INJECT_FAILURES = """\
You are an expert security chaos engineer injecting failures.

Given approved experiments and blast radii:
1. Execute failure injections in controlled sequence
2. Monitor injection status and system responses
3. Halt if safety thresholds are breached
4. Record all injection parameters and timestamps

Safety first: always maintain rollback capability."""

SYSTEM_OBSERVE_BEHAVIOR = """\
You are an expert security chaos engineer observing behavior.

Given active failure injections:
1. Compare observed metrics against baselines
2. Detect anomalies in security control behavior
3. Measure response times and error rates
4. Identify cascading failure patterns

Focus on: deviation from baseline, unexpected behaviors, \
silent failures."""

SYSTEM_ANALYZE_RESILIENCE = """\
You are an expert security chaos engineer analyzing resilience.

Given behavior observations:
1. Assess resilience level for each tested component
2. Calculate recovery times and failure impact
3. Identify systemic weaknesses and single points of failure
4. Generate actionable remediation recommendations

Rate resilience: robust, adequate, fragile, or critical."""
