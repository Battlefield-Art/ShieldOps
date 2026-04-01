"""LLM prompt templates for the Compliance Drift Monitor Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class BaselineLoadOutput(BaseModel):
    """Structured output for baseline loading."""

    total_baselines: int = Field(description="Total baselines loaded")
    frameworks_covered: int = Field(description="Frameworks covered")
    summary: str = Field(description="Loading summary")


class StateScanOutput(BaseModel):
    """Structured output for current state scan."""

    resources_scanned: int = Field(description="Resources scanned")
    controls_evaluated: int = Field(description="Controls evaluated")
    reasoning: str = Field(description="Scan reasoning")


class DriftDetectionOutput(BaseModel):
    """Structured output for drift detection."""

    drifts_found: int = Field(description="Number of drifts detected")
    critical_drifts: int = Field(description="Critical drift count")
    reasoning: str = Field(description="Drift detection reasoning")


class ImpactOutput(BaseModel):
    """Structured output for impact assessment."""

    risk_score: float = Field(description="Overall risk score 0-10")
    frameworks_at_risk: int = Field(description="Frameworks at risk")
    reasoning: str = Field(description="Impact reasoning")


class RemediationOutput(BaseModel):
    """Structured output for remediation planning."""

    plans_generated: int = Field(description="Plans generated")
    automatable: int = Field(description="Automatable remediations")
    reasoning: str = Field(description="Remediation reasoning")


# ── System prompts ────────────────────────────────────

SYSTEM_LOAD_BASELINES = """\
You are an expert compliance engineer loading compliance \
baselines.

Given the configuration:
1. Identify applicable compliance frameworks
2. Load control baselines for each framework
3. Validate baseline completeness and currency
4. Flag any stale or missing baseline controls

Focus on: framework coverage, control completeness, \
baseline freshness."""

SYSTEM_SCAN_STATE = """\
You are an expert compliance engineer scanning current \
infrastructure state.

Given the loaded baselines:
1. Scan all resources against baseline controls
2. Capture current configuration values
3. Identify resources not covered by baselines
4. Note any scan failures or access issues

Prioritize critical controls and high-risk resources."""

SYSTEM_DETECT_DRIFT = """\
You are an expert compliance engineer detecting configuration \
drift.

Given baselines and current state:
1. Compare current values against expected baselines
2. Classify drift severity by control criticality
3. Identify patterns in drift across resources
4. Flag newly introduced misconfigurations

Focus on: accuracy, severity classification, pattern \
recognition."""

SYSTEM_ASSESS_IMPACT = """\
You are an expert compliance risk analyst assessing drift \
impact.

Given detected drift findings:
1. Calculate risk scores per framework
2. Assess cumulative compliance exposure
3. Identify regulatory reporting obligations
4. Determine business impact of each drift

Prioritize by: regulatory risk, data exposure, audit \
readiness."""

SYSTEM_PLAN_REMEDIATION = """\
You are an expert compliance engineer planning remediation.

Given drift findings and impact assessments:
1. Generate remediation actions per finding
2. Identify automatable vs manual remediations
3. Prioritize by risk score and effort
4. Estimate remediation timelines

Optimize for: fastest risk reduction, automation \
opportunities, minimal disruption."""
