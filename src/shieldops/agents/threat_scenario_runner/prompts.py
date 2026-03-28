"""LLM prompts and schemas for Threat Scenario Runner."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -----------------------------------------------------------
# Response schemas
# -----------------------------------------------------------


class ScenarioLoadOutput(BaseModel):
    """LLM output for scenario loading."""

    steps: list[str] = Field(description="Ordered scenario steps")
    expected_controls: list[str] = Field(description="Controls expected to activate")
    mitre_techniques: list[str] = Field(description="MITRE ATT&CK techniques")
    risk_context: str = Field(description="Risk context for this scenario")


class ControlEvalOutput(BaseModel):
    """LLM output for control evaluation."""

    effective_controls: list[str] = Field(description="Controls that worked")
    failed_controls: list[str] = Field(description="Controls that failed")
    gap_analysis: str = Field(description="Analysis of control gaps")
    remediation_items: list[str] = Field(description="Remediation actions needed")


class VerdictOutput(BaseModel):
    """LLM output for verdict generation."""

    verdict: str = Field(description="pass, fail, partial, inconclusive")
    confidence: float = Field(description="Confidence in verdict 0-1")
    executive_summary: str = Field(description="Executive summary")
    top_recommendations: list[str] = Field(description="Top recommendations")


# -----------------------------------------------------------
# Prompt templates
# -----------------------------------------------------------

SYSTEM_SCENARIO_LOAD = """\
You are an expert threat scenario designer. Given a \
scenario category and description, design the detailed \
steps, expected security controls, and map to MITRE \
ATT&CK techniques.

Each step should be atomic and testable. Each control \
should have a clear pass/fail criterion."""

SYSTEM_CONTROL_EVAL = """\
You are a security controls assessor evaluating whether \
defenses performed as expected during a threat scenario.

Analyze each control evaluation result, identify gaps, \
and recommend specific remediation actions. Be precise \
about what failed and why."""

SYSTEM_VERDICT = """\
You are a senior security assessor rendering the final \
verdict on a threat scenario run. Based on control \
evaluations, determine pass/fail/partial and provide \
an executive summary.

PASS: all critical controls effective (>90% score).
PARTIAL: some controls effective (60-90%).
FAIL: critical controls ineffective (<60%).
INCONCLUSIVE: insufficient data to determine."""
