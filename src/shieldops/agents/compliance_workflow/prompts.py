"""LLM prompt templates and response schemas for Compliance Workflow."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ControlIdentificationOutput(BaseModel):
    """Structured output for control identification."""

    controls: list[dict[str, str]] = Field(
        description="Controls with id, name, category, description",
    )
    reasoning: str = Field(
        description="Reasoning for control selection",
    )


class EvidenceCollectionOutput(BaseModel):
    """Structured output for evidence collection planning."""

    evidence_plan: list[dict[str, str]] = Field(
        description="Evidence items with source and description",
    )
    coverage_notes: str = Field(
        description="Notes on evidence coverage gaps",
    )


class ControlTestOutput(BaseModel):
    """Structured output for control testing results."""

    results: list[dict[str, str]] = Field(
        description="Test results with control_id, status, notes",
    )
    overall_assessment: str = Field(
        description="Overall control effectiveness assessment",
    )


class GapAnalysisOutput(BaseModel):
    """Structured output for gap analysis."""

    gaps: list[dict[str, str]] = Field(
        description="Gaps with control_id, severity, description",
    )
    risk_summary: str = Field(
        description="Overall risk summary from identified gaps",
    )


class ReportOutput(BaseModel):
    """Structured output for compliance report."""

    executive_summary: str = Field(
        description="Executive summary of compliance posture",
    )
    overall_score: float = Field(
        description="Compliance score 0-100",
    )
    recommendations: list[str] = Field(
        description="Prioritized remediation recommendations",
    )


SYSTEM_IDENTIFY_CONTROLS = """\
You are an expert compliance auditor identifying \
applicable controls for a framework.

Given the compliance framework and tenant context:
1. List all applicable controls with IDs and names
2. Categorize controls by domain
3. Assign control owners where possible

Focus on completeness — missing controls create \
audit risk."""


SYSTEM_COLLECT_EVIDENCE = """\
You are an expert compliance evidence collector \
planning evidence gathering.

Given the controls and available data sources:
1. Map each control to required evidence
2. Identify evidence sources (logs, configs, policies)
3. Flag controls lacking evidence

Automated evidence is preferred over manual."""


SYSTEM_TEST_CONTROLS = """\
You are an expert compliance tester evaluating \
control effectiveness.

Given the controls and collected evidence:
1. Assess each control against its evidence
2. Determine pass/fail/partial status
3. Document testing methodology and findings

Apply conservative judgment — partial evidence \
means partial pass."""


SYSTEM_IDENTIFY_GAPS = """\
You are an expert compliance analyst identifying \
gaps and risks.

Given the control test results:
1. Identify all failing or partially passing controls
2. Assess severity of each gap
3. Propose remediation plans with timelines

Prioritize gaps by regulatory impact."""


SYSTEM_REPORT = """\
You are an expert compliance reporter generating \
an audit summary.

Given all controls, evidence, gaps, and remediation:
1. Calculate an overall compliance score
2. Write an executive summary
3. Provide prioritized recommendations

Be direct about risks while acknowledging strengths."""
