"""LLM prompt templates and response schemas for the
Compliance Questionnaire Engine Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ControlMappingOutput(BaseModel):
    """Structured output for control mapping."""

    mappings: list[dict[str, str]] = Field(
        description="Question-to-control mappings with evidence",
    )
    unmapped_count: int = Field(
        description="Number of questions without control mapping",
    )
    frameworks_referenced: list[str] = Field(
        description="Compliance frameworks referenced",
    )
    confidence: float = Field(
        description="Overall mapping confidence 0-1",
    )


class AnswerGenerationOutput(BaseModel):
    """Structured output for answer generation."""

    answers: list[dict[str, str]] = Field(
        description="Generated answers with evidence references",
    )
    gaps_identified: int = Field(
        description="Number of gaps requiring manual review",
    )
    auto_confidence: float = Field(
        description="Average confidence of auto-generated answers",
    )
    summary: str = Field(
        description="Summary of answer generation results",
    )


class GapReviewOutput(BaseModel):
    """Structured output for gap review."""

    gaps: list[dict[str, str]] = Field(
        description="Compliance gaps with remediation suggestions",
    )
    risk_score: float = Field(
        description="Aggregate gap risk score 0-10",
    )
    priority_actions: list[str] = Field(
        description="Priority remediation actions",
    )
    summary: str = Field(
        description="Gap analysis summary",
    )


class QuestionnaireReportOutput(BaseModel):
    """Structured output for final questionnaire report."""

    executive_summary: str = Field(
        description="Executive summary of questionnaire response",
    )
    coverage_percentage: float = Field(
        description="Percentage of questions fully answered",
    )
    recommendations: list[str] = Field(
        description="Recommendations for improving compliance",
    )
    gap_summary: list[str] = Field(
        description="Summary of identified gaps",
    )
    readiness_rating: str = Field(
        description="Readiness: ready/needs_work/not_ready",
    )


# --- System prompts ---


SYSTEM_MAPPING = """\
You are an expert compliance analyst mapping questionnaire \
questions to internal security controls.

Given a compliance questionnaire and framework:
1. Map each question to relevant internal controls and \
policies
2. Identify available evidence for each mapping
3. Flag questions without adequate control coverage
4. Reference industry standards (SOC 2, ISO 27001, HIPAA)

Be precise about control references and evidence \
availability."""


SYSTEM_ANSWERS = """\
You are an expert compliance writer generating answers \
for security questionnaires.

Given mapped controls and available evidence:
1. Generate clear, accurate answers citing specific \
controls
2. Reference evidence artifacts and policy documents
3. Mark answers where evidence is insufficient
4. Use professional language appropriate for auditors

Accuracy is paramount — never fabricate evidence or \
controls."""


SYSTEM_GAPS = """\
You are an expert compliance analyst reviewing gaps in \
questionnaire coverage.

Given the gap analysis from answer generation:
1. Assess the severity of each compliance gap
2. Suggest specific remediation actions with timelines
3. Prioritize gaps by audit risk and business impact
4. Map gaps to control framework requirements

Focus on actionable recommendations with clear ownership."""


SYSTEM_REPORT = """\
You are an expert compliance reporter synthesizing \
questionnaire response results.

Given the full questionnaire (questions, answers, gaps):
1. Produce an executive summary for compliance leadership
2. Calculate overall readiness and coverage metrics
3. List prioritized recommendations for gap closure
4. Rate overall questionnaire response quality

Write clearly for both audit and executive audiences."""
