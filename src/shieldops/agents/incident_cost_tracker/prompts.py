"""LLM prompt templates and response schemas for the
Incident Cost Tracker Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class IncidentIdentificationOutput(BaseModel):
    """Structured output for incident identification."""

    incident_type: str = Field(
        description="Classification of incident type",
    )
    severity_assessment: str = Field(
        description="Severity: critical/high/medium/low",
    )
    blast_radius: list[str] = Field(
        description="Affected systems and data stores",
    )
    initial_cost_estimate_usd: float = Field(
        description="Initial cost estimate in USD",
    )
    confidence: float = Field(
        description="Assessment confidence 0-1",
    )


class DirectCostOutput(BaseModel):
    """Structured output for direct cost calculation."""

    costs: list[dict[str, float]] = Field(
        description="Itemized direct costs by category",
    )
    total_usd: float = Field(
        description="Total direct costs in USD",
    )
    major_drivers: list[str] = Field(
        description="Primary cost drivers",
    )
    summary: str = Field(
        description="Direct cost analysis summary",
    )


class IndirectCostOutput(BaseModel):
    """Structured output for indirect cost estimation."""

    costs: list[dict[str, float]] = Field(
        description="Itemized indirect costs by category",
    )
    total_usd: float = Field(
        description="Total indirect costs in USD",
    )
    reputation_impact: str = Field(
        description="Reputation impact: severe/moderate/minor",
    )
    customer_churn_estimate: float = Field(
        description="Estimated customer churn percentage",
    )
    summary: str = Field(
        description="Indirect cost analysis summary",
    )


class RegulatoryAssessmentOutput(BaseModel):
    """Structured output for regulatory exposure assessment."""

    regulations_applicable: list[str] = Field(
        description="Applicable regulations",
    )
    max_exposure_usd: float = Field(
        description="Maximum regulatory exposure in USD",
    )
    estimated_fine_usd: float = Field(
        description="Estimated likely fine in USD",
    )
    notification_required: bool = Field(
        description="Whether breach notification is required",
    )
    recommendations: list[str] = Field(
        description="Compliance action recommendations",
    )


class CostReportOutput(BaseModel):
    """Structured output for final cost report."""

    executive_summary: str = Field(
        description="Executive summary of financial impact",
    )
    grand_total_usd: float = Field(
        description="Grand total estimated cost in USD",
    )
    recommendations: list[str] = Field(
        description="Cost mitigation recommendations",
    )
    insurance_guidance: str = Field(
        description="Cyber insurance claim guidance",
    )
    risk_rating: str = Field(
        description="Financial risk: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_IDENTIFY = """\
You are an expert incident response cost analyst \
identifying and profiling security incidents.

Given the incident details:
1. Classify the incident type and severity
2. Assess the blast radius across systems and data
3. Identify key cost drivers based on incident type
4. Provide an initial cost estimate range

Consider industry benchmarks: average breach cost \
$4.45M (IBM 2023), per-record cost $165."""


SYSTEM_DIRECT = """\
You are an expert financial analyst calculating direct \
costs of security incident response.

Given the incident profile:
1. Itemize containment costs (IR team, tools, overtime)
2. Calculate forensic investigation costs
3. Estimate remediation and recovery expenses
4. Include notification and legal costs

Use industry benchmarks for cost categories. Be precise \
about assumptions."""


SYSTEM_INDIRECT = """\
You are an expert business impact analyst estimating \
indirect costs of security incidents.

Given the incident profile and direct costs:
1. Estimate business downtime revenue loss
2. Model customer churn and reputation damage
3. Calculate opportunity cost and productivity loss
4. Project long-term brand impact

Use IBM/Ponemon cost-per-record benchmarks. Account \
for industry vertical multipliers."""


SYSTEM_REGULATORY = """\
You are an expert regulatory compliance analyst assessing \
fine exposure from security incidents.

Given the incident profile and affected data:
1. Identify applicable regulations (GDPR, HIPAA, PCI, \
state laws)
2. Calculate maximum fine exposure per regulation
3. Estimate likely fine based on precedent
4. Determine notification requirements and deadlines

Be precise about jurisdictional applicability and \
notification timelines."""


SYSTEM_REPORT = """\
You are an expert incident cost reporter synthesizing \
financial impact analysis.

Given the full cost analysis (direct, indirect, \
regulatory):
1. Produce an executive summary for C-suite
2. Present the grand total with confidence intervals
3. Recommend cost mitigation strategies
4. Provide cyber insurance claim guidance

Write clearly for both CFO and CISO audiences."""
