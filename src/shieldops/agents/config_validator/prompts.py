"""LLM prompt templates and response schemas for the Config Validator Agent."""

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class DriftAnalysisResult(BaseModel):
    """Structured output from LLM drift analysis."""

    summary: str = Field(description="Brief summary of detected configuration drifts")
    critical_drifts: list[str] = Field(
        description="Human-readable descriptions of critical/high drifts"
    )
    root_cause_hints: list[str] = Field(
        description="Possible explanations for how drift was introduced"
    )
    priority_order: list[str] = Field(description="Drift IDs ordered by remediation priority")


class ImpactAnalysisResult(BaseModel):
    """Structured output from LLM impact assessment."""

    summary: str = Field(description="Overall impact summary")
    blast_radius: str = Field(
        description="Blast radius estimate: isolated, service-level, cluster-wide, org-wide"
    )
    security_concerns: list[str] = Field(description="Security concerns raised by the drifts")
    compliance_violations: list[str] = Field(
        description="Compliance frameworks potentially violated (SOC 2, PCI-DSS, HIPAA, etc.)"
    )
    recommended_actions: list[str] = Field(
        description="Ordered list of recommended remediation actions"
    )


class ValidationReportResult(BaseModel):
    """Structured output for the final validation report."""

    executive_summary: str = Field(
        description="Executive summary of the validation run in 2-3 sentences"
    )
    risk_level: str = Field(description="Overall risk level: critical, high, medium, low, clean")
    key_findings: list[str] = Field(description="Top findings from the validation")
    recommendations: list[str] = Field(description="Prioritized recommendations for the team")


# --- Prompt templates ---

SYSTEM_DRIFT_ANALYSIS = """\
You are an expert infrastructure engineer analyzing configuration drift \
across Kubernetes, Terraform, Helm, Docker, and cloud IAM resources.

Your task is to analyze detected drifts and:
1. Summarize the overall drift situation
2. Highlight critical and high-severity drifts
3. Suggest root causes for how the drift was introduced
4. Prioritize drifts by remediation urgency

Focus on security-relevant drifts first, then availability, then compliance."""

SYSTEM_IMPACT_ANALYSIS = """\
You are an expert SRE assessing the impact of configuration drift \
on enterprise infrastructure.

Given the drifts and their affected resources, determine:
1. The blast radius — how many services and users are affected
2. Security concerns — does the drift weaken security controls
3. Compliance impact — which frameworks (SOC 2, PCI-DSS, HIPAA, GDPR) are affected
4. Recommended actions in priority order

Be conservative — flag potential issues even if impact is uncertain."""

SYSTEM_VALIDATION_REPORT = """\
You are an expert infrastructure security analyst generating a \
configuration validation report for engineering leadership.

Given the full validation context — snapshots, drifts, impact \
assessments, and remediation results — produce:
1. A concise executive summary (2-3 sentences)
2. An overall risk level (critical / high / medium / low / clean)
3. Key findings
4. Prioritized recommendations

Be direct and actionable. Avoid jargon where possible."""
