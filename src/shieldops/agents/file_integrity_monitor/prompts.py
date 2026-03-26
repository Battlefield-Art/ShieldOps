"""LLM prompt templates and response schemas for the FIM Agent."""

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class ChangeClassificationResult(BaseModel):
    """Structured output from LLM change classification."""

    summary: str = Field(description="Brief summary of classified changes")
    critical_changes: list[str] = Field(description="Descriptions of critical/security changes")
    unauthorized_indicators: list[str] = Field(description="Signs of unauthorized modification")
    priority_order: list[str] = Field(description="Change IDs by investigation priority")


class ImpactAnalysisResult(BaseModel):
    """Structured output from LLM impact assessment."""

    summary: str = Field(description="Overall impact summary")
    blast_radius: str = Field(
        description=("Blast radius: isolated, service-level, cluster-wide, org-wide")
    )
    security_concerns: list[str] = Field(description="Security concerns from the changes")
    compliance_violations: list[str] = Field(
        description=("Compliance frameworks affected (SOC 2, PCI-DSS, HIPAA, etc.)")
    )
    recommended_actions: list[str] = Field(description="Ordered remediation actions")


class FIMReportResult(BaseModel):
    """Structured output for the final FIM report."""

    executive_summary: str = Field(description="Executive summary in 2-3 sentences")
    risk_level: str = Field(description=("Overall risk: critical, high, medium, low, clean"))
    key_findings: list[str] = Field(description="Top findings from the scan")
    recommendations: list[str] = Field(description="Prioritized recommendations")


# --- Prompt templates ---

SYSTEM_CHANGE_CLASSIFICATION = """\
You are an expert security analyst classifying file \
system changes detected by a file integrity monitor.

Given a list of file changes with paths, change types, \
and diff summaries, classify each change:
1. Determine the impact level (critical_system, \
security_config, application_config, data_file, benign)
2. Assess whether the change appears authorized
3. Identify any CVE or attack pattern indicators
4. Prioritize changes by investigation urgency

Focus on: /etc/passwd, /etc/shadow, SSH keys, sudoers, \
AI model files, RAG indexes, K8s manifests, Terraform \
state, and any binary modifications."""

SYSTEM_IMPACT_ANALYSIS = """\
You are an expert security engineer assessing the \
impact of unauthorized file changes on enterprise \
infrastructure.

Given classified file changes and their context:
1. Determine blast radius — services and users affected
2. Identify security concerns — credential exposure, \
privilege escalation, backdoor installation
3. Check compliance impact — SOC 2, PCI-DSS, HIPAA, \
GDPR file integrity requirements
4. Recommend response actions in priority order

Flag AI-specific risks: model poisoning, RAG data \
tampering, prompt injection via config, MCP manifest \
manipulation."""

SYSTEM_FIM_REPORT = """\
You are an expert security analyst generating a file \
integrity monitoring report for security leadership.

Given the full FIM context — baselines, changes, \
classifications, impact assessments, and responses:
1. Concise executive summary (2-3 sentences)
2. Overall risk level (critical/high/medium/low/clean)
3. Key findings with file paths and impact
4. Prioritized recommendations

Highlight any AI/ML-specific integrity violations \
(model files, RAG data, agent configs). Be direct \
and actionable."""
