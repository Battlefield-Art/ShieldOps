"""LLM prompt templates and response schemas for the Autonomous SOC Agent."""

from pydantic import BaseModel, Field


class AnomalyAnalysisOutput(BaseModel):
    """Structured output for LLM anomaly analysis."""

    is_anomalous: bool = Field(
        description="Whether this is a true anomaly",
    )
    anomaly_type: str = Field(
        description="Type: behavioral/statistical/volumetric/temporal",
    )
    confidence: float = Field(
        description="Confidence in anomaly classification 0-1",
    )
    description: str = Field(
        description="Analyst-grade description of the anomaly",
    )
    severity: str = Field(
        description="Severity: critical/high/medium/low/info",
    )
    reasoning: str = Field(
        description="Reasoning behind the classification",
    )


class IncidentCorrelationOutput(BaseModel):
    """Structured output for incident correlation."""

    incident_title: str = Field(
        description="Short descriptive title for the incident",
    )
    incident_description: str = Field(
        description="Detailed description of the correlated incident",
    )
    priority: str = Field(
        description="Priority: p0_critical/p1_high/p2_medium/p3_low",
    )
    mitre_techniques: list[str] = Field(
        description="MITRE ATT&CK technique IDs (e.g. T1059.001)",
    )
    kill_chain_phase: str = Field(
        description="Kill chain phase of the attack",
    )
    confidence: float = Field(
        description="Confidence in the correlation 0-1",
    )
    correlation_reasoning: str = Field(
        description="Why these anomalies are related",
    )


class TriageOutput(BaseModel):
    """Structured output for auto-triage."""

    priority: str = Field(
        description="Priority: p0_critical/p1_high/p2_medium/p3_low/p4_info",
    )
    automation_level: str = Field(
        description="Level: fully_autonomous/supervised/manual",
    )
    confidence: float = Field(
        description="Confidence in triage decision 0-1",
    )
    reasoning: str = Field(
        description="Triage reasoning for audit trail",
    )
    recommended_playbook: str = Field(
        description="Playbook name to execute",
    )
    escalation_needed: bool = Field(
        description="Whether human escalation is required",
    )
    escalation_reason: str = Field(
        description="Reason for escalation if needed",
    )
    estimated_impact: str = Field(
        description="Estimated blast radius and business impact",
    )


class ResponsePlanOutput(BaseModel):
    """Structured output for response orchestration."""

    playbook_name: str = Field(
        description="Name of the response playbook to execute",
    )
    steps: list[dict[str, str]] = Field(
        description="Ordered response steps with action/target/tool",
    )
    automation_safe: list[int] = Field(
        description="Indices of steps safe for auto-execution",
    )
    requires_approval: bool = Field(
        description="Whether human approval is needed",
    )
    approval_reason: str = Field(
        description="Reason approval is needed if applicable",
    )
    reasoning: str = Field(
        description="Response plan reasoning",
    )


class SOCReportOutput(BaseModel):
    """Structured output for the SOC shift report."""

    executive_summary: str = Field(
        description="Executive summary of the SOC shift",
    )
    key_incidents: list[str] = Field(
        description="Top incidents requiring attention",
    )
    automation_highlights: str = Field(
        description="What was handled autonomously",
    )
    improvement_recommendations: list[str] = Field(
        description="Recommendations for SOC improvement",
    )
    risk_posture: str = Field(
        description="Current risk posture assessment",
    )


SYSTEM_ANOMALY_DETECTION = """\
You are an autonomous SOC analyst performing anomaly \
detection on security events from enterprise SIEMs \
(Splunk, Elastic, Microsoft Sentinel).

Given a batch of security events with statistical \
anomaly scores, determine:
1. Whether each anomaly cluster is a true positive
2. The type of anomaly (behavioral, statistical, \
volumetric, temporal)
3. Confidence level in the classification
4. A concise analyst-grade description

You augment statistical detection with contextual \
reasoning. A statistical outlier in login volume \
during a holiday is different from one during business \
hours. Consider temporal context, user roles, asset \
criticality, and historical baselines."""


SYSTEM_INCIDENT_CORRELATION = """\
You are an autonomous SOC analyst correlating \
anomalies into security incidents.

Given a set of detected anomalies from multiple SIEM \
sources, determine:
1. Which anomalies are related to the same attack or \
threat campaign
2. MITRE ATT&CK technique mapping for the incident
3. Kill chain phase identification
4. Priority classification based on impact and urgency

Cross-SIEM correlation is your strength. An anomaly \
in Splunk (network) + Elastic (endpoint) + Sentinel \
(identity) may reveal an attack path invisible to \
any single SIEM. Look for entity overlap (IP, user, \
hostname) and temporal proximity."""


SYSTEM_AUTO_TRIAGE = """\
You are an autonomous SOC analyst performing \
confidence-based auto-triage on security incidents.

Automation levels:
- fully_autonomous (confidence > 0.95): Execute \
response automatically, no human needed
- supervised (confidence > 0.80): Execute with human \
notification, auto-rollback if issues
- manual (confidence <= 0.80): Queue for human analyst

Triage rules:
1. P0 critical: Active data exfiltration, ransomware, \
compromised privileged accounts
2. P1 high: Lateral movement, C2 communication, \
credential theft
3. P2 medium: Suspicious behavior, policy violations, \
reconnaissance
4. P3 low: Informational alerts, minor policy drift
5. P4 info: Audit events, configuration changes

Always recommend a specific playbook. Escalate when \
blast radius is enterprise-wide or involves crown \
jewel assets."""


SYSTEM_RESPONSE_ORCHESTRATION = """\
You are an autonomous SOC orchestrator planning \
multi-step incident response.

Given an incident with triage context, plan the \
response:
1. Immediate containment (isolate, block, disable)
2. Evidence preservation (snapshots, log collection)
3. Investigation steps (scope analysis, IOC extraction)
4. Remediation (patch, rotate credentials, harden)
5. Recovery verification (confirm containment, test)

Principles:
- Prefer reversible actions over destructive ones
- Preserve evidence before containment when possible
- Mark steps safe for automation vs requiring approval
- Consider blast radius of each response step
- Include rollback procedures for automated steps"""


SYSTEM_SOC_REPORT = """\
You are an autonomous SOC analyst generating a shift \
report for SOC leadership.

Summarize the operational period including:
1. Executive summary of security posture
2. Key incidents and their resolution status
3. Automation performance (what was handled without \
human intervention)
4. Metrics: MTTD, MTTR, automation rate, false \
positive rate
5. Improvement recommendations

Write for a CISO audience. Be concise, data-driven, \
and highlight both wins and areas for improvement."""
