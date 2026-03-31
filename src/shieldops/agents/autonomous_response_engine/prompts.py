"""LLM prompt templates and response schemas for the
Autonomous Response Engine Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class IncidentDetectionOutput(BaseModel):
    """Structured output for incident detection analysis."""

    incidents: list[dict[str, str]] = Field(
        description="Detected incidents with type and description",
    )
    indicators: list[str] = Field(
        description="Indicators of compromise extracted",
    )
    affected_assets: list[str] = Field(
        description="Assets affected by the incident",
    )
    confidence: float = Field(
        description="Detection confidence 0-1",
    )


class SeverityClassificationOutput(BaseModel):
    """Structured output for severity classification."""

    severity: str = Field(
        description="Severity: critical/high/medium/low",
    )
    business_impact: str = Field(
        description="Business impact assessment",
    )
    data_at_risk: bool = Field(
        description="Whether sensitive data is at risk",
    )
    rationale: str = Field(
        description="Classification rationale",
    )
    recommended_urgency: str = Field(
        description="Response urgency: immediate/urgent/normal",
    )


class PlaybookSelectionOutput(BaseModel):
    """Structured output for playbook selection."""

    playbook_name: str = Field(
        description="Selected playbook name",
    )
    response_actions: list[str] = Field(
        description="Ordered list of response actions",
    )
    estimated_time: int = Field(
        description="Estimated time in minutes",
    )
    requires_approval: bool = Field(
        description="Whether human approval is needed",
    )
    rationale: str = Field(
        description="Why this playbook was selected",
    )


class ResponseReportOutput(BaseModel):
    """Structured output for final response report."""

    executive_summary: str = Field(
        description="Executive summary of incident response",
    )
    threat_contained: bool = Field(
        description="Whether threat was contained",
    )
    actions_summary: list[str] = Field(
        description="Summary of actions taken",
    )
    recommendations: list[str] = Field(
        description="Post-incident recommendations",
    )
    lessons_learned: list[str] = Field(
        description="Lessons learned from the response",
    )


# --- System prompts ---


SYSTEM_DETECTION = """\
You are an expert incident detection analyst processing \
security alerts for autonomous response.

Given the alert data from security tools:
1. Identify the incident type and attack technique
2. Extract indicators of compromise (IOCs)
3. Map affected assets and potential blast radius
4. Assess detection confidence and false positive \
likelihood

Focus on actionable indicators: IP addresses, domains, \
file hashes, process names, user accounts, and \
API calls."""


SYSTEM_CLASSIFICATION = """\
You are an expert incident severity classifier for \
autonomous response orchestration.

Given the detected incident and its indicators:
1. Classify severity based on data sensitivity, \
blast radius, and attacker capability
2. Assess business impact across availability, \
integrity, and confidentiality
3. Determine whether sensitive data is at risk
4. Recommend response urgency level

Critical: active data exfil, ransomware, root compromise
High: lateral movement, privilege escalation, C2 activity
Medium: suspicious access, policy violation, anomaly
Low: reconnaissance, failed attempts, minor policy drift"""


SYSTEM_PLAYBOOK = """\
You are an expert incident response orchestrator \
selecting automated playbooks.

Given the incident classification and severity:
1. Select the most appropriate response playbook
2. Order response actions by priority and dependency
3. Determine whether human approval is required
4. Estimate execution time and rollback availability

Standard playbooks: isolate-host, block-ip, \
revoke-credentials, quarantine-file, patch-vuln, \
rollback-change, disable-account, rotate-secrets."""


SYSTEM_REPORT = """\
You are an expert incident response reporter \
synthesizing autonomous response results.

Given the full response lifecycle (detection, \
classification, playbook, execution, validation):
1. Produce an executive summary for security leadership
2. Detail all response actions and their outcomes
3. Assess whether the threat is fully contained
4. Provide post-incident recommendations and lessons

Write clearly for both SOC analysts and security \
executives."""
