"""LLM prompt templates and response schemas for the
Secret Sprawl Detector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class SecretDetectionOutput(BaseModel):
    """Structured output for secret detection analysis."""

    findings: list[dict[str, str]] = Field(
        description=("Secret findings with type, file_path, and detection_method"),
    )
    high_entropy_count: int = Field(
        description="Number of high-entropy findings",
    )
    pattern_matches: int = Field(
        description="Number of regex pattern matches",
    )
    summary: str = Field(
        description="Detection analysis summary",
    )


class RiskClassificationOutput(BaseModel):
    """Structured output for risk classification."""

    classifications: list[dict[str, str]] = Field(
        description=("Risk classifications with finding_id, risk_level, and recommendation"),
    )
    critical_count: int = Field(
        description="Number of critical-risk secrets",
    )
    rotation_needed: int = Field(
        description="Number needing immediate rotation",
    )
    exposure_summary: str = Field(
        description="Exposure scope summary",
    )


class AlertPriorityOutput(BaseModel):
    """Structured output for alert prioritization."""

    alerts: list[dict[str, str]] = Field(
        description=("Prioritized alerts with owner, channel, and urgency"),
    )
    immediate_count: int = Field(
        description="Number requiring immediate action",
    )
    escalation_needed: bool = Field(
        description="Whether escalation is needed",
    )
    priority_rationale: str = Field(
        description="Rationale for alert prioritization",
    )


class SprawlReportOutput(BaseModel):
    """Structured output for sprawl detection report."""

    executive_summary: str = Field(
        description="Executive summary of secret sprawl",
    )
    total_secrets: int = Field(
        description="Total secrets detected",
    )
    critical_findings: list[str] = Field(
        description="Critical findings requiring action",
    )
    recommendations: list[str] = Field(
        description="Remediation recommendations",
    )
    risk_rating: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_DETECT = """\
You are an expert secret detection engine analyzing \
code repositories and configuration files for leaked \
credentials.

Given the scan results from repos and config files:
1. Identify secrets using regex patterns, entropy \
analysis, and known credential formats
2. Classify each finding by secret type (API key, \
token, password, certificate, private key)
3. Flag high-entropy strings that may be obfuscated \
credentials
4. Check git history for previously committed and \
removed secrets

Be thorough — a single leaked credential can \
compromise an entire environment."""


SYSTEM_CLASSIFY = """\
You are an expert risk assessor classifying the \
severity of detected secret sprawl.

Given the detected secrets and their context:
1. Assess blast radius based on secret type and scope
2. Determine exposure duration from commit history
3. Prioritize by rotation urgency and access level
4. Recommend specific remediation actions per finding

Critical secrets (production API keys, cloud IAM \
credentials, database passwords) require immediate \
rotation regardless of exposure duration."""


SYSTEM_ALERT = """\
You are an expert alert prioritization engine \
determining notification urgency for secret sprawl \
findings.

Given the classified secrets and their risk levels:
1. Identify owners from commit history and CODEOWNERS
2. Prioritize alerts by risk level and rotation urgency
3. Determine appropriate notification channels
4. Flag findings requiring security team escalation

Time is critical for exposed production credentials. \
Route high-severity findings to on-call responders."""


SYSTEM_REPORT = """\
You are an expert security reporting analyst \
synthesizing secret sprawl detection results.

Given the full detection and classification results:
1. Produce an executive summary of sprawl severity
2. Highlight critical findings with remediation urgency
3. Recommend systematic improvements (vault migration, \
pre-commit hooks, rotation policies)
4. Provide metrics for security posture tracking

Write for security leadership and engineering teams."""
