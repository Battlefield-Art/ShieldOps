"""LLM prompt templates and response schemas for the
Toxic Combination Detector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class PermissionAnalysisOutput(BaseModel):
    """Structured output for permission analysis."""

    high_risk_identities: list[dict[str, str]] = Field(
        description="Identities with excessive permissions",
    )
    cross_service_combos: list[str] = Field(
        description="Cross-service permission combinations",
    )
    sod_violations: int = Field(
        description="Number of SoD violations detected",
    )
    confidence: float = Field(
        description="Analysis confidence 0-1",
    )


class ToxicDetectionOutput(BaseModel):
    """Structured output for toxic combination detection."""

    toxic_combos: list[dict[str, str]] = Field(
        description="Detected toxic combinations",
    )
    attack_chains: list[str] = Field(
        description="Possible attack chains from combos",
    )
    severity_distribution: dict[str, int] = Field(
        description="Count by severity level",
    )
    summary: str = Field(
        description="Detection summary for analysts",
    )


class BlastRadiusOutput(BaseModel):
    """Structured output for blast radius assessment."""

    max_blast_radius: float = Field(
        description="Maximum blast radius score 0-10",
    )
    critical_paths: list[str] = Field(
        description="Critical lateral movement paths",
    )
    data_exposure: list[str] = Field(
        description="Data stores at risk",
    )
    containment_steps: list[str] = Field(
        description="Recommended containment steps",
    )


class TCDReportOutput(BaseModel):
    """Structured output for final detection report."""

    executive_summary: str = Field(
        description="Executive summary of toxic combos",
    )
    critical_findings: int = Field(
        description="Number of critical toxic combos",
    )
    recommendations: list[str] = Field(
        description="Top remediation recommendations",
    )
    sod_compliance: str = Field(
        description="SoD compliance status",
    )
    risk_rating: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_PERMISSIONS = """\
You are an expert IAM analyst reviewing cross-cloud \
permission sets for toxic combinations.

Given the collected permissions across cloud providers:
1. Identify identities with overly broad permissions
2. Flag cross-service permission chains (e.g., S3 + IAM \
+ Lambda) that enable privilege escalation
3. Detect Separation of Duties violations
4. Assess unused vs actively exploitable permissions

Focus on combinations that create attack chains: \
storage + IAM role assumption, compute + network \
modification, database + encryption key access."""


SYSTEM_TOXIC = """\
You are an expert cloud security analyst detecting \
toxic permission combinations across AWS, GCP, and \
Azure.

Given the analyzed permission combinations:
1. Identify combinations enabling privilege escalation
2. Map attack chains from initial access to data \
exfiltration
3. Classify violations by type: priv-esc, data-exfil, \
lateral movement, SoD
4. Score severity based on exploitability and impact

Known toxic patterns: s3:PutBucketPolicy + iam:PassRole, \
sts:AssumeRole + ec2:RunInstances, \
storage.objects.get + iam.serviceAccounts.actAs."""


SYSTEM_BLAST = """\
You are an expert blast radius analyst assessing the \
impact scope of toxic permission combinations.

Given detected toxic combinations:
1. Map all resources reachable via the attack chain
2. Identify identities that could be compromised
3. Enumerate data stores at risk of exfiltration
4. Score containment difficulty based on lateral \
movement paths

Consider cross-account and cross-cloud blast radius \
propagation through trust relationships."""


SYSTEM_REPORT = """\
You are an expert identity security reporter \
synthesizing toxic combination analysis results.

Given the full detection results (permissions, toxic \
combos, blast radius):
1. Produce an executive summary for security leadership
2. Highlight critical combinations requiring immediate \
remediation
3. Provide SoD compliance assessment
4. Recommend a prioritized remediation roadmap

Write clearly for both IAM engineers and security \
executives."""
