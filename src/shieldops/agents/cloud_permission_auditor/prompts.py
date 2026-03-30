"""Cloud Permission Auditor Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ScopeInsight(BaseModel):
    """Structured output from scope analysis."""

    summary: str = Field(
        description="Brief permission scope overview",
    )
    overprivileged: list[str] = Field(
        description="Principals with excessive permissions",
    )
    recommendations: list[str] = Field(
        description="Scope reduction recommendations",
    )


class ViolationInsight(BaseModel):
    """Structured output from violation detection."""

    summary: str = Field(
        description="Violation detection overview",
    )
    critical_findings: list[str] = Field(
        description="Critical and high-severity findings",
    )
    escalation_paths: list[str] = Field(
        description="Detected privilege escalation paths",
    )


class CrossAccountInsight(BaseModel):
    """Structured output from cross-account analysis."""

    summary: str = Field(
        description="Cross-account access overview",
    )
    external_trusts: list[str] = Field(
        description="External trust relationships found",
    )
    risky_patterns: list[str] = Field(
        description="Risky cross-account patterns",
    )


class ReportInsight(BaseModel):
    """Structured output for final audit report."""

    summary: str = Field(
        description="Executive summary of permission audit",
    )
    key_findings: list[str] = Field(
        description="Key findings for leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended remediation steps",
    )


SYSTEM_SCOPE = (
    "You are a cloud IAM security analyst reviewing "
    "permission scopes.\n"
    "1. Identify overprivileged principals\n"
    "2. Flag wildcard and admin-level access\n"
    "3. Detect unused permissions over 90 days\n"
    "4. Recommend least-privilege reductions"
)

SYSTEM_VIOLATIONS = (
    "You are a cloud security auditor detecting "
    "IAM violations.\n"
    "1. Classify violations by severity\n"
    "2. Identify privilege escalation paths\n"
    "3. Flag dormant credentials and service keys\n"
    "4. Assess blast radius of each violation"
)

SYSTEM_CROSS_ACCOUNT = (
    "You are a cloud security analyst reviewing "
    "cross-account trust relationships.\n"
    "1. Map all trust chains between accounts\n"
    "2. Flag external or unknown account access\n"
    "3. Identify overly permissive trust policies\n"
    "4. Detect stale cross-account roles"
)

SYSTEM_REPORT = (
    "You are a cloud IAM security advisor generating "
    "an executive permission audit report.\n"
    "1. Summarize total principals, violations, fixes\n"
    "2. Highlight critical security gaps\n"
    "3. Quantify risk reduction from proposed fixes\n"
    "4. Recommend next steps for IAM governance"
)
