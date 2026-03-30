"""IAM Policy Analyzer Agent — LLM prompt templates and structured output schemas."""

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Structured output schemas
# ---------------------------------------------------------------------------


class PermissionAnalysisOutput(BaseModel):
    """LLM output for permission analysis."""

    summary: str = Field(
        description="Summary of permission analysis findings",
    )
    wildcard_risk: str = Field(
        description="Assessment of wildcard permission risk",
    )
    admin_principals: list[str] = Field(
        description="Principals with admin-level access",
    )
    recommendations: list[str] = Field(
        description="Top permission-tightening recommendations",
    )


class OverprivilegeOutput(BaseModel):
    """LLM output for over-privilege detection."""

    summary: str = Field(
        description="Summary of over-privilege findings",
    )
    critical_count: int = Field(
        description="Number of critically over-privileged principals",
    )
    attack_vectors: list[str] = Field(
        description="Potential attack vectors from over-privilege",
    )
    priority_fixes: list[str] = Field(
        description="Highest-priority fixes ordered by risk",
    )


class UnusedPermissionsOutput(BaseModel):
    """LLM output for unused permission detection."""

    summary: str = Field(
        description="Summary of unused permissions found",
    )
    total_unused: int = Field(
        description="Total count of unused permissions",
    )
    stale_principals: list[str] = Field(
        description="Principals with the most unused permissions",
    )
    removal_plan: list[str] = Field(
        description="Recommended removal sequence",
    )


class PolicyRecommendationOutput(BaseModel):
    """LLM output for policy fix recommendations."""

    summary: str = Field(
        description="Remediation plan summary",
    )
    auto_fixable: int = Field(
        description="Number of auto-applicable recommendations",
    )
    manual_items: list[str] = Field(
        description="Items requiring manual review",
    )
    risk_after_fixes: str = Field(
        description="Expected risk posture after applying fixes",
    )
    estimated_effort_hours: float = Field(
        description="Total estimated effort in hours",
    )


class IAMReportOutput(BaseModel):
    """LLM output for final IAM posture report."""

    summary: str = Field(
        description="Executive summary of IAM posture",
    )
    risk_level: str = Field(
        description="Overall IAM risk: critical/high/medium/low",
    )
    key_findings: list[str] = Field(
        description="Top IAM security findings",
    )
    score_justification: str = Field(
        description="Justification for the IAM risk score",
    )


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_PERMISSION_ANALYSIS = (
    "You are an IAM security analyst specializing in "
    "least-privilege assessment.\n"
    "Analyze the collected IAM policies and permissions:\n"
    "1. Identify wildcard actions (e.g. s3:*, iam:*) and "
    "assess their blast radius\n"
    "2. Flag admin-level policies (AdministratorAccess, "
    "roles/owner, Contributor)\n"
    "3. Evaluate resource scope — are permissions scoped "
    "to specific resources or account-wide?\n"
    "4. Score each principal's permission risk on a 0-100 "
    "scale with justification"
)

SYSTEM_OVERPRIVILEGE_DETECTION = (
    "You are detecting over-privileged IAM principals "
    "across multi-cloud environments.\n"
    "For the provided permission analyses:\n"
    "1. Classify over-privilege type: wildcard abuse, "
    "admin escalation, cross-service spread\n"
    "2. Map over-privilege to CIS Benchmark controls "
    "(CIS-AWS-1.16, CIS-GCP-1.4, etc.)\n"
    "3. Assess blast radius if principal is compromised\n"
    "4. Prioritize alerts by exploitability and "
    "data exposure risk"
)

SYSTEM_UNUSED_PERMISSIONS = (
    "You are analyzing IAM permission usage patterns to "
    "identify stale and unused permissions.\n"
    "For the provided usage data:\n"
    "1. Flag permissions unused for >90 days as "
    "candidates for removal\n"
    "2. Identify principals with >50% unused "
    "permissions as over-provisioned\n"
    "3. Recommend a safe removal sequence that avoids "
    "breaking active workloads\n"
    "4. Highlight permissions that are never used "
    "but grant sensitive access"
)

SYSTEM_POLICY_RECOMMENDATIONS = (
    "You are creating actionable IAM policy remediation "
    "recommendations.\n"
    "Based on over-privilege alerts and unused "
    "permissions:\n"
    "1. Generate least-privilege replacement policies "
    "for each over-privileged principal\n"
    "2. Separate auto-applicable fixes from those "
    "requiring manual review\n"
    "3. Sequence changes to avoid breaking dependencies\n"
    "4. Estimate risk reduction and effort for each fix\n"
    "5. Provide rollback guidance for automated changes"
)

SYSTEM_IAM_REPORT = (
    "You are generating an executive IAM security "
    "posture report.\n"
    "Synthesize all findings into a CISO-ready summary:\n"
    "1. Overall IAM risk score with justification\n"
    "2. Key findings: over-privilege, unused permissions, "
    "policy drift\n"
    "3. Compliance gaps against CIS, NIST 800-53, "
    "SOC 2 standards\n"
    "4. Prioritized action plan with estimated effort "
    "and risk reduction"
)
