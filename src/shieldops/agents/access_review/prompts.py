"""LLM prompt templates and response schemas for the Access Review Agent."""

from typing import Any

from pydantic import BaseModel, Field

# --- Response schemas ---


class AccessAnalysisResult(BaseModel):
    """Structured output from LLM access pattern analysis."""

    excessive_access: list[dict[str, Any]] = Field(
        description="Entitlements with permissions beyond what the identity needs"
    )
    unused_access: list[str] = Field(
        description="Entitlement IDs that have not been used in the review period"
    )
    sod_conflicts: list[dict[str, Any]] = Field(
        description="Separation-of-duty conflicts (identity + conflicting permissions)"
    )
    orphaned_access: list[str] = Field(
        description="Entitlement IDs for identities that no longer exist"
    )
    risk_summary: str = Field(description="Summary of the access risk posture")


class ViolationClassificationResult(BaseModel):
    """Structured output from LLM violation severity classification."""

    classified_violations: list[dict[str, Any]] = Field(
        description=(
            "Violations with severity and auto_revocable flag. "
            "Each dict has: id, severity, auto_revocable, rationale."
        )
    )
    critical_count: int = Field(description="Number of critical violations")
    high_count: int = Field(description="Number of high-severity violations")
    compliance_gaps: list[str] = Field(description="SOC 2 or HIPAA controls that are not satisfied")


class ReviewTaskRecommendationResult(BaseModel):
    """Structured output for generating review task recommendations."""

    tasks: list[dict[str, Any]] = Field(
        description=(
            "Review tasks with recommended_decision and reason. "
            "Each dict has: entitlement_id, identity_name, resource, "
            "permission, recommended_decision, reason, priority."
        )
    )
    summary: str = Field(description="Executive summary of review recommendations")
    auto_revoke_count: int = Field(
        description="Number of entitlements safe for automatic revocation"
    )


class CampaignReportResult(BaseModel):
    """Structured output for final campaign report generation."""

    executive_summary: str = Field(description="Executive summary for compliance officers")
    compliance_status: str = Field(
        description="Overall compliance status: compliant, partially_compliant, non_compliant"
    )
    soc2_findings: list[str] = Field(description="SOC 2-specific findings")
    hipaa_findings: list[str] = Field(description="HIPAA-specific findings")
    risk_reduction_pct: float = Field(
        description="Estimated risk reduction from completed certifications"
    )
    open_items: list[str] = Field(description="Unresolved items requiring follow-up")


# --- Prompt templates ---

SYSTEM_ACCESS_ANALYSIS = """\
You are an expert identity and access management (IAM) analyst performing \
a periodic access review for SOC 2 and HIPAA compliance.

You are given:
- A list of entitlements (identity + resource + permission + last_used timestamps)
- Identity types: human users, service accounts, and AI agents

Your task is to:
1. Identify excessive access (permissions beyond what usage patterns suggest)
2. Flag unused entitlements (not used in the past 90 days)
3. Detect separation-of-duty conflicts (same identity with conflicting permissions)
4. Find orphaned access (entitlements for identities that appear inactive or removed)

Be specific about which entitlements are problematic and why. \
Reference SOC 2 CC6.1 (logical access) and HIPAA 164.312(a)(1) (access control)."""

SYSTEM_VIOLATION_CLASSIFICATION = """\
You are a compliance analyst classifying access violations for severity \
and determining which can be automatically revoked.

You are given:
- A list of access violations with types (excessive, unused, \
separation_of_duties, orphaned)
- The entitlement details for each violation

Your task is to:
1. Classify each violation's severity (critical, high, medium, low)
2. Determine if each violation is safe for automatic revocation
3. Identify which SOC 2 or HIPAA controls are impacted

Rules for auto-revocation:
- NEVER auto-revoke access for production service accounts
- Unused access for terminated employees can be auto-revoked
- Separation-of-duty conflicts require human review
- Orphaned service accounts need owner verification first"""

SYSTEM_REVIEW_TASK_GENERATION = """\
You are an access governance specialist generating review tasks for \
a periodic access certification campaign.

You are given:
- Classified access violations with severity and recommendations
- Entitlement details including identity, resource, and permission

Your task is to:
1. Generate a review task for each violation requiring human certification
2. Recommend a decision (approve, revoke, modify, escalate, defer)
3. Provide clear reasoning for each recommendation
4. Assign priority based on violation severity and compliance impact

IMPORTANT:
- Critical violations must be assigned to security leads
- HIPAA-regulated resources require clinical system owner review
- Service account reviews should go to the owning team lead
- AI agent permissions require the AI governance committee"""

SYSTEM_CAMPAIGN_REPORT = """\
You are a compliance reporting specialist generating the final report \
for a periodic access review campaign.

You are given:
- Campaign statistics (entitlements reviewed, violations found, certifications)
- Certification decisions and their outcomes
- Remaining open items and compliance gaps

Your task is to:
1. Generate an executive summary suitable for SOC 2 auditors
2. Assess overall compliance status against SOC 2 CC6.1-CC6.3 and HIPAA 164.312
3. List specific findings for each compliance framework
4. Calculate risk reduction from completed certifications
5. Identify open items that require follow-up before the next audit

The report must be audit-ready and reference specific control objectives."""
