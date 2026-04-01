"""LLM prompt templates and response schemas for Credential Hygiene Auditor."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class CredentialInventoryAnalysis(BaseModel):
    """LLM analysis of credential inventory."""

    summary: str = Field(description="Brief inventory summary")
    credential_count: int = Field(description="Credentials found")
    types_found: list[str] = Field(description="Credential types found")
    notable_findings: list[str] = Field(description="Notable findings")


class HygieneAssessmentAnalysis(BaseModel):
    """LLM analysis of hygiene assessments."""

    summary: str = Field(description="Brief assessment summary")
    compliant_pct: float = Field(description="Compliance percentage")
    top_issues: list[str] = Field(description="Top hygiene issues")
    assessment_quality: str = Field(description="Quality: excellent/good/fair/poor")


class ViolationDetectionAnalysis(BaseModel):
    """LLM analysis of detected violations."""

    summary: str = Field(description="Brief violation summary")
    violation_count: int = Field(description="Violations detected")
    critical_violations: list[str] = Field(description="Critical violations")
    threat_level: str = Field(description="Threat: critical/high/medium/low")


class RiskScoringAnalysis(BaseModel):
    """LLM analysis of risk scores."""

    summary: str = Field(description="Brief risk scoring summary")
    high_risk_count: int = Field(description="High-risk items")
    risk_drivers: list[str] = Field(description="Key risk drivers")
    risk_assessment: str = Field(description="Risk: critical/high/medium/low")


class RemediationAnalysis(BaseModel):
    """LLM analysis of remediation recommendations."""

    summary: str = Field(description="Brief remediation summary")
    recommendation_count: int = Field(description="Recommendations generated")
    quick_wins: list[str] = Field(description="Quick win fixes")
    automation_possible: bool = Field(description="Whether automation is feasible")


# --- Prompt templates ---

SYSTEM_INVENTORY_CREDENTIALS = """\
You are an expert credential security analyst inventorying \
credentials across an enterprise organization.

You examine password stores, API key registries, SSH key \
management systems, certificate authorities, and secret vaults.

Your task is to:
1. Catalog all credential types and their locations
2. Identify credential owners and associated systems
3. Flag credentials without clear ownership
4. Assess completeness of the credential inventory

Focus on high-privilege credentials and shared secrets. \
Pay attention to service accounts and API keys."""

SYSTEM_ASSESS_HYGIENE = """\
You are an expert credential security analyst assessing \
credential hygiene across an organization.

You are given:
- Credential inventory with age and rotation metadata
- Organizational rotation policies and standards
- Industry best practices (NIST 800-63B, CIS)

Your task is to:
1. Evaluate credential age against rotation policies
2. Check password complexity and reuse patterns
3. Verify MFA enrollment for sensitive credentials
4. Assess credential sharing and scope appropriateness

Strong credential hygiene is foundational to security. \
Flag any deviation from policy."""

SYSTEM_DETECT_VIOLATIONS = """\
You are an expert credential security analyst detecting \
hygiene violations in credential management.

You are given:
- Hygiene assessments with status classifications
- Organizational security policies
- Regulatory requirements (SOC 2, PCI DSS, HIPAA)

Your task is to:
1. Identify policy violations for each credential
2. Classify violation severity based on risk impact
3. Map violations to compliance framework requirements
4. Provide remediation hints for each violation

IMPORTANT:
- Expired credentials are immediate violations
- Shared credentials require justification
- Service accounts need regular rotation"""

SYSTEM_SCORE_RISK = """\
You are an expert credential security analyst scoring \
risk levels for credential hygiene findings.

You are given:
- Hygiene violations with severity and scope
- Credential blast radius analysis
- Historical incident correlation data

Your task is to:
1. Calculate composite risk scores per scope
2. Factor in blast radius and privilege level
3. Identify correlated violations that amplify risk
4. Prioritize remediation by risk score

Higher scores indicate greater organizational risk. \
Consider cascading failure scenarios."""

SYSTEM_RECOMMEND_FIXES = """\
You are an expert credential security analyst recommending \
fixes for credential hygiene violations.

You are given:
- Violations with severity and policy references
- Risk scores and blast radius analysis
- Available automation tools and capabilities

Your task is to:
1. Propose specific remediation actions per violation
2. Estimate effort and automation feasibility
3. Prioritize by risk impact and implementation cost
4. Group related fixes for efficient remediation

Quick wins should be flagged for immediate action. \
Complex fixes should include phased implementation plans."""
