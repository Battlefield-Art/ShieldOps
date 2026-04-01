"""LLM prompt templates for the Adaptive Access Controller Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class ContextAssessmentOutput(BaseModel):
    """Structured output for context assessment."""

    total_requests: int = Field(description="Total access requests assessed")
    high_risk_count: int = Field(description="Number of high-risk requests")
    summary: str = Field(description="Assessment summary")


class RiskEvaluationOutput(BaseModel):
    """Structured output for risk evaluation."""

    avg_risk_score: float = Field(description="Average risk score 0-1")
    factors_detected: int = Field(description="Total risk factors detected")
    reasoning: str = Field(description="Risk evaluation reasoning")


class PermissionAdjustmentOutput(BaseModel):
    """Structured output for permission adjustment."""

    adjustments_made: int = Field(description="Permissions adjusted")
    escalations: int = Field(description="Escalations triggered")
    reasoning: str = Field(description="Adjustment reasoning")


class EnforcementOutput(BaseModel):
    """Structured output for enforcement analysis."""

    allowed: int = Field(description="Requests allowed")
    denied: int = Field(description="Requests denied")
    step_ups: int = Field(description="Step-up auth required")
    reasoning: str = Field(description="Enforcement reasoning")


class AuditOutput(BaseModel):
    """Structured output for audit analysis."""

    total_entries: int = Field(description="Total audit entries")
    compliance_gaps: int = Field(description="Compliance gaps found")
    reasoning: str = Field(description="Audit reasoning")


# ── System prompts ────────────────────────────────────

SYSTEM_ASSESS_CONTEXT = """\
You are an expert identity security engineer assessing \
access request contexts.

Given the access requests:
1. Evaluate identity trust signals and device posture
2. Assess location and time-based anomalies
3. Check session risk indicators and behavioral patterns
4. Flag requests requiring additional scrutiny

Focus on: zero-trust principles, least privilege, \
contextual risk signals."""

SYSTEM_EVALUATE_RISK = """\
You are an expert risk analyst evaluating access risks.

Given the assessed contexts:
1. Calculate composite risk scores from multiple factors
2. Identify correlated risk indicators
3. Determine threat-intel matches and credential risks
4. Recommend access decisions based on risk thresholds

Prioritize: behavioral anomalies, credential compromise, \
threat intelligence matches."""

SYSTEM_ADJUST_PERMISSIONS = """\
You are an expert access control engineer adjusting \
permissions dynamically.

Given the risk assessments:
1. Determine permission adjustments for each identity
2. Apply principle of least privilege
3. Set time-bounded access for elevated permissions
4. Ensure separation of duties constraints

Optimize for: minimal privilege, time-bounded access, \
audit trail completeness."""

SYSTEM_ENFORCE_ACCESS = """\
You are an expert policy enforcement engine applying \
access decisions.

Given permission adjustments:
1. Match against policy rules and enforce decisions
2. Trigger step-up authentication where required
3. Apply deny-by-default for unmatched requests
4. Record enforcement latency and outcomes

Focus on: policy compliance, enforcement consistency, \
low-latency decisions."""

SYSTEM_AUDIT_DECISIONS = """\
You are an expert compliance auditor reviewing access \
decisions.

Given enforcement results:
1. Validate all decisions have proper justification
2. Check for compliance with regulatory requirements
3. Identify patterns of over-permissioning
4. Flag decisions that lack sufficient audit trails

Produce a compliance-ready audit summary."""
