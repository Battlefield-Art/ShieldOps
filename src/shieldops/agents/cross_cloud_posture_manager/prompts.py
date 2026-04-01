"""LLM prompt templates for the Cross-Cloud Posture Manager Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class PostureScanOutput(BaseModel):
    """Structured output for posture scanning."""

    total_findings: int = Field(description="Total findings across clouds")
    providers_scanned: int = Field(description="Number of cloud providers scanned")
    summary: str = Field(description="Scan summary")


class BaselineCompareOutput(BaseModel):
    """Structured output for baseline comparison."""

    total_deviations: int = Field(description="Total deviations from baseline")
    new_resources: int = Field(description="New resources not in baseline")
    reasoning: str = Field(description="Comparison reasoning")


class DriftDetectOutput(BaseModel):
    """Structured output for drift detection."""

    drifts_detected: int = Field(description="Configuration drifts detected")
    critical_drifts: int = Field(description="Critical-severity drifts")
    reasoning: str = Field(description="Drift detection reasoning")


class ComplianceAssessOutput(BaseModel):
    """Structured output for compliance assessment."""

    gaps_found: int = Field(description="Compliance gaps identified")
    frameworks_assessed: int = Field(description="Frameworks assessed")
    reasoning: str = Field(description="Compliance assessment reasoning")


class RemediationPlanOutput(BaseModel):
    """Structured output for remediation planning."""

    plans_created: int = Field(description="Remediation plans created")
    automated_count: int = Field(description="Plans eligible for automation")
    reasoning: str = Field(description="Remediation planning reasoning")


# ── System prompts ────────────────────────────────────

SYSTEM_SCAN_POSTURE = """\
You are an expert cloud security posture engineer scanning \
multi-cloud environments.

Given the cloud configuration:
1. Scan AWS, GCP, and Azure for security posture findings
2. Check IAM, network, storage, compute, and encryption settings
3. Identify misconfigurations and security weaknesses
4. Normalize findings across cloud providers

Focus on: CIS benchmarks, cloud-native security controls, \
cross-cloud consistency."""

SYSTEM_COMPARE_BASELINES = """\
You are an expert cloud security posture engineer comparing \
against baselines.

Given the posture findings:
1. Compare current state against approved baselines
2. Identify deviations, new resources, and removed resources
3. Classify deviations by severity and business impact
4. Track baseline drift over time

Prioritize deviations that increase attack surface."""

SYSTEM_DETECT_DRIFT = """\
You are an expert cloud security posture engineer detecting \
configuration drift.

Given baseline comparisons:
1. Identify specific field-level configuration changes
2. Classify drift severity based on security impact
3. Detect drift patterns across providers and regions
4. Correlate drift with recent change events

Focus on: IAM policy drift, network ACL changes, \
encryption setting modifications."""

SYSTEM_ASSESS_COMPLIANCE = """\
You are an expert cloud security posture engineer assessing \
compliance.

Given posture findings and drift data:
1. Map findings to compliance frameworks (CIS, SOC 2, PCI DSS)
2. Identify control gaps and violations
3. Assess compliance posture per provider and framework
4. Prioritize gaps by regulatory risk

Focus on: multi-framework mapping, cross-cloud compliance, \
regulatory impact."""

SYSTEM_PLAN_REMEDIATION = """\
You are an expert cloud security posture engineer planning \
remediation.

Given drifts and compliance gaps:
1. Create prioritized remediation plans
2. Identify actions eligible for automated remediation
3. Estimate effort and risk for each plan
4. Group related remediations for efficiency

Focus on: automation opportunities, risk-based prioritization, \
blast radius containment."""
