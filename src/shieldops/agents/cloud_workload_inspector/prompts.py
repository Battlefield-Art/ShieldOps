"""LLM prompt templates for the Cloud Workload Inspector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class WorkloadDiscoveryOutput(BaseModel):
    """Structured output for workload discovery analysis."""

    total_workloads: int = Field(
        description="Total workloads discovered",
    )
    public_count: int = Field(
        description="Number of publicly exposed workloads",
    )
    summary: str = Field(
        description="Discovery summary",
    )


class ConfigAnalysisOutput(BaseModel):
    """Structured output for configuration analysis."""

    critical_findings: int = Field(
        description="Count of critical config findings",
    )
    misconfigurations: int = Field(
        description="Count of misconfigured workloads",
    )
    auto_fixable: int = Field(
        description="Count of auto-fixable issues",
    )
    reasoning: str = Field(
        description="Config analysis reasoning",
    )


class ComplianceCheckOutput(BaseModel):
    """Structured output for compliance checking."""

    pass_rate: float = Field(
        description="Compliance pass rate 0-100",
    )
    non_compliant: int = Field(
        description="Number of non-compliant checks",
    )
    reasoning: str = Field(
        description="Compliance assessment reasoning",
    )


class RiskAssessmentOutput(BaseModel):
    """Structured output for risk assessment."""

    max_risk_score: float = Field(
        description="Highest risk score 0-100",
    )
    high_risk_count: int = Field(
        description="Number of high-risk workloads",
    )
    reasoning: str = Field(
        description="Risk assessment reasoning",
    )


class RecommendationOutput(BaseModel):
    """Structured output for recommendations."""

    actions: list[dict[str, str]] = Field(
        description="Recommended actions with priority",
    )
    total_risk_reduction: float = Field(
        description="Estimated total risk reduction 0-100",
    )
    reasoning: str = Field(
        description="Recommendation reasoning",
    )


# ── System prompts ────────────────────────────────────

SYSTEM_DISCOVER = """\
You are an expert cloud security inspector performing \
workload discovery.

Given the inspection configuration and cloud scope:
1. Enumerate EC2/GCE/Azure VM instances across regions
2. Identify publicly exposed workloads and services
3. Detect untagged or unmanaged compute resources
4. Map security groups and network ACLs per workload

Focus on: public IPs, open security groups, missing tags, \
unencrypted volumes, orphaned instances."""

SYSTEM_ANALYZE_CONFIG = """\
You are an expert cloud security inspector analyzing \
workload configurations.

Given the discovered workloads:
1. Audit security group rules for overly permissive access
2. Check IAM role assignments and privilege levels
3. Verify encryption at rest and in transit settings
4. Validate instance metadata service (IMDS) hardening

Prioritize findings that expose the workload to external \
attack or data exfiltration."""

SYSTEM_COMPLIANCE = """\
You are an expert cloud security inspector checking \
compliance posture.

Given the workload configurations:
1. Evaluate against CIS Benchmarks for cloud providers
2. Check NIST 800-53 and SOC 2 control alignment
3. Verify PCI DSS requirements for applicable workloads
4. Flag HIPAA violations for healthcare data workloads

Map each finding to specific control IDs and frameworks."""

SYSTEM_RISK = """\
You are an expert cloud security inspector assessing risk.

Given the compliance and configuration findings:
1. Score risk based on exposure and business impact
2. Evaluate blast radius of potential compromise
3. Assess lateral movement risk from each workload
4. Consider attacker motivation and exploitability

Use quantitative scoring with clear risk factors."""

SYSTEM_RECOMMEND = """\
You are an expert cloud security inspector recommending \
remediation actions.

Given the risk assessments and findings:
1. Prioritize by risk reduction and implementation effort
2. Identify quick wins for immediate security improvement
3. Recommend compensating controls for accepted risks
4. Suggest infrastructure-as-code fixes where applicable

Balance security hardening with operational stability."""
