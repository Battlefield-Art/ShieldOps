"""LLM prompt templates for the Attack Surface Mapper Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class AssetDiscoveryOutput(BaseModel):
    """Structured output for asset discovery analysis."""

    total_assets: int = Field(
        description="Total assets discovered",
    )
    shadow_it_count: int = Field(
        description="Number of shadow IT assets",
    )
    summary: str = Field(
        description="Discovery summary",
    )


class ExposureClassifyOutput(BaseModel):
    """Structured output for exposure classification."""

    internet_facing: int = Field(
        description="Count of internet-facing assets",
    )
    misconfigured: int = Field(
        description="Count of misconfigured assets",
    )
    forgotten: int = Field(
        description="Count of forgotten endpoints",
    )
    reasoning: str = Field(
        description="Classification reasoning",
    )


class RiskAssessmentOutput(BaseModel):
    """Structured output for risk assessment."""

    max_risk_score: float = Field(
        description="Highest risk score 0-100",
    )
    critical_count: int = Field(
        description="Number of critical-risk assets",
    )
    reasoning: str = Field(
        description="Risk assessment reasoning",
    )


class AttackPathOutput(BaseModel):
    """Structured output for attack path mapping."""

    paths: list[dict[str, str]] = Field(
        description="Attack paths with entry, target, impact",
    )
    highest_likelihood: float = Field(
        description="Highest path likelihood 0-1",
    )
    reasoning: str = Field(
        description="Attack path reasoning",
    )


class RemediationOutput(BaseModel):
    """Structured output for remediation recommendations."""

    actions: list[dict[str, str]] = Field(
        description="Remediation actions with priority",
    )
    total_risk_reduction: float = Field(
        description="Estimated total risk reduction 0-100",
    )
    reasoning: str = Field(
        description="Remediation reasoning",
    )


# ── System prompts ────────────────────────────────────

SYSTEM_DISCOVER = """\
You are an expert attack surface mapper performing \
asset discovery.

Given the scan configuration and target scope:
1. Identify all externally visible assets including \
shadow IT
2. Detect forgotten endpoints and abandoned services
3. Enumerate DNS records, certificates, cloud resources
4. Flag assets not tracked in the asset inventory

Focus on: subdomains, certificate transparency logs, \
cloud storage buckets, exposed APIs, forgotten dev/staging \
environments."""

SYSTEM_CLASSIFY = """\
You are an expert attack surface mapper classifying \
asset exposure levels.

Given the discovered assets:
1. Classify each asset by exposure level (internet-facing, \
DMZ, internal, restricted, airgapped)
2. Identify misconfigured services (open ports, missing \
TLS, no auth)
3. Flag forgotten or orphaned endpoints
4. Assess shadow IT risk for untracked assets

Prioritize assets that violate security policy or have \
unexpected exposure."""

SYSTEM_RISK = """\
You are an expert attack surface mapper assessing risk.

Given the classified assets and their exposure:
1. Score risk based on exploitability and business impact
2. Map relevant CVEs and known vulnerabilities
3. Evaluate the blast radius of potential compromise
4. Consider attacker motivation and capability

Use CVSS scoring methodology and MITRE ATT&CK mapping."""

SYSTEM_ATTACK_PATHS = """\
You are an expert attack surface mapper identifying \
attack paths.

Given the risk-assessed assets:
1. Map possible attack chains from entry to target
2. Identify lateral movement opportunities
3. Assess likelihood and impact of each path
4. Map to MITRE ATT&CK techniques

Focus on: initial access, privilege escalation, lateral \
movement, data exfiltration paths."""

SYSTEM_REMEDIATE = """\
You are an expert attack surface mapper recommending \
remediation.

Given the mapped attack paths and risk assessments:
1. Prioritize remediation by risk reduction impact
2. Identify quick wins vs long-term hardening
3. Estimate effort and operational impact
4. Suggest compensating controls for accepted risks

Balance security improvement with operational stability."""
