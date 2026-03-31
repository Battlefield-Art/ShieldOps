"""LLM prompt templates and response schemas for the
Deception Network Manager Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class DecoyDeploymentOutput(BaseModel):
    """Structured output for decoy deployment planning."""

    decoys: list[dict[str, str]] = Field(
        description="List of decoys with type, service, and segment",
    )
    coverage_score: float = Field(
        description="Network coverage score 0-1",
    )
    recommended_tokens: list[str] = Field(
        description="Recommended deception tokens to deploy",
    )
    confidence: float = Field(
        description="Deployment confidence 0-1",
    )


class BehaviorAnalysisOutput(BaseModel):
    """Structured output for attacker behavior analysis."""

    ttp_chain: list[str] = Field(
        description="MITRE ATT&CK TTP chain observed",
    )
    risk_score: float = Field(
        description="Attacker risk score 0-10",
    )
    lateral_movement: bool = Field(
        description="Whether lateral movement was detected",
    )
    summary: str = Field(
        description="Behavior analysis summary",
    )


class AttackerClassificationOutput(BaseModel):
    """Structured output for attacker classification."""

    profile: str = Field(
        description="Attacker profile classification",
    )
    sophistication: str = Field(
        description="Sophistication: advanced/intermediate/basic",
    )
    confidence: float = Field(
        description="Classification confidence 0-1",
    )
    mitre_techniques: list[str] = Field(
        description="Mapped MITRE ATT&CK technique IDs",
    )
    intent: str = Field(
        description="Assessed attacker intent",
    )


class IntelReportOutput(BaseModel):
    """Structured output for threat intelligence report."""

    executive_summary: str = Field(
        description="Executive summary of deception findings",
    )
    iocs: list[str] = Field(
        description="Indicators of compromise extracted",
    )
    recommendations: list[str] = Field(
        description="Actionable security recommendations",
    )
    mitre_coverage: list[str] = Field(
        description="MITRE techniques observed",
    )
    effectiveness_rating: str = Field(
        description="Deception effectiveness: high/medium/low",
    )


# --- System prompts ---


SYSTEM_DEPLOY = """\
You are an expert deception network architect planning \
honeypot and deception asset deployments.

Given the network segments and scope:
1. Recommend deception assets (honeypots, honeytokens, \
breadcrumbs) for maximum coverage
2. Place decoys to detect lateral movement and \
privilege escalation
3. Configure realistic services that attract attacker \
interaction
4. Ensure deception assets blend with production \
infrastructure

Focus on high-value targets: Active Directory, \
databases, file shares, and cloud credentials."""


SYSTEM_BEHAVIOR = """\
You are an expert threat analyst reviewing attacker \
interactions with deception assets.

Given captured interaction data from honeypots:
1. Reconstruct the attacker's TTP chain using \
MITRE ATT&CK
2. Identify lateral movement patterns and pivoting
3. Detect data exfiltration attempts and staging
4. Score risk based on sophistication and intent

Be precise about attack sequences and tool signatures."""


SYSTEM_CLASSIFY = """\
You are an expert threat intelligence analyst \
classifying attacker profiles from deception data.

Given behavioral analysis of attacker interactions:
1. Classify the attacker's sophistication level
2. Map observed TTPs to known threat actor groups
3. Assess intent (reconnaissance, exploitation, \
data theft, sabotage)
4. Identify unique indicators of compromise

Distinguish automated scanning from targeted operations."""


SYSTEM_REPORT = """\
You are an expert deception operations reporter \
synthesizing campaign intelligence.

Given the full deception campaign (decoys, interactions, \
classifications):
1. Produce an executive summary for security leadership
2. List actionable IOCs for threat detection rules
3. Recommend defensive improvements based on observed TTPs
4. Rate overall deception program effectiveness

Write clearly for both SOC analysts and executives."""
