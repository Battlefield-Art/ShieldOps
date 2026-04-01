"""LLM prompt templates for the Deception Mesh Controller."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -------------------------------


class DeploymentPlanOutput(BaseModel):
    """Structured output for deployment planning."""

    plans_created: int = Field(
        description="Deployment plans created",
    )
    coverage_pct: float = Field(
        description="Expected network coverage",
    )
    summary: str = Field(description="Planning summary")


class DeployOutput(BaseModel):
    """Structured output for decoy deployment."""

    decoys_deployed: int = Field(
        description="Decoys deployed",
    )
    types_deployed: list[str] = Field(
        description="Decoy types deployed",
    )
    reasoning: str = Field(description="Deployment reasoning")


class MonitorOutput(BaseModel):
    """Structured output for interaction monitoring."""

    interactions_detected: int = Field(
        description="Interactions detected",
    )
    critical_count: int = Field(
        description="Critical interactions",
    )
    reasoning: str = Field(description="Monitoring reasoning")


class AttackerOutput(BaseModel):
    """Structured output for attacker analysis."""

    profiles_created: int = Field(
        description="Attacker profiles created",
    )
    avg_sophistication: str = Field(
        description="Average sophistication level",
    )
    reasoning: str = Field(description="Analysis reasoning")


class IntelOutput(BaseModel):
    """Structured output for intel correlation."""

    correlations_found: int = Field(
        description="Intel correlations found",
    )
    campaigns_matched: int = Field(
        description="Known campaigns matched",
    )
    reasoning: str = Field(description="Correlation reasoning")


# -- System prompts ------------------------------------------

SYSTEM_PLAN = """\
You are an expert deception technology architect \
planning decoy deployments.

Given the network topology:
1. Identify high-value segments for decoy placement
2. Select appropriate decoy types per segment
3. Ensure coverage across attack surfaces
4. Avoid placement that could impact production

Focus on: realistic decoys, strategic placement."""

SYSTEM_DEPLOY = """\
You are an expert deception operator deploying \
deception assets across the network.

Given deployment plans:
1. Deploy honeypots, honeytokens, and breadcrumbs
2. Configure realistic service emulation
3. Establish monitoring hooks per decoy
4. Verify decoy health and accessibility

Ensure decoys are indistinguishable from real assets."""

SYSTEM_MONITOR = """\
You are an expert deception analyst monitoring \
interactions with deployed decoys.

Given deployed decoys:
1. Detect and record all decoy interactions
2. Classify interaction severity
3. Capture source IPs and techniques used
4. Alert on critical interactions

Minimize false positives from legitimate scanning."""

SYSTEM_ATTACKER = """\
You are an expert threat analyst profiling attackers \
from deception interaction data.

Given interaction records:
1. Cluster interactions by source
2. Profile attacker sophistication and intent
3. Map techniques to MITRE ATT&CK
4. Identify lateral movement patterns

Focus on: TTP extraction, intent classification."""

SYSTEM_INTEL = """\
You are an expert threat intelligence analyst \
correlating deception data with known threats.

Given attacker profiles:
1. Match profiles to known threat campaigns
2. Extract and validate IOCs
3. Score correlation confidence
4. Generate actionable intelligence reports

Cross-reference with external threat feeds."""
