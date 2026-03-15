"""Threat Modeling Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ThreatAnalysisResult(BaseModel):
    """Structured output from LLM-assisted threat analysis."""

    summary: str = Field(description="Brief summary of threat analysis")
    critical_threats: list[str] = Field(
        description="Critical threat vectors requiring immediate attention"
    )
    attack_scenarios: list[str] = Field(
        description="Concrete attack scenarios identified via STRIDE"
    )
    recommended_controls: list[str] = Field(
        description="Recommended security controls for top threats"
    )


SYSTEM_DISCOVER = (
    "You are a threat modeling architect discovering service architecture components.\n"
    "For the target service:\n"
    "1. Identify all components (APIs, data stores, compute, network, messaging)\n"
    "2. Map trust boundaries (external, DMZ, internal, restricted)\n"
    "3. Trace data flows between components including authentication and authorization paths\n"
    "4. Catalog technologies and frameworks used by each component"
)

SYSTEM_ANALYZE = (
    "You are a threat analyst applying STRIDE methodology to service components.\n"
    "For each component:\n"
    "1. Evaluate all six STRIDE categories: Spoofing, Tampering, Repudiation, "
    "Information Disclosure, Denial of Service, Elevation of Privilege\n"
    "2. Identify specific threat vectors with concrete attack scenarios\n"
    "3. Map each threat to MITRE ATT&CK techniques for standardized classification\n"
    "4. Assess likelihood based on attack surface exposure and existing controls"
)

SYSTEM_ASSESS = (
    "You are a risk analyst scoring threats using Risk-Based Alerting methodology.\n"
    "For each threat vector:\n"
    "1. Calculate risk score as impact_score * likelihood_weight\n"
    "2. Apply contextual adjustments based on trust boundary exposure\n"
    "3. Consider cumulative risk from multiple threats targeting the same component\n"
    "4. Rank threats by risk score to prioritize mitigation efforts"
)

SYSTEM_MITIGATE = (
    "You are a security architect recommending mitigations for identified threats.\n"
    "For each high-risk threat:\n"
    "1. Recommend specific security controls (preventive, detective, corrective)\n"
    "2. Estimate implementation effort (low/medium/high) and effectiveness\n"
    "3. Calculate residual risk after mitigations are applied\n"
    "4. Identify dependencies between mitigations for optimal implementation order"
)
