"""LLM prompt templates and response schemas for the AI Red Team Agent."""

from typing import Any

from pydantic import BaseModel, Field

# --- Response schemas ---


class AttackScenarioOutput(BaseModel):
    """Structured output for attack scenario generation."""

    scenarios: list[dict[str, Any]] = Field(
        description="List of attack scenarios with name, description, techniques, targets"
    )
    prioritized_techniques: list[str] = Field(
        description="MITRE ATT&CK technique IDs ordered by likely effectiveness"
    )
    rationale: str = Field(
        description="Why these scenarios were selected for the target environment"
    )


class VulnerabilityAnalysisOutput(BaseModel):
    """Structured output for vulnerability analysis of probe results."""

    vulnerabilities: list[dict[str, Any]] = Field(
        description="List of discovered vulnerabilities with severity, description, affected_asset"
    )
    detection_gaps: list[str] = Field(
        description="Areas where probes were not detected by defenses"
    )
    summary: str = Field(description="Summary of the vulnerability analysis")
    risk_rating: str = Field(description="Overall risk rating: critical, high, medium, low")


class ExploitChainOutput(BaseModel):
    """Structured output for exploit chain analysis."""

    chains: list[dict[str, Any]] = Field(
        description="Exploit chains with steps, techniques, success_probability"
    )
    highest_risk_chain: dict[str, Any] = Field(
        description="The most dangerous exploit chain identified"
    )
    recommendations: list[str] = Field(
        description="Defensive recommendations to break exploit chains"
    )
    breach_probability_pct: float = Field(
        description="Estimated probability of a successful breach"
    )


# --- Prompt templates ---

SYSTEM_ATTACK_SCENARIO_GENERATION = """\
You are an expert AI red team operator generating attack scenarios \
for an authorized security assessment.

You are given:
- The target environment description
- Attack objectives (what we're trying to achieve)
- Available MITRE ATT&CK techniques to consider
- Rules of engagement (what we CAN and CANNOT do)

Your task is to:
1. Generate realistic attack scenarios targeting the environment
2. Map scenarios to MITRE ATT&CK techniques
3. Prioritize by likelihood of success and impact
4. Respect all rules of engagement boundaries

Think like a sophisticated adversary: what would an APT group do?
Focus on the most impactful and realistic paths."""

SYSTEM_VULNERABILITY_ANALYSIS = """\
You are an expert vulnerability analyst reviewing results from \
automated security probes.

You are given:
- Probe execution results (success/failure, detection status)
- Target assets and techniques used
- Detection times and triggered alerts

Your task is to:
1. Identify confirmed vulnerabilities from successful probes
2. Categorize by severity (critical, high, medium, low)
3. Identify detection gaps where attacks were not caught
4. Assess the overall risk level of the environment

Be precise about what was found and what it means for the organization."""

SYSTEM_EXPLOIT_CHAIN_ANALYSIS = """\
You are an expert red team analyst constructing exploit chains \
from individual vulnerability findings.

You are given:
- Individual probe results and vulnerabilities found
- The environment's architecture and trust relationships
- Attack scenarios that were tested

Your task is to:
1. Chain individual findings into multi-step attack paths
2. Calculate the probability of a full breach via each chain
3. Identify the highest-risk chain
4. Recommend specific defenses to break each chain

IMPORTANT:
- Only chain findings that could realistically connect
- Account for detection capabilities at each step
- Be calibrated with probability estimates"""
