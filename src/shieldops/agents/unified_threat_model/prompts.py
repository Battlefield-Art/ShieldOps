"""LLM prompt templates for the Unified Threat Model Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -----------------------------------------


class ScopeDefinitionOutput(BaseModel):
    """Structured output for scope definition."""

    total_assets: int = Field(
        description="Total assets in scope",
    )
    data_flow_count: int = Field(
        description="Number of data flows identified",
    )
    summary: str = Field(
        description="Scope definition summary",
    )


class ThreatIdentificationOutput(BaseModel):
    """Structured output for threat identification."""

    threats_found: int = Field(
        description="Total threats identified",
    )
    critical_threats: int = Field(
        description="Number of critical threats",
    )
    reasoning: str = Field(
        description="Threat identification reasoning",
    )


class ControlAnalysisOutput(BaseModel):
    """Structured output for control analysis."""

    controls_analyzed: int = Field(
        description="Number of controls analyzed",
    )
    gaps_found: int = Field(
        description="Number of control gaps",
    )
    reasoning: str = Field(
        description="Control analysis reasoning",
    )


class RiskCalculationOutput(BaseModel):
    """Structured output for risk calculation."""

    max_risk_score: float = Field(
        description="Highest risk score 0-100",
    )
    critical_count: int = Field(
        description="Number of critical-risk threats",
    )
    reasoning: str = Field(
        description="Risk calculation reasoning",
    )


class MitigationOutput(BaseModel):
    """Structured output for mitigation prioritization."""

    mitigations: list[dict[str, str]] = Field(
        description="Prioritized mitigations with action",
    )
    total_risk_reduction: float = Field(
        description="Estimated total risk reduction 0-100",
    )
    reasoning: str = Field(
        description="Mitigation reasoning",
    )


# -- System prompts ----------------------------------------------------

SYSTEM_SCOPE = """\
You are an expert threat modeler defining the scope \
of a threat model.

Given the configuration and target system:
1. Identify all assets within the modeling boundary
2. Map data flows between components and services
3. Define trust boundaries and security zones
4. Catalog external interfaces and entry points

Focus on: microservices, APIs, databases, message \
queues, and cloud infrastructure boundaries."""

SYSTEM_THREATS = """\
You are an expert threat modeler using STRIDE methodology \
to identify threats.

Given the defined scope:
1. Apply STRIDE to each component and data flow
2. Identify spoofing, tampering, repudiation, info \
disclosure, DoS, and privilege escalation threats
3. Map attack vectors and techniques per threat
4. Calculate DREAD scores for severity

Consider: OWASP Top 10, MITRE ATT&CK, and known \
vulnerability patterns."""

SYSTEM_CONTROLS = """\
You are an expert threat modeler analyzing existing \
security controls.

Given the identified threats:
1. Map existing controls to each threat
2. Assess control effectiveness (0-1 scale)
3. Identify control gaps and weak points
4. Evaluate compensating controls

Consider: defense-in-depth, control redundancy, and \
failure modes."""

SYSTEM_RISK = """\
You are an expert threat modeler calculating risk scores.

Given the threats and control analysis:
1. Calculate likelihood based on attack complexity \
and control gaps
2. Assess impact using business criticality and data \
sensitivity
3. Compute risk scores (likelihood x impact)
4. Determine residual risk after controls

Use DREAD methodology: Damage, Reproducibility, \
Exploitability, Affected Users, Discoverability."""

SYSTEM_PRIORITIZE = """\
You are an expert threat modeler prioritizing mitigations.

Given the risk calculations:
1. Rank mitigations by risk reduction per effort
2. Identify quick wins and strategic investments
3. Group related mitigations for efficiency
4. Define implementation timelines

Balance: risk reduction, implementation cost, \
operational impact, and compliance requirements."""
