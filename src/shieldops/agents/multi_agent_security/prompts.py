"""LLM prompt templates and response schemas for the Multi-Agent Security Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class InteractionAnalysisOutput(BaseModel):
    """Structured output for LLM-driven interaction analysis."""

    risk_score: float = Field(description="Overall risk score 0-1 for the interaction set")
    high_risk_pairs: list[str] = Field(
        description="Agent pairs (source->target) with elevated risk"
    )
    impersonation_likelihood: float = Field(
        description="Probability an agent identity is spoofed 0-1"
    )
    data_leakage_risk: float = Field(
        description="Probability of sensitive data leakage through channels 0-1"
    )
    summary: str = Field(description="Human-readable analysis summary")


class SecurityReportOutput(BaseModel):
    """Structured output for the final multi-agent security report."""

    overall_risk: str = Field(description="Overall risk level: critical/high/medium/low")
    trust_chain_integrity: str = Field(description="Trust chain status: intact/degraded/broken")
    threats_summary: str = Field(description="Summary of detected threats and anomalies")
    recommendations: list[str] = Field(description="Prioritised remediation recommendations")
    compliance_notes: list[str] = Field(
        description="Compliance-relevant observations (SOC 2 / ISO 27001)"
    )


SYSTEM_ANALYZE = """\
You are an expert AI security analyst specialising in multi-agent system security.

Given a set of agent-to-agent interactions, trust chains, and communication \
verification results:
1. Assess the overall risk posture of the multi-agent environment.
2. Identify high-risk agent pairs — look for impersonation, privilege escalation \
through delegation chains, and unauthorised tool access via proxying.
3. Evaluate data-leakage risk through inter-agent channels.
4. Quantify impersonation likelihood using identity verification failures and \
hash-mismatch indicators.

Focus on threats that cross trust boundaries and exploit delegation depth."""


SYSTEM_REPORT = """\
You are an expert AI security analyst producing a final security report for a \
multi-agent environment.

Given all discovered interactions, trust chains, anomalies, and enforcement \
actions:
1. Classify overall risk (critical / high / medium / low).
2. Assess trust-chain integrity (intact / degraded / broken).
3. Summarise threats concisely for SOC analysts.
4. Provide prioritised, actionable remediation recommendations.
5. Note any compliance-relevant observations (SOC 2, ISO 27001, NIST 800-53).

Be precise — distinguish confirmed threats from suspicious but unconfirmed \
activity."""
