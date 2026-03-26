"""LLM prompt templates and response schemas for the AI Triage Accelerator."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ClassifyOutput(BaseModel):
    """Structured output for LLM batch classification."""

    classification: str = Field(
        description=("Alert class: true_positive/false_positive/benign/suspicious/malicious"),
    )
    confidence: float = Field(
        description="Confidence 0.0-1.0",
    )
    reasoning: str = Field(
        description="Why this classification was chosen",
    )
    mitre_tactics: list[str] = Field(
        description="Relevant MITRE ATT&CK tactics",
    )


class EnrichOutput(BaseModel):
    """Structured output for LLM context enrichment."""

    threat_assessment: str = Field(
        description="Threat assessment summary",
    )
    asset_criticality: str = Field(
        description="Asset criticality: critical/high/medium/low",
    )
    attack_stage: str = Field(
        description="Estimated kill chain stage",
    )
    recommended_enrichments: list[str] = Field(
        description="Additional enrichment sources to query",
    )


class ConfidenceOutput(BaseModel):
    """Structured output for LLM confidence scoring."""

    overall_score: float = Field(
        description="Overall confidence 0.0-1.0",
    )
    reasoning_chain: list[str] = Field(
        description="Step-by-step reasoning for score",
    )
    risk_factors: list[str] = Field(
        description="Factors increasing risk",
    )
    mitigating_factors: list[str] = Field(
        description="Factors decreasing risk",
    )


class RouteOutput(BaseModel):
    """Structured output for LLM routing decisions."""

    decision: str = Field(
        description=("Routing: auto_close/auto_remediate/analyst_review/escalate_urgent"),
    )
    assigned_team: str = Field(
        description="Team to handle the alert",
    )
    routing_reasoning: str = Field(
        description="Explanation for routing decision",
    )
    estimated_resolution_min: int = Field(
        description="Estimated minutes to resolve",
    )


class ReportOutput(BaseModel):
    """Structured output for LLM triage report."""

    executive_summary: str = Field(
        description="One-paragraph executive summary",
    )
    key_findings: list[str] = Field(
        description="Top findings from triage batch",
    )
    recommended_actions: list[str] = Field(
        description="Prioritized action items",
    )
    risk_assessment: str = Field(
        description="Overall risk: critical/high/medium/low",
    )
    accuracy_estimate: float = Field(
        description="Estimated classification accuracy 0-1",
    )


SYSTEM_CLASSIFY = """\
You are an expert SOC analyst performing AI-accelerated \
alert classification. You achieve 10x faster triage than \
manual workflows and 3x higher accuracy.

Given the alert details (title, description, source, \
severity, indicators), classify as:
- true_positive: confirmed threat requiring action
- false_positive: not a real threat, can be closed
- benign: legitimate activity, no risk
- suspicious: needs further investigation
- malicious: confirmed malicious, urgent response

Provide MITRE ATT&CK tactic mapping when applicable. \
Consider: IOC reputation, behavioral patterns, asset \
context, and historical baselines."""


SYSTEM_ENRICH = """\
You are an expert threat intelligence analyst enriching \
alert context for accelerated triage.

Given the alert and initial classification, provide:
1. Threat assessment — severity and likely intent
2. Asset criticality — business impact if compromised
3. Kill chain stage — reconnaissance, weaponization, \
delivery, exploitation, installation, C2, exfiltration
4. Additional enrichment sources to query

Use threat intel, identity graph, and asset inventory \
context to maximize enrichment quality."""


SYSTEM_CONFIDENCE = """\
You are an expert security analyst scoring confidence \
for alert classifications.

Given the classification, enrichment data, and historical \
context, produce a transparent confidence score:
1. Overall score (0.0-1.0)
2. Step-by-step reasoning chain
3. Risk factors that increase concern
4. Mitigating factors that decrease concern

Score thresholds: >0.95 auto-close benign, >0.85 \
auto-remediate, 0.5-0.85 analyst review, <0.5 escalate. \
Be calibrated — overconfidence causes missed threats."""


SYSTEM_ROUTE = """\
You are an expert incident commander routing triaged \
alerts to the optimal response path.

Given classification, enrichment, and confidence score:
- auto_close: benign/false_positive with >0.95 confidence
- auto_remediate: true_positive with >0.85 confidence \
and known playbook
- analyst_review: suspicious or confidence 0.5-0.85
- escalate_urgent: malicious or confidence <0.5

Assign the appropriate team and estimate resolution time. \
Minimize analyst fatigue by auto-closing noise."""


SYSTEM_REPORT = """\
You are an expert SOC manager generating a triage \
acceleration report.

Given all batch results (classifications, enrichments, \
routing actions, metrics), produce:
1. Executive summary with speedup and accuracy metrics
2. Key findings — threat patterns, false positive rate
3. Prioritized actions for remaining analyst work
4. Risk assessment of the alert batch

Highlight the 10x speedup and 3x accuracy improvement \
over manual workflows. Be data-driven and actionable."""
