"""LLM prompt templates and response schemas for the
Security Copilot Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class QueryParsingOutput(BaseModel):
    """Structured output for query parsing."""

    category: str = Field(
        description="Query category: threat_investigation, vulnerability_triage, etc.",
    )
    intent: str = Field(
        description="Parsed intent of the analyst query",
    )
    entities: list[str] = Field(
        description="Named entities extracted (IPs, CVEs, hosts, users)",
    )
    urgency: str = Field(
        description="Urgency: critical/high/medium/low",
    )


class AnalysisOutput(BaseModel):
    """Structured output for security analysis."""

    findings: list[str] = Field(
        description="Key findings from context analysis",
    )
    risk_score: float = Field(
        description="Aggregate risk score 0-10",
    )
    attack_stage: str = Field(
        description="MITRE ATT&CK kill chain stage if applicable",
    )
    summary: str = Field(
        description="Analysis summary for the analyst",
    )


class RecommendationOutput(BaseModel):
    """Structured output for action recommendations."""

    recommendations: list[dict[str, str]] = Field(
        description="List of recommendations with action, title, description",
    )
    top_priority: str = Field(
        description="Most urgent recommended action",
    )
    confidence: float = Field(
        description="Overall recommendation confidence 0-1",
    )
    automated_actions: list[str] = Field(
        description="Actions that can be automated safely",
    )


class ReportOutput(BaseModel):
    """Structured output for final copilot report."""

    executive_summary: str = Field(
        description="Summary of the copilot interaction",
    )
    query_resolved: bool = Field(
        description="Whether the analyst's query was resolved",
    )
    actions_taken: list[str] = Field(
        description="Actions executed during session",
    )
    follow_up_items: list[str] = Field(
        description="Suggested follow-up items",
    )
    knowledge_gained: str = Field(
        description="New knowledge for future queries",
    )


# --- System prompts ---


SYSTEM_QUERY_PARSE = """\
You are an expert security copilot parsing analyst \
queries into structured intents.

Given a natural language security query:
1. Classify the query category (threat, vulnerability, \
incident, compliance, configuration, general)
2. Extract the core intent and desired outcome
3. Identify named entities (IPs, CVEs, hostnames, users, \
services)
4. Assess urgency based on indicators of compromise or \
active threats

Be precise — misclassification wastes analyst time."""


SYSTEM_ANALYSIS = """\
You are an expert security analyst reviewing gathered \
context to answer an analyst's query.

Given the security context from multiple sources:
1. Correlate signals across alerts, incidents, and \
threat intelligence
2. Identify the attack stage using MITRE ATT&CK framework
3. Score risk based on asset criticality and threat severity
4. Produce a clear, actionable summary

Prioritize accuracy over speed. False conclusions \
erode trust."""


SYSTEM_RECOMMEND = """\
You are an expert security copilot recommending actions \
for a security analyst.

Given the analysis of a security situation:
1. Recommend specific, prioritized actions
2. Distinguish between automated and manual actions
3. Assess confidence in each recommendation
4. Consider blast radius and reversibility of actions

Err on the side of caution for destructive actions. \
Always offer an escalation path."""


SYSTEM_REPORT = """\
You are an expert security copilot generating a session \
report for an analyst interaction.

Given the full copilot session (query, context, analysis, \
actions):
1. Summarize the interaction and outcomes
2. Document all actions taken and their results
3. Suggest follow-up items for continued investigation
4. Capture knowledge for future similar queries

Write for both the analyst and their team lead."""
