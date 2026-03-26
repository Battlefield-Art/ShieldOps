"""LLM prompt templates and response schemas for AI SOC Assistant."""

from pydantic import BaseModel, Field


class ParsedQueryOutput(BaseModel):
    """Structured output for query parsing."""

    query_type: str = Field(
        description="One of: investigation, threat_hunt, "
        "incident_response, compliance_check, "
        "system_status, explainer",
    )
    entities: list[str] = Field(
        description="Extracted entities: IPs, users, hosts, domains, hashes",
    )
    time_range: str = Field(
        description="Inferred time range, e.g. 24h, 7d, 30d",
    )
    intent: str = Field(
        description="One-sentence summary of analyst intent",
    )


class ReasoningOutput(BaseModel):
    """Structured output for reasoning about findings."""

    summary: str = Field(
        description="Concise summary of findings",
    )
    key_findings: list[str] = Field(
        description="Bullet-point key findings",
    )
    risk_level: str = Field(
        description="Risk level: critical/high/medium/low/info",
    )
    confidence: float = Field(
        description="Confidence in assessment 0.0-1.0",
    )
    evidence_chain: list[str] = Field(
        description="Evidence supporting the conclusion",
    )
    mitre_techniques: list[str] = Field(
        description="Relevant MITRE ATT&CK technique IDs",
    )


class ActionsOutput(BaseModel):
    """Structured output for action generation."""

    actions: list[dict[str, str]] = Field(
        description="Suggested actions with action_type, description, target, confidence",
    )
    reasoning: str = Field(
        description="Why these actions are recommended",
    )


class PresentationOutput(BaseModel):
    """Structured output for response formatting."""

    answer: str = Field(
        description="Analyst-friendly answer to the query",
    )
    evidence: list[str] = Field(
        description="Supporting evidence bullets",
    )
    follow_up_suggestions: list[str] = Field(
        description="Suggested follow-up questions",
    )


SYSTEM_PARSE_QUERY = """\
You are an AI SOC assistant parsing analyst queries.

Given a natural language query from a SOC analyst, determine:
1. Query type (investigation, threat_hunt, incident_response, \
compliance_check, system_status, explainer)
2. Extract entities (IPs, usernames, hostnames, domains, hashes)
3. Infer time range (default 24h if not specified)
4. Summarize the analyst's intent in one sentence

Be precise about entity extraction. Support queries like:
- "What happened to user john@corp.com in the last 24 hours?"
- "Hunt for lateral movement from 10.0.0.5"
- "Show me all failed logins to prod servers this week"
- "Explain what T1566 means and how to detect it"
"""


SYSTEM_REASON = """\
You are an expert SOC analyst reasoning about security findings.

Given cross-vendor context (SIEM, EDR, identity, cloud), perform:
1. Synthesize findings into a coherent narrative
2. Identify key findings and risk indicators
3. Assess overall risk level with confidence score
4. Build an evidence chain linking observations
5. Map findings to MITRE ATT&CK techniques

Think step-by-step. Be transparent about uncertainty.
Cross-correlate across vendor sources for higher confidence.
Distinguish between confirmed threats and suspicious activity."""


SYSTEM_ACTIONS = """\
You are an AI SOC assistant suggesting response actions.

Given the reasoning and evidence, recommend actions:
1. Prioritize by urgency and confidence
2. Include specific targets and parameters
3. Mark safe-to-automate vs requires-approval actions
4. Cover: SIEM queries, EDR isolation, identity checks, \
cloud scans, playbook execution, report generation

Only suggest actions supported by evidence.
Never recommend destructive actions without high confidence."""


SYSTEM_PRESENT = """\
You are an AI SOC assistant formatting results for analysts.

Given the full analysis, create a clear response:
1. Lead with the answer to the analyst's question
2. Support with evidence bullets
3. Suggest relevant follow-up questions
4. Use analyst-friendly language (not raw JSON)

Be concise but thorough. Prioritize actionable information.
Use severity indicators where appropriate."""
