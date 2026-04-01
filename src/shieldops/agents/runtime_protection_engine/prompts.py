"""LLM prompt templates and response schemas for Runtime Protection Engine."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class TelemetryAnalysis(BaseModel):
    """LLM analysis of collected runtime telemetry."""

    summary: str = Field(description="Brief summary of telemetry collection")
    event_count: int = Field(description="Number of telemetry events collected")
    notable_patterns: list[str] = Field(description="Notable patterns in telemetry")
    agents_monitored: list[str] = Field(description="Agent IDs being monitored")


class BehaviorAnalysis(BaseModel):
    """LLM analysis of agent behavior profiles."""

    summary: str = Field(description="Brief behavior analysis summary")
    suspicious_count: int = Field(description="Number of suspicious behaviors")
    behavior_patterns: list[str] = Field(description="Key behavior patterns observed")
    risk_assessment: str = Field(description="Behavioral risk: critical/high/medium/low")


class AnomalyAnalysis(BaseModel):
    """LLM analysis of detected anomalies."""

    summary: str = Field(description="Brief anomaly detection summary")
    anomaly_count: int = Field(description="Number of anomalies detected")
    critical_anomalies: list[str] = Field(description="Critical anomaly descriptions")
    attack_indicators: list[str] = Field(description="Potential attack indicators")
    overall_threat: str = Field(description="Overall threat level: critical/high/medium/low")


class EnforcementAnalysis(BaseModel):
    """LLM analysis of policy enforcement actions."""

    summary: str = Field(description="Brief enforcement summary")
    actions_taken: int = Field(description="Number of enforcement actions")
    blocked_count: int = Field(description="Number of blocked actions")
    effectiveness: str = Field(description="Enforcement effectiveness: excellent/good/fair/poor")


class AlertAnalysis(BaseModel):
    """LLM analysis of generated alerts."""

    summary: str = Field(description="Brief alert generation summary")
    alert_count: int = Field(description="Number of alerts generated")
    priority_alerts: list[str] = Field(description="High-priority alert details")
    escalation_needed: bool = Field(description="Whether escalation is needed")


# --- Prompt templates ---

SYSTEM_COLLECT_TELEMETRY = """\
You are an expert AI runtime security analyst collecting \
and evaluating telemetry from AI agent executions.

You monitor tool calls, API invocations, resource usage, \
token consumption, and execution patterns across the \
agent fleet.

Your task is to:
1. Assess completeness and quality of collected telemetry
2. Identify gaps in monitoring coverage
3. Flag unusual patterns in tool call sequences
4. Recommend additional telemetry sources

Focus on security-relevant telemetry. \
Prioritize tool calls that access sensitive resources."""

SYSTEM_ANALYZE_BEHAVIOR = """\
You are an expert AI runtime security analyst profiling \
agent behavior from collected telemetry data.

You are given:
- Tool call sequences and frequencies
- Resource usage patterns and latency data
- Baseline behavior profiles for comparison

Your task is to:
1. Classify behavior as normal/suspicious/anomalous/malicious
2. Calculate deviation scores from baseline
3. Identify privilege escalation attempts
4. Flag data exfiltration patterns

Think carefully about context — a tool call that is \
normal for one agent may be suspicious for another."""

SYSTEM_DETECT_ANOMALIES = """\
You are an expert AI runtime security analyst detecting \
anomalies in agent behavior profiles.

You are given:
- Behavior profiles with deviation scores
- Historical baseline data
- Active threat intelligence

Your task is to:
1. Identify statistically significant anomalies
2. Assess severity and confidence for each anomaly
3. Map anomalies to MITRE ATT&CK techniques where applicable
4. Recommend enforcement actions per anomaly

IMPORTANT:
- Minimize false positives while catching real threats
- Consider temporal patterns and context
- Distinguish between anomalous and merely unusual behavior"""

SYSTEM_ENFORCE_POLICIES = """\
You are an expert AI runtime security analyst enforcing \
protection policies on detected anomalies.

You are given:
- Detected anomalies with severity and confidence
- Available enforcement actions
- Active security policies

Your task is to:
1. Select appropriate enforcement action per anomaly
2. Consider blast radius and operational impact
3. Ensure rollback capability for reversible actions
4. Document enforcement rationale

IMPORTANT:
- Block only high-confidence, high-severity anomalies
- Prefer throttling over blocking when uncertainty exists
- Never block critical business operations without human approval"""

SYSTEM_GENERATE_ALERTS = """\
You are an expert AI runtime security analyst generating \
security alerts from anomaly detection and enforcement.

You are given:
- Detected anomalies and enforcement actions
- Alert severity thresholds and routing rules
- Stakeholder notification preferences

Your task is to:
1. Generate actionable alerts with clear descriptions
2. Group related anomalies into unified alerts
3. Assign severity based on combined risk
4. Recommend next steps for SOC analysts

Write clear, actionable alert descriptions. \
Include evidence and context for investigation."""
