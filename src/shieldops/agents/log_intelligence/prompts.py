"""LLM prompt templates and response schemas for the Log Intelligence Agent."""

from pydantic import BaseModel, Field


class PatternAnalysisOutput(BaseModel):
    """Structured output for LLM-enhanced pattern detection."""

    pattern_type: str = Field(
        description="Pattern category: anomaly/security_event/error_spike/behavioral/compliance"
    )
    description: str = Field(description="Human-readable pattern description")
    severity: str = Field(description="Severity: critical/high/medium/low/info")
    likely_cause: str = Field(description="Most probable root cause")
    recommended_action: str = Field(description="Suggested remediation step")
    confidence: float = Field(description="Confidence in analysis 0-1")


class ThreatCorrelationOutput(BaseModel):
    """Structured output for LLM-enhanced threat correlation."""

    threat_category: str = Field(description="Category of threat identified")
    mitre_technique: str = Field(description="MITRE ATT&CK technique ID if applicable")
    description: str = Field(description="Narrative of the threat chain")
    severity: str = Field(description="Severity: critical/high/medium/low")
    confidence: float = Field(description="Confidence in correlation 0-1")
    ioc_indicators: list[str] = Field(description="Indicators of compromise found")
    recommended_action: str = Field(description="Recommended response action")


class InsightOutput(BaseModel):
    """Structured output for LLM-generated log insights."""

    title: str = Field(description="Concise insight title")
    description: str = Field(description="Detailed insight explanation")
    insight_type: str = Field(description="Type: security/operational/compliance")
    priority: str = Field(description="Priority: critical/high/medium/low")
    recommendation: str = Field(description="Actionable recommendation")


class ReportOutput(BaseModel):
    """Structured output for final log intelligence report."""

    summary: str = Field(description="Executive summary of log intelligence")
    key_findings: list[str] = Field(description="Top findings ranked by severity")
    threat_assessment: str = Field(description="Overall threat posture assessment")
    recommendations: list[str] = Field(description="Actionable recommendations")
    risk_level: str = Field(description="Overall risk: critical/high/medium/low")


SYSTEM_PATTERN_ANALYSIS = """\
You are an expert log analyst performing intelligent \
pattern detection across multi-source logs.

Given normalized log data from multiple sources \
(Splunk, Elastic, CloudWatch, GCP, Datadog, syslog):
1. Identify anomalous patterns by type (anomaly, \
security_event, error_spike, behavioral, compliance)
2. Assess severity based on deviation and service impact
3. Hypothesize root cause using cross-source correlation

Focus on patterns invisible to single-source SIEM tools.\
"""


SYSTEM_THREAT_CORRELATION = """\
You are an expert threat analyst correlating log patterns \
to security threats.

Given detected patterns across heterogeneous log sources:
1. Map patterns to MITRE ATT&CK techniques where applicable
2. Identify attack chains spanning multiple services
3. Extract IOCs (IPs, domains, hashes, user agents)
4. Assess threat severity and confidence

Leverage cross-source visibility that proprietary SIEMs lack.\
"""


SYSTEM_INSIGHT_GENERATION = """\
You are an expert log intelligence analyst generating \
actionable insights.

Given patterns and threat correlations from multi-source \
log analysis:
1. Synthesize findings into clear, prioritized insights
2. Distinguish security vs operational vs compliance issues
3. Provide specific, actionable recommendations
4. Highlight blind spots only visible via cross-source analysis

Be concise and focus on what requires immediate action.\
"""


SYSTEM_REPORT = """\
You are an expert log intelligence analyst generating an \
executive report.

Given the full analysis context (patterns, threats, insights):
1. Summarize findings in clear, non-technical language
2. Assess overall threat posture
3. Rank recommendations by business impact
4. Highlight cross-source intelligence advantages

Be concise — focus on what matters and what to do about it.\
"""
