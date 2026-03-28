"""LLM prompt templates and response schemas for the Threat Feed Manager."""

from __future__ import annotations

from pydantic import BaseModel, Field


class NormalizeOutput(BaseModel):
    """Structured output for IOC normalization."""

    ioc_type: str = Field(description="IOC type: ip/domain/hash/url/email/cve")
    severity: str = Field(description="Severity: critical/high/medium/low")
    confidence: float = Field(description="Confidence score 0.0-1.0")
    tags: list[str] = Field(description="Relevant tags for the IOC")


class ScoreOutput(BaseModel):
    """Structured output for feed scoring."""

    reliability: float = Field(description="Feed reliability 0.0-1.0")
    freshness: float = Field(description="Data freshness 0.0-1.0")
    coverage: float = Field(description="Threat coverage 0.0-1.0")
    recommendation: str = Field(description="Keep/deprioritize/remove recommendation")


class EnrichOutput(BaseModel):
    """Structured output for IOC enrichment."""

    threat_actor: str = Field(description="Associated threat actor if known")
    campaign: str = Field(description="Associated campaign if known")
    mitre_tactics: list[str] = Field(description="MITRE ATT&CK tactics")
    risk_summary: str = Field(description="One-sentence risk summary")


class ReportOutput(BaseModel):
    """Structured output for feed management report."""

    executive_summary: str = Field(description="One-paragraph summary")
    top_iocs: list[str] = Field(description="Top 5 IOCs by severity")
    feed_health_summary: str = Field(description="Overall feed health")
    recommendations: list[str] = Field(description="Action recommendations")


SYSTEM_NORMALIZE = """\
You are an expert threat intelligence analyst \
normalizing indicators of compromise.

Given raw IOC data from a threat feed, determine:
1. IOC type (ip, domain, hash, url, email, cve)
2. Severity (critical, high, medium, low)
3. Confidence score (0.0-1.0)
4. Relevant tags (malware family, campaign, TTP)

Be precise and conservative with confidence scores."""


SYSTEM_SCORE = """\
You are an expert threat intelligence manager \
evaluating feed quality.

Given feed statistics and IOC data, score:
1. Reliability (false positive rate, accuracy)
2. Freshness (age of indicators, update frequency)
3. Coverage (breadth of threat landscape covered)

Recommend keep, deprioritize, or remove."""


SYSTEM_ENRICH = """\
You are an expert threat intelligence analyst \
enriching IOCs with contextual information.

Given a normalized IOC, determine:
1. Associated threat actor (if attributable)
2. Campaign linkage
3. MITRE ATT&CK tactics and techniques
4. Risk summary for SOC analysts

Only include high-confidence attributions."""


SYSTEM_REPORT = """\
You are an expert threat intelligence manager \
generating a feed management summary.

Given all feed data, IOCs, and scores, produce:
1. Concise executive summary
2. Top IOCs by severity
3. Feed health overview
4. Actionable recommendations

Be direct and prioritize actionable insights."""
