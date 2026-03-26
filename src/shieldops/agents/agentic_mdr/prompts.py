"""LLM prompt templates and response schemas for Agentic MDR."""

from pydantic import BaseModel, Field

# ------------------------------------------------------------------
# Structured output schemas
# ------------------------------------------------------------------


class TriageLLMOutput(BaseModel):
    """LLM output for auto-triage."""

    priority: str = Field(description="critical / high / medium / low / info")
    confidence: float = Field(description="Confidence in the triage 0-1")
    decision: str = Field(description=("auto_remediate | human_approve | escalate | suppress"))
    investigation_depth: str = Field(description="shallow / standard / deep / forensic")
    mitre_techniques: list[str] = Field(description="MITRE ATT&CK IDs (e.g. T1059.001)")
    reasoning: str = Field(description="Short reasoning for the triage decision")


class InvestigateLLMOutput(BaseModel):
    """LLM output for investigation analysis."""

    description: str = Field(description="Finding description")
    severity: str = Field(description="critical / high / medium / low")
    kill_chain_phase: str = Field(
        description=("recon / weaponize / deliver / exploit / install / c2 / action")
    )
    mitre_techniques: list[str] = Field(description="MITRE ATT&CK technique IDs")
    ioc_indicators: list[str] = Field(description="IOCs discovered (IPs, hashes, domains)")
    confidence: float = Field(description="Confidence in the finding 0-1")
    recommended_actions: list[str] = Field(description="Recommended response actions")


class ReportLLMOutput(BaseModel):
    """LLM output for the final MDR report."""

    executive_summary: str = Field(description="1-paragraph executive summary")
    timeline: list[str] = Field(description="Chronological event timeline")
    root_cause: str = Field(description="Root cause analysis")
    actions_taken: list[str] = Field(description="Actions executed and their outcomes")
    recommendations: list[str] = Field(description="Forward-looking recommendations")
    severity_final: str = Field(description="Final severity after investigation")


# ------------------------------------------------------------------
# System prompts
# ------------------------------------------------------------------

SYSTEM_TRIAGE = """\
You are the ShieldOps Agentic MDR triage engine — a vendor-neutral, \
machine-speed managed detection and response system.

You are triaging security alerts ingested from multiple vendors \
(CrowdStrike Falcon, Microsoft Defender, Wiz, Splunk, Elastic, \
and others). Determine the correct priority, confidence, and \
response decision for each alert.

Decision thresholds:
- confidence >= 0.85 AND low blast-radius -> auto_remediate
- 0.50 <= confidence < 0.85 -> human_approve
- confidence < 0.50 -> escalate to senior analyst
- known false-positive pattern -> suppress

Consider:
1. Cross-vendor signal reinforcement
2. MITRE ATT&CK alignment
3. Temporal clustering of related events
4. Asset criticality (production, crown jewels, privileged)
5. Historical false-positive rate for this alert type"""

SYSTEM_INVESTIGATE = """\
You are the ShieldOps Agentic MDR investigation engine performing \
deep cross-vendor analysis.

Given the triaged alerts and their enrichment data, correlate \
signals across CrowdStrike, Defender, Wiz, Splunk, and Elastic \
to build a complete attack narrative.

Provide:
1. Kill chain phase mapping
2. MITRE ATT&CK technique identification (sub-techniques)
3. IOC extraction (IPs, domains, hashes, user agents)
4. Cross-vendor correlation — signals one vendor missed that \
   another caught
5. Blast radius assessment

Your vendor-neutral view is the key differentiator. Single-vendor \
MDR misses the full picture."""

SYSTEM_REPORT = """\
You are the ShieldOps Agentic MDR report generator.

Given the full investigation findings, response actions, and \
validation results, produce a concise incident report suitable \
for both executive stakeholders and SOC analysts.

Include:
1. Executive summary (1 paragraph)
2. Chronological timeline
3. Root cause analysis
4. Actions taken and their outcomes
5. Forward-looking recommendations
6. Final severity assessment

Be precise, evidence-based, and vendor-neutral."""
