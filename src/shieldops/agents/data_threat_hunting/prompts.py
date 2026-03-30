"""LLM prompt templates and response schemas for the Data Threat Hunting Agent."""

from typing import Any

from pydantic import BaseModel, Field


class HypothesisGenerationOutput(BaseModel):
    """Structured output for hypothesis generation."""

    hypotheses: list[dict[str, Any]] = Field(
        description=(
            "List of hunt hypotheses with description, mitre_techniques, target_sources, confidence"
        ),
    )
    rationale: str = Field(
        description="Overall rationale for chosen hypotheses",
    )


class IndicatorAnalysisOutput(BaseModel):
    """Structured output for indicator analysis."""

    indicators_matched: int = Field(
        description="Count of matched indicators",
    )
    severity: str = Field(
        description="Overall severity: critical/high/medium/low",
    )
    behavioral_patterns: list[str] = Field(
        description="Identified behavioral patterns",
    )
    summary: str = Field(
        description="Human-readable analysis summary",
    )


class CorrelationOutput(BaseModel):
    """Structured output for cross-source correlation."""

    findings: list[dict[str, Any]] = Field(
        description=(
            "Correlated findings with verdict, severity, confidence, sources, description"
        ),
    )
    threats_confirmed: int = Field(
        description="Number of confirmed threats",
    )
    summary: str = Field(
        description="Correlation summary for analysts",
    )


class HuntReportOutput(BaseModel):
    """Structured output for the final hunt report."""

    executive_summary: str = Field(
        description="Executive summary of the hunt",
    )
    threat_level: str = Field(
        description="Overall threat level: critical/high/medium/low",
    )
    key_findings: list[str] = Field(
        description="Top findings for leadership review",
    )
    recommended_actions: list[str] = Field(
        description="Prioritized remediation actions",
    )
    hunt_playbook: list[str] = Field(
        description="Playbook steps for analyst follow-up",
    )


SYSTEM_HYPOTHESIS_GENERATION = """\
You are an expert threat hunter specializing in data-layer \
threats across production, backup, and AI pipeline environments.

Given the hunt context (threat intel, environment profile, \
initial hypotheses):
1. Generate specific, testable hunt hypotheses
2. Map each hypothesis to MITRE ATT&CK techniques
3. Identify which data sources to target (production, \
backup_snapshot, ai_pipeline, cloud_storage, database)
4. Prioritize by likelihood and potential impact

Focus on threats that span data layers:
- Ransomware staging in backups before production encryption
- Data exfiltration through AI pipeline side channels
- Persistence mechanisms hidden in backup snapshots
- Dormant malware in cold storage awaiting restoration
- Supply chain poisoning of training data"""


SYSTEM_INDICATOR_ANALYSIS = """\
You are an expert threat analyst evaluating indicators of \
compromise across multiple data sources.

Given the collected evidence and IOC matches:
1. Assess each indicator match for true/false positive
2. Identify behavioral patterns across sources
3. Correlate temporal patterns (e.g., backup anomaly \
followed by production activity)
4. Rate overall severity considering cross-source context

Prioritize indicators showing cross-environment movement \
(backup -> production or production -> AI pipeline)."""


SYSTEM_CORRELATION = """\
You are an expert threat hunter performing cross-source \
correlation of hunt findings.

Given findings from production, backups, AI pipelines, \
and other sources:
1. Identify findings that appear across multiple sources
2. Build attack chains from correlated evidence
3. Assign verdicts: confirmed_threat, likely_threat, \
suspicious, benign, or inconclusive
4. Prioritize by blast radius and attacker capability

Key correlation patterns:
- Same IOC in production and backup (persistence)
- Backup anomaly preceding production incident (staging)
- AI pipeline data matching exfiltration patterns
- Credential usage across cloud storage and databases"""


SYSTEM_HUNT_REPORT = """\
You are a senior threat hunter producing a hunt campaign \
report for SOC leadership.

Given all findings, correlations, and backup scan results:
1. Write a concise executive summary
2. Highlight the most critical findings
3. Provide prioritized remediation actions
4. Generate a hunt playbook for analyst follow-up
5. Assess overall threat level

The report should be actionable and clear for both \
technical analysts and security leadership."""
