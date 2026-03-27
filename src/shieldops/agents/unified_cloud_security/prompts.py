"""Unified Cloud Security Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class CloudStateInsight(BaseModel):
    """Structured output from cloud state collection."""

    summary: str = Field(description="Multi-cloud state overview")
    misconfig_hotspots: list[str] = Field(description="Clouds with most misconfigurations")
    coverage_gaps: list[str] = Field(description="Gaps in cloud security coverage")


class PostureInsight(BaseModel):
    """Structured output from posture assessment."""

    summary: str = Field(description="Security posture overview")
    weakest_functions: list[str] = Field(description="Weakest security function areas")
    benchmark_failures: list[str] = Field(description="Key benchmark compliance failures")


class ThreatInsight(BaseModel):
    """Structured output from threat detection."""

    summary: str = Field(description="Cloud threat detection overview")
    attack_patterns: list[str] = Field(description="Detected attack patterns")
    cross_cloud_risks: list[str] = Field(description="Cross-cloud attack vectors")


class ResponseInsight(BaseModel):
    """Structured output from response orchestration."""

    summary: str = Field(description="Response orchestration overview")
    automation_gaps: list[str] = Field(description="Areas needing more automation")
    playbook_recommendations: list[str] = Field(description="Suggested new playbooks")


SYSTEM_COLLECT = (
    "You are a multi-cloud security architect "
    "assessing cloud infrastructure state.\n"
    "1. Compare resource counts across providers\n"
    "2. Identify misconfiguration density by cloud\n"
    "3. Flag shadow cloud resources\n"
    "4. Assess identity sprawl across platforms"
)

SYSTEM_POSTURE = (
    "You are a cloud security posture analyst.\n"
    "1. Evaluate CSPM, CWPP, CDR, CIEM, DSPM scores\n"
    "2. Identify weakest security functions\n"
    "3. Compare posture across cloud providers\n"
    "4. Map to CIS and NIST benchmarks"
)

SYSTEM_THREAT = (
    "You are a cloud threat detection specialist.\n"
    "1. Classify threats by MITRE Cloud Matrix\n"
    "2. Identify cross-cloud attack chains\n"
    "3. Assess threat actor sophistication\n"
    "4. Correlate threats across providers"
)

SYSTEM_RESPONSE = (
    "You are a cloud security response orchestrator.\n"
    "1. Match threats to response playbooks\n"
    "2. Prioritize automated vs manual responses\n"
    "3. Estimate containment time per action\n"
    "4. Identify cross-cloud remediation needs"
)
