"""Cloud Workload Protector Agent — LLM prompts and schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ---------------------------------------------------------------
# Structured output schemas
# ---------------------------------------------------------------


class AnomalyAnalysisOutput(BaseModel):
    """LLM output for runtime anomaly analysis."""

    summary: str = Field(
        description="Summary of runtime anomalies",
    )
    risk_level: str = Field(
        description="Overall risk: critical/high/medium/low",
    )
    container_escapes: int = Field(
        description="Number of container escape attempts",
    )
    attack_patterns: list[str] = Field(
        description="Identified attack patterns or TTPs",
    )
    recommendations: list[str] = Field(
        description="Prioritized containment steps",
    )


class DriftAnalysisOutput(BaseModel):
    """LLM output for file integrity drift analysis."""

    summary: str = Field(
        description="Summary of drift findings",
    )
    tampered_binaries: int = Field(
        description="Count of tampered system binaries",
    )
    unauthorized_changes: list[str] = Field(
        description="Unauthorized file changes found",
    )
    rootkit_indicators: bool = Field(
        description="Whether rootkit indicators exist",
    )


class VulnAssessmentOutput(BaseModel):
    """LLM output for vulnerability assessment."""

    summary: str = Field(
        description="Vulnerability assessment summary",
    )
    exploitable_count: int = Field(
        description="Actively exploitable vuln count",
    )
    critical_cves: list[str] = Field(
        description="Critical CVEs needing action now",
    )
    patch_priority: list[str] = Field(
        description="Recommended patching priority",
    )


class ContainmentPlanOutput(BaseModel):
    """LLM output for threat containment planning."""

    summary: str = Field(
        description="Containment plan summary",
    )
    isolated_workloads: int = Field(
        description="Number of workloads to isolate",
    )
    actions_taken: list[str] = Field(
        description="Containment actions applied",
    )
    risk_after: str = Field(
        description="Residual risk after containment",
    )


class WorkloadReportOutput(BaseModel):
    """LLM output for workload protection report."""

    summary: str = Field(
        description="Executive protection summary",
    )
    protection_score: float = Field(
        description="Overall protection score 0-100",
    )
    key_findings: list[str] = Field(
        description="Top findings across workloads",
    )
    score_justification: str = Field(
        description="Justification for the score",
    )


# ---------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------

SYSTEM_ANOMALY_DETECTION = (
    "You are a runtime workload security analyst.\n"
    "Analyze runtime anomalies across cloud workloads:\n"
    "1. Classify anomalies by MITRE ATT&CK technique\n"
    "2. Detect container escape attempts (nsenter, "
    "mount namespace, cgroup breakout)\n"
    "3. Identify crypto-mining, reverse shells, and "
    "lateral movement patterns\n"
    "4. Prioritize by blast radius and exploitability"
)

SYSTEM_DRIFT_ANALYSIS = (
    "You are a file integrity monitoring specialist.\n"
    "Analyze drift findings on cloud workloads:\n"
    "1. Detect unauthorized changes to system binaries "
    "and configuration files\n"
    "2. Identify rootkit indicators (modified libc, "
    "hidden processes, kernel modules)\n"
    "3. Distinguish legitimate updates from malicious "
    "tampering\n"
    "4. Flag supply chain compromise indicators"
)

SYSTEM_VULN_ASSESSMENT = (
    "You are a vulnerability assessment specialist.\n"
    "Assess vulnerabilities in workload images and "
    "runtimes:\n"
    "1. Prioritize CVEs by CVSS score and "
    "exploitability (EPSS)\n"
    "2. Identify actively exploited vulnerabilities "
    "(KEV catalog)\n"
    "3. Map vulns to running workloads for blast "
    "radius estimation\n"
    "4. Recommend patching order by risk reduction"
)

SYSTEM_CONTAINMENT = (
    "You are a workload threat containment planner.\n"
    "Plan containment for detected threats:\n"
    "1. Isolate compromised workloads via network "
    "policy or security group changes\n"
    "2. Kill malicious processes without disrupting "
    "legitimate services\n"
    "3. Quarantine affected container images\n"
    "4. Provide rollback guidance for all actions"
)

SYSTEM_REPORT = (
    "You are a cloud workload protection analyst.\n"
    "Generate an executive report on workload "
    "security:\n"
    "1. Summarize runtime anomalies, drift findings, "
    "and vulnerabilities\n"
    "2. Score overall workload protection posture "
    "(0-100)\n"
    "3. Highlight critical findings requiring "
    "immediate action\n"
    "4. Provide strategic recommendations for "
    "hardening"
)
