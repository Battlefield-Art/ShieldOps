"""Cloud Workload Protector Agent — LLM prompt templates and schemas."""

from pydantic import BaseModel, Field


class RuntimeAnalysisOutput(BaseModel):
    """LLM output for runtime anomaly analysis."""

    summary: str = Field(description="Runtime analysis summary")
    threat_level: str = Field(description="Threat: critical/high/medium/low")
    suspicious_processes: list[str] = Field(description="Suspicious processes detected")
    recommendations: list[str] = Field(description="Response recommendations")


class DriftAnalysisOutput(BaseModel):
    """LLM output for drift analysis."""

    summary: str = Field(description="Drift analysis summary")
    drift_count: int = Field(description="Total drifts detected")
    auto_fixable: int = Field(description="Auto-remediable drift count")
    priority_fixes: list[str] = Field(description="Priority drift fixes")


class VulnAssessmentOutput(BaseModel):
    """LLM output for vulnerability assessment."""

    summary: str = Field(description="Vulnerability summary")
    risk_level: str = Field(description="Risk: critical/high/medium/low")
    exploit_risk: list[str] = Field(description="Exploitable vulnerabilities")
    patch_plan: list[str] = Field(description="Recommended patch plan")


SYSTEM_RUNTIME_ANALYSIS = (
    "You are a cloud workload runtime security analyst.\n"
    "Analyze runtime behavior for anomalies:\n"
    "1. Detect suspicious process execution patterns\n"
    "2. Identify unauthorized network connections\n"
    "3. Flag file integrity violations\n"
    "4. Map anomalies to MITRE ATT&CK techniques"
)

SYSTEM_DRIFT_DETECTION = (
    "You are a cloud workload configuration drift detector.\n"
    "Analyze configuration drift from baselines:\n"
    "1. Compare running configs against approved baselines\n"
    "2. Identify security-impacting drift (firewall, users)\n"
    "3. Prioritize drift by blast radius\n"
    "4. Recommend auto-remediation where safe"
)

SYSTEM_VULN_ASSESSMENT = (
    "You are a cloud workload vulnerability assessor.\n"
    "Assess vulnerability findings across workloads:\n"
    "1. Prioritize by CVSS score and exploitability\n"
    "2. Identify actively exploited vulnerabilities\n"
    "3. Create a risk-based patch plan\n"
    "4. Recommend compensating controls for unpatchable"
)
