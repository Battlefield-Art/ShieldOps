"""Serverless Security Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class PermissionAnalysisOutput(BaseModel):
    """LLM output for permission analysis."""

    summary: str = Field(description="Permission analysis summary")
    over_privileged_count: int = Field(description="Functions with excessive permissions")
    recommendations: list[str] = Field(description="Permission tightening recommendations")


class DependencyScanOutput(BaseModel):
    """LLM output for dependency scanning."""

    summary: str = Field(description="Dependency scan summary")
    critical_vulns: int = Field(description="Critical vulnerabilities")
    remediation_steps: list[str] = Field(description="Remediation steps")


class ThreatAssessmentOutput(BaseModel):
    """LLM output for threat assessment."""

    summary: str = Field(description="Threat assessment summary")
    risk_level: str = Field(description="Overall risk: critical/high/medium/low")
    attack_vectors: list[str] = Field(description="Identified attack vectors")
    mitigations: list[str] = Field(description="Recommended mitigations")


SYSTEM_PERMISSION_ANALYSIS = (
    "You are a serverless security analyst.\n"
    "Analyze IAM permissions for serverless functions:\n"
    "1. Identify over-privileged roles (wildcard actions, admin)\n"
    "2. Flag functions with access to sensitive resources\n"
    "3. Recommend least-privilege policy refinements\n"
    "4. Detect cross-account trust issues"
)

SYSTEM_DEPENDENCY_SCAN = (
    "You are a serverless dependency security scanner.\n"
    "Analyze function dependencies for vulnerabilities:\n"
    "1. Identify CVEs in runtime dependencies\n"
    "2. Flag outdated packages with known exploits\n"
    "3. Detect malicious or typosquatted packages\n"
    "4. Recommend version upgrades and mitigations"
)

SYSTEM_THREAT_ASSESSMENT = (
    "You are a serverless threat detection specialist.\n"
    "Assess threats targeting serverless functions:\n"
    "1. Detect cold start timing attacks\n"
    "2. Identify event injection vulnerabilities\n"
    "3. Flag data exfiltration via environment variables\n"
    "4. Map threats to MITRE ATT&CK serverless techniques"
)
