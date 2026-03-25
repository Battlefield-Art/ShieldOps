"""Lateral Movement Detector Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class PathAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted movement path analysis."""

    summary: str = Field(description="Brief summary of identified lateral movement paths")
    confirmed_paths: int = Field(description="Number of confirmed lateral movement paths")
    risk_level: str = Field(description="Overall risk level: low, medium, high, critical")
    movement_patterns: list[str] = Field(
        description="Identified movement patterns with MITRE technique IDs"
    )
    false_positive_indicators: list[str] = Field(
        description="Indicators that suggest false positives to filter"
    )


class BlastRadiusOutput(BaseModel):
    """Structured output from LLM-assisted blast radius assessment."""

    summary: str = Field(description="Brief summary of blast radius findings")
    total_resources_at_risk: int = Field(
        description="Total number of resources potentially affected"
    )
    critical_assets: list[str] = Field(description="Critical assets in the blast radius")
    data_exposure_risk: str = Field(
        description="Data exposure risk level: none, low, medium, high, critical"
    )
    containment_priority: list[str] = Field(description="Prioritized list of containment actions")


class MovementResponseOutput(BaseModel):
    """Structured output from LLM-assisted response planning."""

    summary: str = Field(description="Brief summary of recommended response actions")
    immediate_actions: list[str] = Field(description="Actions to execute immediately")
    investigation_steps: list[str] = Field(description="Follow-up investigation steps")
    auto_execute_safe: bool = Field(description="Whether automated response is safe to execute")
    confidence: float = Field(description="Confidence in response plan 0.0-1.0")


class DetectionSummaryOutput(BaseModel):
    """Structured output from LLM-assisted detection summary."""

    executive_summary: str = Field(
        description="Executive summary of lateral movement detection findings"
    )
    threat_level: str = Field(description="Overall threat level: none, low, medium, high, critical")
    key_findings: list[str] = Field(description="Key findings from the detection run")
    recommendations: list[str] = Field(
        description="Strategic recommendations to prevent future lateral movement"
    )
    mitre_techniques: list[str] = Field(description="MITRE ATT&CK techniques observed")


SYSTEM_PATH_ANALYSIS = (
    "You are a security analyst specializing in identity-based lateral movement detection.\n"
    "Analyze the following identity signals and detected movement paths.\n"
    "For each path:\n"
    "1. Assess whether it represents genuine lateral movement or benign activity\n"
    "2. Map to MITRE ATT&CK techniques (T1550, T1078, T1134, T1606)\n"
    "3. Identify cross-cloud patterns: OAuth token reuse, service account pivoting,\n"
    "   federation abuse, delegation chains, credential relay\n"
    "4. Flag geo-impossible travel or temporally suspicious sequences\n"
    "5. Estimate false positive probability for each path"
)

SYSTEM_BLAST_RADIUS = (
    "You are a security impact analyst assessing the blast radius of lateral movement.\n"
    "Given the detected movement paths and affected resources:\n"
    "1. Identify all resources reachable through the movement chain\n"
    "2. Assess data exposure risk (PII, secrets, financial, infrastructure)\n"
    "3. Determine if the movement enables further privilege escalation\n"
    "4. Prioritize containment actions by impact and urgency\n"
    "5. Consider cross-cloud blast radius amplification"
)

SYSTEM_RESPONSE_PLANNING = (
    "You are an incident response planner for identity-based attacks.\n"
    "Given the lateral movement paths and blast radius assessments:\n"
    "1. Recommend immediate containment actions (revoke, disable, rotate)\n"
    "2. Assess whether automated response is safe (won't break production)\n"
    "3. Plan investigation steps to determine full scope of compromise\n"
    "4. Consider impact on legitimate workloads before recommending blocks\n"
    "5. Ensure response actions cover all affected clouds and identity providers"
)

SYSTEM_DETECTION_SUMMARY = (
    "You are a threat intelligence analyst writing an executive summary.\n"
    "Summarize the lateral movement detection findings for security leadership:\n"
    "1. Describe the overall threat level and key movement patterns detected\n"
    "2. Highlight the most critical paths and their potential impact\n"
    "3. Map all findings to MITRE ATT&CK framework\n"
    "4. Provide strategic recommendations to harden identity posture\n"
    "5. Identify gaps in visibility that should be addressed"
)
