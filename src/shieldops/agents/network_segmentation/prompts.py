"""Network Segmentation Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ViolationAnalysisResult(BaseModel):
    """Structured output from LLM-assisted violation analysis."""

    summary: str = Field(description="Brief summary of segmentation violation findings")
    risk_level: str = Field(description="Overall risk level: low, medium, high, critical")
    lateral_movement_risk: float = Field(
        description="Probability of lateral movement exploitation 0.0-1.0"
    )
    violation_details: list[str] = Field(
        description="Detailed description of each significant violation"
    )
    recommended_actions: list[str] = Field(
        description="Recommended remediation actions in priority order"
    )


class EnforcementPlanResult(BaseModel):
    """Structured output from LLM-assisted enforcement planning."""

    summary: str = Field(description="Brief summary of the enforcement plan")
    firewall_rules: list[str] = Field(description="Firewall rules to apply")
    network_acls: list[str] = Field(description="Network ACLs to update")
    rollback_plan: str = Field(description="Rollback procedure if enforcement causes issues")
    blast_radius: str = Field(description="Estimated blast radius of enforcement changes")
    confidence: float = Field(description="Confidence in enforcement plan 0.0-1.0")


class RiskAssessmentResult(BaseModel):
    """Structured output from LLM-assisted risk assessment."""

    summary: str = Field(description="Brief risk assessment summary")
    overall_risk_score: float = Field(description="Overall segmentation risk score 0.0-1.0")
    attack_paths: list[str] = Field(description="Identified attack paths through zone boundaries")
    mitre_techniques: list[str] = Field(description="Relevant MITRE ATT&CK technique IDs")
    compliance_gaps: list[str] = Field(description="Compliance gaps related to segmentation")


SYSTEM_VIOLATION_ANALYSIS = (
    "You are a network security analyst specializing in micro-segmentation.\n"
    "Analyze the following network zone topology and traffic flow violations.\n"
    "For each violation:\n"
    "1. Assess the risk of lateral movement exploitation\n"
    "2. Identify potential attack paths across zone boundaries\n"
    "3. Map violations to MITRE ATT&CK techniques\n"
    "4. Evaluate compliance impact (PCI-DSS, SOC 2, HIPAA)\n"
    "5. Recommend specific remediation actions in priority order"
)

SYSTEM_ENFORCEMENT_PLAN = (
    "You are a network security engineer planning micro-segmentation enforcement.\n"
    "Based on the detected violations and risk assessment:\n"
    "1. Design firewall rules to block unauthorized cross-zone traffic\n"
    "2. Specify network ACL changes for each affected zone pair\n"
    "3. Estimate blast radius — which services may be impacted\n"
    "4. Provide a rollback plan in case enforcement disrupts operations\n"
    "5. Prioritize enforcement by severity and business impact"
)

SYSTEM_RISK_ASSESSMENT = (
    "You are a security risk analyst assessing network segmentation posture.\n"
    "Given the discovered zones, traffic flows, and violations:\n"
    "1. Score the overall segmentation risk from 0.0 (fully segmented) to 1.0\n"
    "2. Identify the most critical attack paths through zone boundaries\n"
    "3. Map risks to MITRE ATT&CK lateral movement techniques\n"
    "4. Flag compliance gaps for PCI-DSS (req 1), SOC 2 (CC6.6), HIPAA\n"
    "5. Provide an executive summary suitable for a CISO briefing"
)
