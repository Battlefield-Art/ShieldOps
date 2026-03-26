"""Model Security Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ModelScanAnalysis(BaseModel):
    """Structured output from LLM-assisted model scan analysis."""

    summary: str = Field(description="Brief summary of model scan findings")
    high_risk_models: list[str] = Field(description="Model IDs flagged as high risk")
    supply_chain_concerns: list[str] = Field(
        description="Identified supply chain integrity concerns"
    )
    recommended_actions: list[str] = Field(
        description="Immediate actions recommended for detected issues"
    )


class ModelSecurityReport(BaseModel):
    """Structured output from LLM-assisted security report generation."""

    executive_summary: str = Field(description="Executive summary of model security posture")
    critical_findings: list[str] = Field(
        description="Critical findings requiring immediate remediation"
    )
    risk_assessment: str = Field(description="Overall risk assessment narrative")
    remediation_plan: list[str] = Field(
        description="Ordered remediation steps for identified issues"
    )


SYSTEM_SCAN = (
    "You are a model security analyst scanning ML/AI model artifacts for threats.\n"
    "For each model under evaluation:\n"
    "1. Assess the model source registry and publisher trustworthiness\n"
    "2. Check for known vulnerabilities in the model framework and serialization format\n"
    "3. Evaluate signature validity and supply chain provenance\n"
    "4. Identify indicators of backdoor injection, data poisoning, or weight tampering\n"
    "5. Flag models using unsafe deserialization (pickle, torch.load without weights_only)\n"
    "6. Map findings to MITRE ATLAS techniques for standardized classification"
)

SYSTEM_REPORT = (
    "You are a model security reporting specialist generating executive-level summaries.\n"
    "Given the scan results, provenance checks, backdoor indicators, and integrity assessments:\n"
    "1. Produce an executive summary of the organization's model security posture\n"
    "2. Highlight critical findings that require immediate remediation\n"
    "3. Provide a risk assessment narrative covering supply chain, integrity, and backdoor risks\n"
    "4. Recommend an ordered remediation plan prioritized by risk severity\n"
    "5. Include compliance implications (SOC 2, NIST AI RMF, EU AI Act) where applicable"
)
