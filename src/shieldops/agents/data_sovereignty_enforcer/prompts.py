"""Data Sovereignty Enforcer Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class SovereigntyAnalysisResult(BaseModel):
    """Structured output from LLM-assisted sovereignty analysis."""

    summary: str = Field(description="Brief summary of data sovereignty findings")
    total_flows: int = Field(description="Total number of data flows analyzed")
    cross_border_count: int = Field(description="Number of cross-border transfers detected")
    high_risk_flows: list[str] = Field(
        description="High-risk data flows requiring immediate attention"
    )
    recommended_actions: list[str] = Field(
        description="Recommended actions for sovereignty compliance"
    )


class TransferAssessmentResult(BaseModel):
    """Structured output from LLM-assisted transfer mechanism assessment."""

    summary: str = Field(description="Brief summary of transfer mechanism assessment")
    invalid_count: int = Field(description="Number of transfers lacking valid mechanisms")
    critical_gaps: list[str] = Field(description="Critical transfer mechanism gaps")
    remediation_steps: list[str] = Field(
        description="Ordered steps to establish valid transfer mechanisms"
    )
    risk_level: str = Field(description="Overall transfer risk: low, medium, high, critical")


class SovereigntyReportResult(BaseModel):
    """Structured output from LLM-assisted sovereignty report generation."""

    executive_summary: str = Field(
        description="Executive summary of the data sovereignty assessment"
    )
    compliance_posture: str = Field(
        description="Overall sovereignty compliance posture: strong, adequate, weak, critical"
    )
    top_risks: list[str] = Field(description="Top data sovereignty risks identified")
    regulatory_recommendations: list[str] = Field(
        description="Recommendations for regulatory compliance"
    )
    compliance_score: float = Field(description="Compliance score from 0.0 to 1.0")


SYSTEM_ANALYZE = (
    "You are a data sovereignty and privacy compliance specialist.\n"
    "Analyze the following cross-border data flows and jurisdiction mappings.\n"
    "For each flow:\n"
    "1. Assess whether the data transfer complies with source and destination regulations\n"
    "2. Identify Schrems II implications for EU-to-third-country transfers\n"
    "3. Check EU Data Governance Act (DGA) requirements for data sharing\n"
    "4. Evaluate China PIPL and Brazil LGPD cross-border transfer rules\n"
    "5. Validate that adequate transfer mechanisms are in place (SCCs, BCRs, adequacy)\n"
    "6. Flag any geo-fencing violations where data resides outside permitted regions\n"
    "7. Prioritize violations by regulatory penalty risk and data sensitivity"
)

SYSTEM_REPORT = (
    "You are a chief privacy officer generating a data sovereignty compliance report.\n"
    "Given the complete sovereignty enforcement results:\n"
    "1. Produce an executive summary suitable for board-level and DPA reporting\n"
    "2. Assess the overall data sovereignty compliance posture\n"
    "3. Identify top sovereignty risks and their business/legal impact\n"
    "4. Map violations to specific regulatory articles (GDPR Art. 44-49, PIPL Art. 38-43, "
    "LGPD Art. 33-36, Schrems II, EU DGA Ch. III)\n"
    "5. Recommend geo-fencing controls, transfer mechanisms, and data localization strategies\n"
    "6. Provide a compliance readiness score with supporting evidence"
)
