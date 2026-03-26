"""Insider Threat Detection Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class DeviationAnalysisOutput(BaseModel):
    """LLM output for behavioral deviation analysis."""

    summary: str = Field(description="Brief summary of detected deviations")
    confirmed_deviations: int = Field(description="Number of confirmed real deviations")
    risk_level: str = Field(description="Overall risk: low, medium, high, critical")
    behavioral_patterns: list[str] = Field(description="Identified insider threat patterns")
    false_positive_indicators: list[str] = Field(
        description="Indicators suggesting false positives"
    )


class RiskAssessmentOutput(BaseModel):
    """LLM output for insider risk assessment."""

    summary: str = Field(description="Brief summary of risk assessment")
    highest_risk_users: list[str] = Field(description="User IDs with highest risk")
    primary_category: str = Field(
        description=(
            "Primary risk category: flight_risk, data_theft, sabotage, espionage, negligence"
        )
    )
    urgency: str = Field(description="Response urgency: immediate, urgent, normal")
    recommended_actions: list[str] = Field(description="Prioritized recommended actions")


class InvestigationOutput(BaseModel):
    """LLM output for investigation planning."""

    summary: str = Field(description="Brief summary of investigation findings")
    investigation_steps: list[str] = Field(description="Recommended investigation steps")
    evidence_gaps: list[str] = Field(description="Missing evidence to gather")
    containment_safe: bool = Field(description="Whether auto-containment is safe")
    confidence: float = Field(description="Confidence in findings 0.0-1.0")


class InsiderReportOutput(BaseModel):
    """LLM output for executive report generation."""

    executive_summary: str = Field(description="Executive summary of insider threat findings")
    threat_level: str = Field(description="Overall threat: none, low, medium, high, critical")
    key_findings: list[str] = Field(description="Key findings from the detection run")
    recommendations: list[str] = Field(description="Strategic recommendations")
    mitre_techniques: list[str] = Field(description="MITRE ATT&CK techniques observed")


SYSTEM_DEVIATION_ANALYSIS = (
    "You are a behavioral analytics expert specializing "
    "in insider threat detection.\n"
    "Analyze the following user behavioral deviations:\n"
    "1. Assess whether each deviation is genuine insider "
    "threat activity or benign behavior\n"
    "2. Correlate across signal sources: identity, HR, "
    "DLP, code repos, AI tool usage\n"
    "3. Identify compound patterns (e.g. resignation + "
    "data hoarding = flight risk)\n"
    "4. Flag temporal patterns: off-hours + bulk access\n"
    "5. Estimate false positive probability for each"
)

SYSTEM_RISK_ASSESSMENT = (
    "You are an insider risk analyst assessing user "
    "threat levels.\n"
    "Given the behavioral deviations and scores:\n"
    "1. Classify the primary risk category: flight_risk, "
    "data_theft, sabotage, espionage, negligence\n"
    "2. Assess urgency of response required\n"
    "3. Cross-reference indicators across all signal "
    "sources for corroboration\n"
    "4. Consider organizational context (department, "
    "privilege level, tenure)\n"
    "5. Recommend proportionate response actions"
)

SYSTEM_INVESTIGATION = (
    "You are a security investigator planning an insider "
    "threat investigation.\n"
    "Given high-risk user profiles and evidence:\n"
    "1. Plan investigation steps to confirm or refute "
    "the threat\n"
    "2. Identify evidence gaps that need to be filled\n"
    "3. Assess whether automated containment is safe\n"
    "4. Consider legal and HR implications\n"
    "5. Ensure investigation does not alert the subject"
)

SYSTEM_REPORT = (
    "You are a threat intelligence analyst writing an "
    "executive insider threat report.\n"
    "Summarize findings for security leadership:\n"
    "1. Overall threat level and key behavioral patterns\n"
    "2. Highlight highest-risk users and categories\n"
    "3. Map findings to MITRE ATT&CK insider techniques\n"
    "4. Provide strategic recommendations for insider "
    "threat program improvement\n"
    "5. Identify monitoring gaps and blind spots"
)
