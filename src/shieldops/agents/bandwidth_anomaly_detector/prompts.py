"""Bandwidth Anomaly Detector Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class TrafficClassificationResult(BaseModel):
    """Structured output from LLM traffic classification."""

    summary: str = Field(description="Brief summary of traffic classification")
    categories: list[str] = Field(description="Detected traffic categories for each anomaly")
    threat_indicators: list[str] = Field(
        description="Indicators of compromise or suspicious behavior"
    )
    recommended_actions: list[str] = Field(description="Recommended follow-up actions")


class BaselineAnalysisResult(BaseModel):
    """Structured output from LLM baseline analysis."""

    summary: str = Field(description="Brief summary of baseline deviations")
    deviation_explanations: list[str] = Field(
        description="Explanations for each baseline deviation"
    )
    risk_assessment: str = Field(description="Overall risk level based on deviations")
    affected_entities: list[str] = Field(description="Entities with significant deviations")


class BandwidthReportResult(BaseModel):
    """Structured output for bandwidth anomaly report."""

    executive_summary: str = Field(description="Executive summary of bandwidth analysis")
    critical_findings: list[str] = Field(
        description="Critical anomalies requiring immediate action"
    )
    exfiltration_risks: list[str] = Field(description="Potential data exfiltration or DLP risks")
    recommendations: list[str] = Field(description="Prioritized recommendations for the SOC")


SYSTEM_CLASSIFY = (
    "You are a network security analyst classifying bandwidth anomalies.\n"
    "For each anomaly:\n"
    "1. Classify the traffic pattern (spike, off-hours, large egress, "
    "crypto-mining, torrent, shadow IT, DGA, beaconing)\n"
    "2. Identify threat indicators (C2 beaconing intervals, "
    "known mining pool ports, torrent DHT signatures)\n"
    "3. Assess data exfiltration risk based on volume, destination, "
    "and timing\n"
    "4. Recommend containment or investigation actions"
)

SYSTEM_BASELINE = (
    "You are a network traffic analyst evaluating bandwidth baselines.\n"
    "Given the baseline profiles and current traffic:\n"
    "1. Identify entities with significant deviations from normal\n"
    "2. Explain likely causes for each deviation\n"
    "3. Flag off-hours activity that may indicate automated exfiltration\n"
    "4. Assess overall risk posture of the network segment"
)

SYSTEM_REPORT = (
    "You are a SOC analyst generating a bandwidth anomaly report.\n"
    "Summarize the detection run:\n"
    "1. Provide an executive summary of all bandwidth findings\n"
    "2. Highlight critical anomalies (large egress, crypto-mining, "
    "C2 beaconing)\n"
    "3. Identify potential data exfiltration or DLP violations\n"
    "4. Prioritize recommendations for the security operations team"
)
