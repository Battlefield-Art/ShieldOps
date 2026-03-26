"""Anomaly Detector Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class AnomalyClassificationResult(BaseModel):
    """Structured output from LLM-assisted anomaly classification."""

    summary: str = Field(description="Brief summary of anomaly classification")
    classifications: list[str] = Field(
        description="Classification labels for each anomaly"
    )
    severity_assessments: list[str] = Field(
        description="Severity assessment rationale for each anomaly"
    )
    recommended_actions: list[str] = Field(
        description="Recommended follow-up actions"
    )


class CorrelationAnalysisResult(BaseModel):
    """Structured output from LLM-assisted correlation analysis."""

    summary: str = Field(description="Brief summary of correlation findings")
    correlated_groups: list[str] = Field(
        description="Groups of correlated anomalies"
    )
    root_cause_hypotheses: list[str] = Field(
        description="Possible root causes for correlated anomalies"
    )
    affected_services: list[str] = Field(
        description="Services affected by the anomalies"
    )


class AnomalyReportResult(BaseModel):
    """Structured output for anomaly detection report."""

    executive_summary: str = Field(description="Executive summary of findings")
    critical_findings: list[str] = Field(
        description="Critical anomalies requiring immediate attention"
    )
    trends: list[str] = Field(
        description="Emerging trends identified in the data"
    )
    recommendations: list[str] = Field(
        description="Prioritized recommendations for operations team"
    )


SYSTEM_CLASSIFY = (
    "You are an ML engineer classifying detected anomalies in telemetry data.\n"
    "For each anomaly:\n"
    "1. Classify the anomaly type (spike, drop, trend change, distribution shift)\n"
    "2. Assess severity based on deviation magnitude and business impact\n"
    "3. Determine confidence level based on data quality and detection method\n"
    "4. Recommend immediate actions for critical anomalies"
)

SYSTEM_CORRELATE = (
    "You are an SRE correlating multiple anomalies across services.\n"
    "Given the detected anomalies:\n"
    "1. Identify temporal and causal correlations between anomalies\n"
    "2. Group related anomalies that likely share a root cause\n"
    "3. Generate root cause hypotheses for each correlated group\n"
    "4. Identify the blast radius — which services are affected"
)

SYSTEM_REPORT = (
    "You are an observability expert generating an anomaly detection report.\n"
    "Summarize the detection run:\n"
    "1. Provide an executive summary of all findings\n"
    "2. Highlight critical anomalies requiring immediate attention\n"
    "3. Identify emerging trends that may indicate future issues\n"
    "4. Prioritize recommendations for the operations team"
)
