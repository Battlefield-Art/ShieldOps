"""Security Signal Correlator Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class CorrelationInsight(BaseModel):
    """Structured output from signal correlation analysis."""

    summary: str = Field(
        description="Brief correlation analysis overview",
    )
    attack_chains: list[str] = Field(
        description="Detected multi-stage attack chains",
    )
    noise_signals: list[str] = Field(
        description="Signals identified as noise",
    )


class IncidentInsight(BaseModel):
    """Structured output from incident generation."""

    summary: str = Field(
        description="Incident generation overview",
    )
    critical_incidents: list[str] = Field(
        description="Critical incidents requiring action",
    )
    mitre_coverage: list[str] = Field(
        description="MITRE ATT&CK techniques covered",
    )


class NormalizationInsight(BaseModel):
    """Structured output from signal normalization."""

    summary: str = Field(
        description="Normalization quality overview",
    )
    unmapped_fields: list[str] = Field(
        description="Fields that could not be mapped",
    )
    recommendations: list[str] = Field(
        description="Normalization improvements",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of signal correlation",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a security signal analyst reviewing "
    "cross-domain security events.\n"
    "1. Identify multi-stage attack patterns\n"
    "2. Correlate signals across EDR, SIEM, cloud\n"
    "3. Distinguish real threats from noise\n"
    "4. Map correlations to MITRE ATT&CK framework"
)

SYSTEM_REPORT = (
    "You are a security operations advisor generating an "
    "executive signal correlation report.\n"
    "1. Summarize incidents by severity and source\n"
    "2. Highlight attack chains requiring response\n"
    "3. Quantify noise reduction achieved\n"
    "4. Recommend detection tuning improvements"
)
