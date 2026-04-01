"""LLM prompt templates and response schemas for Data Security Posture."""

from pydantic import BaseModel, Field

# ── Structured Output Schemas ───────────────────────────────


class DataDiscoveryOutput(BaseModel):
    """LLM output for data store discovery."""

    stores_found: int = Field(
        description="Number of data stores discovered",
    )
    cloud_stores: int = Field(
        description="Number of cloud-hosted stores",
    )
    summary: str = Field(
        description="Summary of discovered data stores",
    )
    risk_level: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


class ClassificationOutput(BaseModel):
    """LLM output for data classification."""

    sensitive_count: int = Field(
        description="Number of stores with sensitive data",
    )
    pii_count: int = Field(
        description="Stores containing PII",
    )
    phi_count: int = Field(
        description="Stores containing PHI",
    )
    reasoning: str = Field(
        description="Classification reasoning chain",
    )


class RiskAssessmentOutput(BaseModel):
    """LLM output for risk assessment."""

    high_risk_stores: list[dict[str, str]] = Field(
        description="High-risk stores with details",
    )
    risk_score: float = Field(
        description="Composite risk score 0-100",
    )
    compliance_gaps: list[str] = Field(
        description="Compliance gaps identified",
    )
    reasoning: str = Field(
        description="Risk assessment reasoning",
    )


class ControlRecommendationOutput(BaseModel):
    """LLM output for control recommendations."""

    controls: list[dict[str, str]] = Field(
        description="Recommended controls with priority",
    )
    quick_wins: int = Field(
        description="Number of quick-win controls",
    )
    reasoning: str = Field(
        description="Control selection reasoning",
    )


# ── System Prompts ──────────────────────────────────────────


SYSTEM_DISCOVER = """\
You are an expert data security analyst performing \
data store discovery across cloud and on-premise environments.

Given the tenant configuration and scan scope:
1. Identify all data stores: S3, RDS, DynamoDB, BigQuery, \
Cosmos DB, file shares, data lakes, AI training stores
2. Flag stores with public access or missing encryption
3. Detect shadow data stores and orphaned datasets
4. Classify each store by type and initial risk level

Focus on stores containing sensitive data that may be \
exposed to AI pipelines or agent tool calls."""


SYSTEM_CLASSIFY = """\
You are an expert data classification analyst assessing \
data sensitivity across discovered stores.

Given discovered data stores and sample metadata:
1. Classify data using PII/PHI/PCI detection patterns
2. Identify sensitive columns and record types
3. Flag data flowing into AI training or RAG pipelines
4. Assign classification: public, internal, confidential, \
restricted, PII, PHI

Weight AI pipeline exposure higher — data feeding LLM \
training or RAG retrieval requires stricter controls."""


SYSTEM_ASSESS_RISK = """\
You are an expert risk analyst assessing data security \
risks for classified data stores.

Given classified stores with sensitivity levels:
1. Score risk based on classification, exposure, and controls
2. Identify compliance gaps (GDPR, HIPAA, PCI-DSS, SOC 2)
3. Map attack vectors: exfiltration, injection, privilege escalation
4. Assess business impact of data breach per store

Produce ranked risk assessments with remediation priorities."""


SYSTEM_CONTROLS = """\
You are an expert security engineer recommending \
protection controls for high-risk data stores.

Given risk assessments with compliance gaps:
1. Recommend encryption, access controls, DLP policies
2. Identify quick wins for immediate risk reduction
3. Map controls to compliance frameworks
4. Estimate implementation effort and dependencies

Balance security with operational impact. Prioritize \
controls that reduce the largest risk exposure first."""


SYSTEM_REPORT = """\
You are an expert data security analyst generating a \
DSPM report for executive and compliance audiences.

Given the full posture assessment results:
1. Summarize data security posture with trend indicators
2. Highlight sensitive data exposure and compliance gaps
3. Report on control coverage and validation results
4. Provide remediation progress and next steps

Keep the report actionable with clear risk priorities."""
