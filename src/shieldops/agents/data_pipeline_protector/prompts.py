"""Data Pipeline Protector Agent — LLM prompt templates and schemas."""

from pydantic import BaseModel, Field

# --- Output schemas for LLM structured calls ---


class PipelineDiscoveryOutput(BaseModel):
    """LLM output for pipeline discovery analysis."""

    summary: str = Field(
        description="Brief summary of discovered pipelines",
    )
    high_risk_pipelines: list[str] = Field(
        description="Names of pipelines assessed as high risk",
    )
    recommendations: list[str] = Field(
        description="Recommendations for pipeline hardening",
    )


class InputScanOutput(BaseModel):
    """LLM output for input scanning analysis."""

    summary: str = Field(
        description="Brief summary of input scan results",
    )
    injection_vectors: list[str] = Field(
        description="Injection vectors found in inputs",
    )
    poisoning_indicators: list[str] = Field(
        description="Data poisoning indicators detected",
    )
    risk_level: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


class AnomalyDetectionOutput(BaseModel):
    """LLM output for anomaly detection analysis."""

    summary: str = Field(
        description="Brief summary of anomaly detection",
    )
    anomaly_patterns: list[str] = Field(
        description="Patterns of anomalies detected",
    )
    root_causes: list[str] = Field(
        description="Likely root causes for anomalies",
    )
    severity_assessment: str = Field(
        description="Overall severity assessment",
    )


class SchemaValidationOutput(BaseModel):
    """LLM output for schema validation analysis."""

    summary: str = Field(
        description="Brief summary of schema validation",
    )
    breaking_changes: list[str] = Field(
        description="Breaking schema changes detected",
    )
    drift_indicators: list[str] = Field(
        description="Schema drift indicators found",
    )
    remediation_steps: list[str] = Field(
        description="Steps to remediate schema issues",
    )


class AccessEnforcementOutput(BaseModel):
    """LLM output for access enforcement analysis."""

    summary: str = Field(
        description="Brief summary of access enforcement",
    )
    violations: list[str] = Field(
        description="Access violations detected",
    )
    policy_gaps: list[str] = Field(
        description="Gaps in access control policies",
    )
    hardening_steps: list[str] = Field(
        description="Steps to harden access controls",
    )


class ProtectionReportOutput(BaseModel):
    """LLM output for the final protection report."""

    summary: str = Field(
        description="Executive summary of protection scan",
    )
    critical_findings: list[str] = Field(
        description="Critical findings requiring action",
    )
    overall_risk: str = Field(
        description="Overall risk: critical/high/medium/low",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


# --- System prompts ---


SYSTEM_PIPELINE_DISCOVERY = (
    "You are a data pipeline security analyst.\n"
    "Analyze the discovered pipeline inventory:\n"
    "1. ETL pipelines — batch ingestion risks\n"
    "2. Streaming pipelines — real-time attack surface\n"
    "3. ML training pipelines — poisoning exposure\n"
    "4. Data replication — unauthorized copies\n"
    "5. API ingestion — injection entry points\n"
    "Rank pipelines by risk and recommend hardening."
)

SYSTEM_INPUT_SCAN = (
    "You are a data security analyst specializing in "
    "pipeline input validation.\n"
    "Analyze the input scan results for:\n"
    "1. SQL/NoSQL injection in ETL sources\n"
    "2. Prompt injection in ML training data\n"
    "3. Serialization attacks in stream payloads\n"
    "4. Malformed schemas exploiting parsers\n"
    "5. Poisoned records in ML datasets\n"
    "Classify each vector and recommend mitigations."
)

SYSTEM_ANOMALY_DETECTION = (
    "You are a data pipeline anomaly analyst.\n"
    "Analyze the detected anomalies for:\n"
    "1. Volume anomalies — unexpected data surges\n"
    "2. Latency anomalies — processing delays\n"
    "3. Distribution shifts — feature drift\n"
    "4. Cardinality changes — new or missing keys\n"
    "5. Temporal patterns — off-schedule runs\n"
    "Identify root causes and severity."
)

SYSTEM_SCHEMA_VALIDATION = (
    "You are a data engineering security analyst.\n"
    "Analyze the schema validation results for:\n"
    "1. Type changes — field type mutations\n"
    "2. Null introduction — new nullable fields\n"
    "3. Field removal — dropped required fields\n"
    "4. Constraint relaxation — widened ranges\n"
    "5. Encoding changes — charset mutations\n"
    "Flag breaking changes and recommend fixes."
)

SYSTEM_ACCESS_ENFORCEMENT = (
    "You are a data access control analyst.\n"
    "Analyze the access enforcement results for:\n"
    "1. Overprivileged service accounts\n"
    "2. Unauthorized pipeline access attempts\n"
    "3. Cross-tenant data leakage risks\n"
    "4. Missing encryption in transit/at rest\n"
    "5. Stale credentials and API keys\n"
    "Identify violations and hardening steps."
)

SYSTEM_PROTECTION_REPORT = (
    "You are a senior data security architect.\n"
    "Synthesize the full pipeline protection scan:\n"
    "1. Pipeline inventory and risk posture\n"
    "2. Input injection and poisoning findings\n"
    "3. Anomaly detection results\n"
    "4. Schema drift and tampering findings\n"
    "5. Access control enforcement outcomes\n"
    "Produce an executive summary with next steps."
)
