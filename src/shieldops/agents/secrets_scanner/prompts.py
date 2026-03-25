"""Secrets Scanner Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class SecretAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted secret pattern analysis."""

    summary: str = Field(description="Brief summary of secret detection findings")
    total_findings: int = Field(description="Total number of secrets detected")
    high_confidence_count: int = Field(description="Number of high-confidence findings (>0.8)")
    false_positive_ids: list[str] = Field(
        description="IDs of likely false-positive findings to exclude"
    )
    pattern_notes: list[str] = Field(description="Additional patterns or anomalies observed")


class SeverityOutput(BaseModel):
    """Structured output from LLM-assisted severity classification."""

    summary: str = Field(description="Brief severity assessment summary")
    critical_count: int = Field(description="Number of critical-severity findings")
    high_count: int = Field(description="Number of high-severity findings")
    priority_finding_ids: list[str] = Field(
        description="Finding IDs that should be remediated first"
    )
    risk_narrative: str = Field(
        description="Narrative describing overall risk posture from leaked secrets"
    )


class ExposureOutput(BaseModel):
    """Structured output from LLM-assisted exposure verification."""

    summary: str = Field(description="Brief exposure verification summary")
    publicly_exposed_count: int = Field(description="Number of secrets confirmed publicly exposed")
    active_count: int = Field(description="Number of secrets confirmed still active")
    immediate_risk_ids: list[str] = Field(
        description="Finding IDs that pose immediate risk (active + exposed)"
    )
    exposure_notes: list[str] = Field(description="Additional notes about exposure vectors")


class RemediationOutput(BaseModel):
    """Structured output from LLM-assisted remediation planning."""

    summary: str = Field(description="Brief remediation plan summary")
    auto_remediate_ids: list[str] = Field(description="Finding IDs safe for automated remediation")
    manual_review_ids: list[str] = Field(
        description="Finding IDs requiring manual review before action"
    )
    remediation_steps: list[str] = Field(description="Ordered list of remediation steps to execute")
    post_remediation_checks: list[str] = Field(
        description="Verification checks to run after remediation"
    )


SYSTEM_SCAN_ANALYSIS = (
    "You are a secrets detection analyst for enterprise security.\n"
    "Analyze the following scan results and identify leaked credentials.\n"
    "For each finding:\n"
    "1. Assess whether the match is a true positive or false positive\n"
    "2. Consider context — test fixtures, documentation examples, and "
    "placeholder values are false positives\n"
    "3. Identify patterns suggesting bulk credential leaks or systematic "
    "misconfigurations\n"
    "4. Highlight any findings that appear in multiple locations\n"
    "5. Provide a confidence-weighted summary of the overall secret hygiene posture"
)

SYSTEM_SEVERITY_ASSESSMENT = (
    "You are a security risk analyst specializing in credential exposure.\n"
    "Given the detected secrets and their metadata:\n"
    "1. Classify severity by combining secret type, exposure level, and blast radius\n"
    "2. Cloud provider keys (AWS/GCP/Azure) in public repos are always critical\n"
    "3. Database URLs with embedded passwords are high severity\n"
    "4. Assess the chain of access — a leaked AWS key may grant access to "
    "databases, S3 buckets, and other services\n"
    "5. Prioritize findings by remediation urgency, considering active status "
    "and exposure window"
)

SYSTEM_EXPOSURE_VERIFICATION = (
    "You are a threat intelligence analyst verifying secret exposure.\n"
    "For each detected secret:\n"
    "1. Determine if the source is publicly accessible (public repos, "
    "public container registries, public logs)\n"
    "2. Assess whether the secret is still active based on creation time "
    "and rotation policies\n"
    "3. Check for evidence of exploitation — unusual API activity, "
    "unauthorized access patterns\n"
    "4. Identify secrets that appear in threat intelligence feeds or "
    "paste sites\n"
    "5. Flag any secrets with immediate exploitation risk"
)

SYSTEM_REMEDIATION_PLANNING = (
    "You are a security remediation engineer planning secret rotation.\n"
    "Given the verified findings and severity assessments:\n"
    "1. Determine which secrets can be safely auto-rotated without "
    "service disruption\n"
    "2. Identify secrets requiring manual review (shared credentials, "
    "production databases, third-party integrations)\n"
    "3. Plan rotation order to minimize blast radius — rotate the most "
    "critical and exposed secrets first\n"
    "4. Include post-rotation verification steps (health checks, "
    "integration tests)\n"
    "5. Generate a rollback plan for each rotation in case of failure"
)
