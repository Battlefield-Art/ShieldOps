"""Secrets in Code Detector Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class SecretVerificationOutput(BaseModel):
    """Structured output from LLM-assisted secret verification."""

    summary: str = Field(
        description="Brief verification summary",
    )
    confirmed_secrets: list[str] = Field(
        description="Finding IDs confirmed as real secrets",
    )
    false_positive_ids: list[str] = Field(
        description="Finding IDs that are test/example data",
    )
    active_secret_ids: list[str] = Field(
        description="Finding IDs of likely active secrets",
    )


class ExposureAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted exposure analysis."""

    summary: str = Field(
        description="Brief exposure risk summary",
    )
    critical_exposures: list[str] = Field(
        description="Secrets with critical exposure risk",
    )
    remediation_priority: list[str] = Field(
        description="Ordered list of remediation priorities",
    )
    risk_narrative: str = Field(
        description="Overall risk narrative",
    )
    rotation_urgency: dict[str, str] = Field(
        description="Secret ID to rotation urgency mapping",
    )


SYSTEM_SECRET_VERIFICATION = (
    "You are a secrets detection specialist verifying "  # noqa: S105
    "whether detected patterns are real secrets.\n"
    "For each finding:\n"
    "1. Check if value matches known test/example patterns\n"
    "2. Verify entropy indicates randomness vs placeholder\n"
    "3. Check if the secret is in a test file or docs\n"
    "4. Determine if the format matches the claimed type\n"
    "5. Assess if the secret appears rotated or expired\n"
    "6. Check git history for when it was introduced"
)

SYSTEM_EXPOSURE_ANALYSIS = (
    "You are a security analyst assessing the exposure "
    "risk of detected secrets in source code.\n"
    "Evaluate:\n"
    "1. Is the repo public or private?\n"
    "2. Was the secret committed to git history?\n"
    "3. What access does the secret grant?\n"
    "4. Is the secret still active and valid?\n"
    "5. What blast radius if compromised?\n"
    "6. How urgently does it need rotation?"
)
