"""Cloud Storage Scanner Agent — LLM prompt templates and schemas."""

from pydantic import BaseModel, Field


class AccessAnalysisOutput(BaseModel):
    """LLM output for access analysis."""

    summary: str = Field(description="Access analysis summary")
    exposed_count: int = Field(description="Publicly exposed buckets")
    risk_level: str = Field(description="Risk: critical/high/medium/low")
    recommendations: list[str] = Field(description="Access hardening recommendations")


class EncryptionAnalysisOutput(BaseModel):
    """LLM output for encryption analysis."""

    summary: str = Field(description="Encryption compliance summary")
    unencrypted_count: int = Field(description="Unencrypted buckets")
    recommendations: list[str] = Field(description="Encryption recommendations")


class StorageRiskOutput(BaseModel):
    """LLM output for storage risk assessment."""

    summary: str = Field(description="Storage risk assessment summary")
    risk_level: str = Field(description="Risk: critical/high/medium/low")
    data_exposure_risk: list[str] = Field(description="Data exposure risks")
    priority_actions: list[str] = Field(description="Priority remediation actions")


SYSTEM_ACCESS_ANALYSIS = (
    "You are a cloud storage access security analyst.\n"
    "Analyze storage bucket access configurations:\n"
    "1. Identify publicly accessible buckets\n"
    "2. Detect overly permissive ACLs and policies\n"
    "3. Flag cross-account access without controls\n"
    "4. Recommend least-privilege access policies"
)

SYSTEM_ENCRYPTION_ANALYSIS = (
    "You are a cloud storage encryption specialist.\n"
    "Analyze storage encryption configurations:\n"
    "1. Identify unencrypted storage buckets\n"
    "2. Check for weak encryption algorithms\n"
    "3. Verify KMS key rotation policies\n"
    "4. Ensure compliance with data-at-rest requirements"
)

SYSTEM_STORAGE_RISK = (
    "You are a cloud storage security risk assessor.\n"
    "Assess overall storage security risk:\n"
    "1. Combine access, encryption, and data findings\n"
    "2. Score risk by data sensitivity and exposure\n"
    "3. Map findings to compliance requirements\n"
    "4. Create a prioritized remediation plan"
)
