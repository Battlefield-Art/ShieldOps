"""LLM prompt templates for the AI Model Governance Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class InventoryOutput(BaseModel):
    """Structured output for model inventory analysis."""

    total_models: int = Field(
        description="Total models in inventory",
    )
    unregistered_count: int = Field(
        description="Number of unregistered models",
    )
    summary: str = Field(
        description="Inventory summary",
    )


class RiskAssessmentOutput(BaseModel):
    """Structured output for model risk assessment."""

    high_risk_count: int = Field(
        description="Number of high/unacceptable risk models",
    )
    avg_risk_score: float = Field(
        description="Average risk score 0-100",
    )
    reasoning: str = Field(
        description="Risk assessment reasoning",
    )


class BiasCheckOutput(BaseModel):
    """Structured output for bias detection."""

    bias_detected: int = Field(
        description="Number of models with bias detected",
    )
    avg_disparity: float = Field(
        description="Average disparity score 0-1",
    )
    reasoning: str = Field(
        description="Bias analysis reasoning",
    )


class ComplianceOutput(BaseModel):
    """Structured output for compliance validation."""

    non_compliant: int = Field(
        description="Number of non-compliant models",
    )
    frameworks_checked: list[str] = Field(
        description="Compliance frameworks evaluated",
    )
    reasoning: str = Field(
        description="Compliance reasoning",
    )


class PolicyOutput(BaseModel):
    """Structured output for policy enforcement."""

    enforced_count: int = Field(
        description="Number of policies enforced",
    )
    blocked_count: int = Field(
        description="Number of models blocked",
    )
    reasoning: str = Field(
        description="Policy enforcement reasoning",
    )


# ── System prompts ────────────────────────────────────

SYSTEM_INVENTORY = """\
You are an expert AI governance analyst performing \
model inventory assessment.

Given the governance configuration:
1. Catalog all AI models across the organization
2. Identify unregistered or shadow AI deployments
3. Verify model cards and documentation completeness
4. Track model lineage and versioning

Focus on: model registry gaps, undocumented models, \
deprecated versions still in production."""

SYSTEM_RISK = """\
You are an expert AI governance analyst assessing \
model risk under EU AI Act classification.

Given the model inventory:
1. Classify each model by EU AI Act risk tier
2. Assess potential harms and impact areas
3. Evaluate transparency and explainability
4. Identify models requiring conformity assessment

Use NIST AI RMF and ISO 42001 frameworks."""

SYSTEM_BIAS = """\
You are an expert AI governance analyst detecting \
bias in AI models.

Given the risk-assessed models:
1. Evaluate demographic parity across protected groups
2. Detect selection and measurement bias
3. Assess fairness metrics (equalized odds, calibration)
4. Flag models with significant disparate impact

Focus on: statistical parity, equal opportunity, \
counterfactual fairness, intersectional bias."""

SYSTEM_COMPLIANCE = """\
You are an expert AI governance analyst validating \
regulatory compliance.

Given the bias-checked models:
1. Validate against EU AI Act requirements
2. Check NIST AI RMF alignment
3. Verify ISO 42001 conformance
4. Assess sector-specific regulations (HIPAA, ECOA)

Ensure: documentation, human oversight, data governance, \
transparency obligations."""

SYSTEM_POLICY = """\
You are an expert AI governance analyst enforcing \
organizational AI policies.

Given compliance validation results:
1. Enforce deployment gates for non-compliant models
2. Apply risk-based access controls
3. Trigger remediation workflows
4. Document enforcement decisions

Balance: security requirements with operational continuity."""
