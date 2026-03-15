"""Adaptive Security Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class EvaluationResult(BaseModel):
    """Structured output from LLM-assisted proposal evaluation."""

    summary: str = Field(description="Brief summary of evaluation results")
    recommended_accepts: int = Field(description="Number of proposals recommended for acceptance")
    risk_assessment: str = Field(description="Overall risk assessment: low, medium, high, critical")
    blind_spot_warnings: list[str] = Field(
        description="Warnings about potential detection blind spots"
    )
    confidence_notes: list[str] = Field(
        description="Notes on evaluation confidence and methodology"
    )


SYSTEM_BASELINE = (
    "You are a security baseline analyst computing statistical baselines for risk metrics.\n"
    "For each entity type (host, user, IP):\n"
    "1. Calculate mean, standard deviation, and percentile distributions\n"
    "2. Establish normal operating ranges for risk scores, alert volumes, and sensitivity\n"
    "3. Account for time-of-day, day-of-week, and seasonal patterns\n"
    "4. Flag any metrics with high variance that may need wider thresholds"
)

SYSTEM_DETECT_PROPOSE = (
    "You are analyzing baseline drift and proposing adaptive threshold adjustments.\n"
    "Use the autoresearch pattern: propose, evaluate, accept/reject.\n"
    "For each drifted metric:\n"
    "1. Determine if drift is benign (environment change) or adversarial (evasion)\n"
    "2. Factor in threat context (normal, elevated, active attack, post-incident)\n"
    "3. Propose threshold adjustments that minimize false positives without missing threats\n"
    "4. Assign confidence and risk rating to each proposal"
)

SYSTEM_EVALUATE = (
    "You are evaluating proposed threshold adjustments via dry-run simulation.\n"
    "For each proposal:\n"
    "1. Simulate impact on false positive rate and detection rate\n"
    "2. Check for policy compliance and safety constraints\n"
    "3. Accept proposals with high confidence and acceptable risk\n"
    "4. Reject proposals that could increase blind spots or violate safety thresholds"
)

SYSTEM_APPLY = (
    "You are applying accepted threshold adjustments to the security system.\n"
    "For each accepted adjustment:\n"
    "1. Apply the new threshold value\n"
    "2. Log the change with full audit trail (old value, new value, reasoning)\n"
    "3. Set a review period for automatic rollback if metrics degrade\n"
    "4. Notify relevant security analysts of the adjustment"
)
