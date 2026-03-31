"""LLM prompt templates and response schemas for the
Runtime Application Protector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class AttackDetectionOutput(BaseModel):
    """Structured output for runtime attack detection."""

    attacks: list[dict[str, str]] = Field(
        description=("List of attacks with category, endpoint, and payload"),
    )
    risk_scores: list[float] = Field(
        description="Risk score per detected attack 0-10",
    )
    cwe_ids: list[str] = Field(
        description="CWE identifiers for detected attacks",
    )
    confidence: float = Field(
        description="Overall detection confidence 0-1",
    )


class ThreatClassificationOutput(BaseModel):
    """Structured output for attack classification."""

    attack_category: str = Field(
        description="Attack type: sqli/xss/path_traversal/deserialization",
    )
    severity: str = Field(
        description="Severity: critical/high/medium/low",
    )
    confidence: float = Field(
        description="Classification confidence 0-1",
    )
    cwe_ids: list[str] = Field(
        description="Mapped CWE identifiers",
    )
    description: str = Field(
        description="Detailed attack description",
    )
    recommended_action: str = Field(
        description="Recommended protection action",
    )


class ProtectionReportOutput(BaseModel):
    """Structured output for the protection report."""

    executive_summary: str = Field(
        description="Executive summary of runtime protection",
    )
    total_blocked: int = Field(
        description="Total attacks blocked",
    )
    top_attack_categories: list[str] = Field(
        description="Most common attack categories",
    )
    recommendations: list[str] = Field(
        description="Actionable security recommendations",
    )
    risk_rating: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_DETECTION = """\
You are an expert runtime application security analyst \
detecting attacks in real-time request data.

Given the runtime telemetry from instrumented application \
hooks:
1. Identify SQL injection attempts via tainted SQL \
query construction
2. Detect XSS payloads in user-controlled output \
contexts
3. Flag path traversal attempts targeting filesystem \
resources
4. Recognize unsafe deserialization of untrusted data

Score risk based on exploitability and blast radius."""


SYSTEM_CLASSIFICATION = """\
You are an expert application security researcher \
classifying runtime attacks against OWASP and CWE.

Given a detected runtime attack event with payload:
1. Classify the precise attack category and variant
2. Map to CWE identifiers for vulnerability tracking
3. Assess severity based on data exposure and privilege
4. Recommend the optimal protection action

Be precise: false positives erode developer trust \
in RASP tooling."""


SYSTEM_REPORT = """\
You are an expert application security reporter \
synthesizing runtime protection results.

Given the full protection session (events, attacks, \
protections applied):
1. Produce an executive summary for security leadership
2. Highlight the most impactful attack categories
3. Recommend code-level and architecture-level fixes
4. Rate overall application risk posture

Write clearly for both developers and security teams."""
