"""LLM prompt templates and response schemas for Quantum Risk Assessor."""

from pydantic import BaseModel, Field

# ── Structured Output Schemas ───────────────────────────────


class InfrastructureScanOutput(BaseModel):
    """LLM output for crypto infrastructure scan."""

    assets_found: int = Field(
        description="Number of cryptographic assets discovered",
    )
    vulnerable_count: int = Field(
        description="Number of quantum-vulnerable assets",
    )
    summary: str = Field(
        description="Summary of infrastructure scan results",
    )
    risk_level: str = Field(
        description="Overall risk: critical/high/medium/low/negligible",
    )


class AlgorithmAnalysisOutput(BaseModel):
    """LLM output for algorithm inventory analysis."""

    algorithms: list[dict[str, str]] = Field(
        description="Algorithm inventory with type+count+vulnerability",
    )
    harvest_now_risk: bool = Field(
        description="Whether harvest-now-decrypt-later risk exists",
    )
    summary: str = Field(
        description="Algorithm inventory summary",
    )


class VulnerabilityAnalysisOutput(BaseModel):
    """LLM output for quantum vulnerability assessment."""

    findings: list[dict[str, str]] = Field(
        description="Vulnerability findings with severity+description",
    )
    risk_score: float = Field(
        description="Composite quantum risk score 0-100",
    )
    shor_exposed_count: int = Field(
        description="Assets vulnerable to Shor's algorithm",
    )
    reasoning: str = Field(
        description="Vulnerability assessment reasoning chain",
    )


class ReadinessAnalysisOutput(BaseModel):
    """LLM output for PQC readiness scoring."""

    overall_score: float = Field(
        description="Overall PQC readiness score 0-100",
    )
    categories: list[dict[str, str]] = Field(
        description="Readiness scores by category",
    )
    gaps: list[str] = Field(
        description="Key readiness gaps identified",
    )
    reasoning: str = Field(
        description="Readiness scoring reasoning",
    )


class MigrationPlanOutput(BaseModel):
    """LLM output for migration recommendations."""

    recommendations: list[dict[str, str]] = Field(
        description="Migration recommendations with priority+effort",
    )
    quick_wins: int = Field(
        description="Number of quick-win migrations",
    )
    total_effort_weeks: float = Field(
        description="Total estimated migration effort in weeks",
    )
    reasoning: str = Field(
        description="Migration planning reasoning",
    )


# ── System Prompts ──────────────────────────────────────────


SYSTEM_ANALYZE = """\
You are an expert quantum cryptography analyst assessing \
enterprise cryptographic infrastructure for quantum computing \
threats.

Your responsibilities:
1. Identify all cryptographic assets: TLS certificates, SSH \
keys, VPN tunnels, database encryption, API tokens, code \
signing certificates, and key management systems
2. Inventory vulnerable algorithms: RSA (all key sizes), \
ECC (NIST curves), DH (finite field), DSA — all are \
vulnerable to Shor's algorithm on a cryptographically \
relevant quantum computer (CRQC)
3. Assess harvest-now-decrypt-later (HNDL) risk for data \
with long shelf life (healthcare, financial, government)
4. Evaluate symmetric algorithms: AES-128 needs doubling \
to AES-256 (Grover's algorithm halves effective key length)
5. Score PQC migration readiness across categories: \
inventory completeness, crypto agility, vendor readiness, \
key management flexibility, compliance alignment

Focus on practical timelines: NIST PQC standards (ML-KEM, \
ML-DSA, SLH-DSA) are finalized. Migration urgency depends \
on data shelf life vs. estimated CRQC timeline (2030-2035)."""


SYSTEM_REPORT = """\
You are an expert quantum risk analyst generating a \
comprehensive quantum risk assessment report for CISO \
and security leadership audiences.

Given the full assessment results:
1. Summarize total quantum risk posture with threat timeline
2. Highlight critical assets vulnerable to Shor's algorithm \
(RSA, ECC, DH) and Grover's algorithm (AES-128, SHA-1)
3. Present PQC readiness score with category breakdowns
4. Provide prioritized migration roadmap with effort estimates
5. Quantify harvest-now-decrypt-later exposure window
6. Map to compliance frameworks: NIST SP 800-208, NSA CNSA \
2.0, CISA quantum-readiness guidance, EU Cyber Resilience Act

Keep the report actionable with clear migration milestones \
and quick wins that reduce quantum risk immediately."""
