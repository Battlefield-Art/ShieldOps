"""LLM prompt templates for the Quantum Safe Auditor Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class CryptoInventoryOutput(BaseModel):
    """Structured output for crypto inventory analysis."""

    total_assets: int = Field(
        description="Total crypto assets discovered",
    )
    vulnerable_algorithms: int = Field(
        description="Count of quantum-vulnerable algorithms",
    )
    summary: str = Field(
        description="Inventory summary",
    )


class QuantumRiskOutput(BaseModel):
    """Structured output for quantum risk assessment."""

    high_risk_count: int = Field(
        description="Number of high quantum-risk assets",
    )
    hndl_risk_count: int = Field(
        description="Harvest-now-decrypt-later risk count",
    )
    reasoning: str = Field(
        description="Quantum risk reasoning",
    )


class VulnerabilityOutput(BaseModel):
    """Structured output for vulnerability identification."""

    vulnerable_count: int = Field(
        description="Number of vulnerable crypto assets",
    )
    critical_algorithms: list[str] = Field(
        description="Critically vulnerable algorithms found",
    )
    reasoning: str = Field(
        description="Vulnerability analysis reasoning",
    )


class MigrationPlanOutput(BaseModel):
    """Structured output for migration planning."""

    plans: list[dict[str, str]] = Field(
        description="Migration plans with target algorithms",
    )
    total_effort_weeks: int = Field(
        description="Total estimated migration effort in weeks",
    )
    reasoning: str = Field(
        description="Migration planning reasoning",
    )


class ProgressOutput(BaseModel):
    """Structured output for progress tracking."""

    overall_percent: float = Field(
        description="Overall migration completion 0-100",
    )
    blocked_count: int = Field(
        description="Number of blocked migrations",
    )
    reasoning: str = Field(
        description="Progress assessment reasoning",
    )


# ── System prompts ────────────────────────────────────

SYSTEM_INVENTORY = """\
You are an expert post-quantum cryptography auditor \
performing cryptographic asset inventory.

Given the audit configuration:
1. Discover all cryptographic algorithms in use
2. Map TLS certificates, signing keys, encryption schemes
3. Identify legacy or deprecated crypto implementations
4. Catalog key sizes and protocol versions

Focus on: RSA, ECC, DH key exchanges, AES modes, \
SHA variants, and certificate chains."""

SYSTEM_RISK = """\
You are an expert post-quantum cryptography auditor \
assessing quantum computing risk.

Given the crypto inventory:
1. Evaluate harvest-now-decrypt-later (HNDL) exposure
2. Estimate time-to-quantum-threat for each algorithm
3. Assess data sensitivity and retention periods
4. Score quantum risk based on NIST PQC guidelines

Use: Shor's algorithm impact on RSA/ECC, Grover's \
impact on symmetric crypto, NIST PQC transition timeline."""

SYSTEM_VULNERABLE = """\
You are an expert post-quantum cryptography auditor \
identifying vulnerable cryptographic assets.

Given the risk assessments:
1. Flag all quantum-vulnerable algorithms (RSA, ECC, DH)
2. Identify critical data protected by vulnerable crypto
3. Assess impact of quantum decryption on each asset
4. Recommend NIST PQC replacement algorithms

Map to: ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA \
(SPHINCS+), FN-DSA (FALCON)."""

SYSTEM_MIGRATION = """\
You are an expert post-quantum cryptography auditor \
planning crypto migration.

Given the vulnerable assets:
1. Prioritize migration by risk and business impact
2. Design phased migration with hybrid crypto approach
3. Identify dependencies and compatibility requirements
4. Estimate effort and timeline for each migration

Balance: security urgency with operational stability, \
prefer hybrid PQ/classical as transition strategy."""

SYSTEM_PROGRESS = """\
You are an expert post-quantum cryptography auditor \
tracking migration progress.

Given the migration plans:
1. Assess completion status of each migration
2. Identify blockers and dependencies
3. Recommend acceleration strategies
4. Report on overall quantum readiness posture

Focus on: critical path items, testing coverage, \
backward compatibility verification."""
