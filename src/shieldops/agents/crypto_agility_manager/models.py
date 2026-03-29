"""Crypto Agility Manager Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MigrationStage(StrEnum):
    DISCOVER_ALGORITHMS = "discover_algorithms"
    ASSESS_AGILITY = "assess_agility"
    PLAN_MIGRATION = "plan_migration"
    TEST_COMPATIBILITY = "test_compatibility"
    EXECUTE_MIGRATION = "execute_migration"
    REPORT = "report"


class PQCAlgorithm(StrEnum):
    CRYSTALS_KYBER = "crystals_kyber"
    CRYSTALS_DILITHIUM = "crystals_dilithium"
    SPHINCS_PLUS = "sphincs_plus"
    FALCON = "falcon"
    BIKE = "bike"
    CLASSIC_MCELIECE = "classic_mceliece"


class MigrationPriority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    DEFERRED = "deferred"


class AlgorithmRecord(BaseModel):
    """A discovered cryptographic algorithm in use."""

    id: str = ""
    service: str = ""
    algorithm: str = ""
    key_size: int = 0
    usage: str = ""
    protocol: str = ""
    quantum_safe: bool = False
    priority: MigrationPriority = MigrationPriority.MEDIUM
    location: str = ""
    last_seen: datetime | None = None


class AgilityAssessment(BaseModel):
    """Assessment of cryptographic agility for a service."""

    service: str = ""
    algorithm: str = ""
    supports_negotiation: bool = False
    supports_hybrid: bool = False
    migration_complexity: str = "medium"
    estimated_effort_hours: int = 0
    blockers: list[str] = Field(default_factory=list)
    recommended_pqc: str = ""


class MigrationPlan(BaseModel):
    """A migration plan for transitioning to a PQC algorithm."""

    id: str = ""
    service: str = ""
    current_algorithm: str = ""
    target_algorithm: str = ""
    priority: MigrationPriority = MigrationPriority.MEDIUM
    hybrid_mode: bool = True
    steps: list[str] = Field(default_factory=list)
    rollback_steps: list[str] = Field(default_factory=list)
    estimated_downtime_seconds: int = 0
    requires_approval: bool = False


class CompatibilityResult(BaseModel):
    """Result of a PQC compatibility test."""

    service: str = ""
    algorithm: str = ""
    target_pqc: str = ""
    compatible: bool = True
    performance_impact_pct: float = 0.0
    key_size_increase_pct: float = 0.0
    issues: list[str] = Field(default_factory=list)
    handshake_time_ms: float = 0.0


class MigrationExecution(BaseModel):
    """Result of executing a PQC migration step."""

    plan_id: str = ""
    service: str = ""
    status: str = "pending"
    hybrid_enabled: bool = False
    rollback_available: bool = True
    verification_passed: bool = False
    message: str = ""


class CryptoAgilityManagerState(BaseModel):
    """Main state for the Crypto Agility Manager agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: MigrationStage = MigrationStage.DISCOVER_ALGORITHMS

    # Pipeline data
    algorithms: list[dict[str, Any]] = Field(default_factory=list)
    assessments: list[dict[str, Any]] = Field(default_factory=list)
    migration_plans: list[dict[str, Any]] = Field(default_factory=list)
    compatibility_results: list[dict[str, Any]] = Field(default_factory=list)
    executions: list[dict[str, Any]] = Field(default_factory=list)

    # Stats
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    current_step: str = ""
    session_start: str = ""

    # Report
    summary: str = ""
    total_algorithms: int = 0
    quantum_vulnerable_count: int = 0
    migrated_count: int = 0

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
