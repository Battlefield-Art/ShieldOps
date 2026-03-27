"""Backup Security Posture Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class BackupPostureStage(StrEnum):
    INVENTORY_BACKUP_INFRA = "inventory_backup_infra"
    ASSESS_SECURITY_CONFIG = "assess_security_config"
    DETECT_VULNERABILITIES = "detect_vulnerabilities"
    TEST_RECOVERY = "test_recovery"
    RECOMMEND_HARDENING = "recommend_hardening"
    REPORT = "report"


class BackupComponent(StrEnum):
    STORAGE = "storage"
    NETWORK = "network"
    ACCESS_CONTROL = "access_control"
    ENCRYPTION = "encryption"
    REPLICATION = "replication"
    RETENTION = "retention"


class HardeningPriority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class BackupInventory(BaseModel):
    """Backup infrastructure inventory item."""

    id: str = ""
    name: str = ""
    component: BackupComponent = BackupComponent.STORAGE
    provider: str = ""
    location: str = ""
    capacity_tb: float = 0.0
    used_tb: float = 0.0
    backup_count: int = 0
    last_backup: str = ""
    immutable: bool = False


class SecurityConfig(BaseModel):
    """Backup security configuration assessment."""

    inventory_id: str = ""
    component: BackupComponent = BackupComponent.STORAGE
    encryption_at_rest: bool = True
    encryption_in_transit: bool = True
    mfa_enabled: bool = False
    air_gapped: bool = False
    versioning_enabled: bool = True
    compliance_score: float = Field(default=0.0, ge=0.0, le=100.0)
    issues: list[str] = Field(default_factory=list)


class BackupVulnerability(BaseModel):
    """Backup infrastructure vulnerability."""

    id: str = ""
    inventory_id: str = ""
    component: BackupComponent = BackupComponent.STORAGE
    vulnerability: str = ""
    severity: HardeningPriority = HardeningPriority.MEDIUM
    exploitable: bool = False
    ransomware_risk: bool = False
    cve_id: str = ""
    description: str = ""


class RecoveryTest(BaseModel):
    """Recovery test result."""

    id: str = ""
    inventory_id: str = ""
    test_type: str = ""
    success: bool = True
    recovery_time_min: int = 0
    data_integrity_pct: float = Field(default=100.0, ge=0.0, le=100.0)
    rpo_met: bool = True
    rto_met: bool = True
    issues: list[str] = Field(default_factory=list)


class HardeningRecommendation(BaseModel):
    """Hardening recommendation for backup infra."""

    id: str = ""
    inventory_id: str = ""
    component: BackupComponent = BackupComponent.STORAGE
    priority: HardeningPriority = HardeningPriority.MEDIUM
    recommendation: str = ""
    rationale: str = ""
    effort_hours: float = 0.0
    ransomware_protection: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class BackupSecurityPostureState(BaseModel):
    """Main state for the Backup Security Posture agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: BackupPostureStage = BackupPostureStage.INVENTORY_BACKUP_INFRA

    # Backup inventory
    inventory: list[BackupInventory] = Field(default_factory=list)

    # Security configs
    configs: list[SecurityConfig] = Field(default_factory=list)

    # Vulnerabilities
    vulnerabilities: list[BackupVulnerability] = Field(default_factory=list)

    # Recovery tests
    recovery_tests: list[RecoveryTest] = Field(default_factory=list)

    # Hardening recommendations
    recommendations: list[HardeningRecommendation] = Field(default_factory=list)

    # Summary
    report: str = ""
    total_backup_assets: int = 0
    critical_vulns: int = 0
    recovery_success_rate: float = 0.0

    # Reasoning
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)

    # Error
    error: str = ""
