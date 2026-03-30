"""Audit Trail Analyzer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ATAStage(StrEnum):
    COLLECT_LOGS = "collect_logs"
    NORMALIZE_EVENTS = "normalize_events"
    DETECT_ANOMALIES = "detect_anomalies"
    CORRELATE_ACTIVITIES = "correlate_activities"
    GENERATE_FINDINGS = "generate_findings"
    REPORT = "report"


class AuditSource(StrEnum):
    APPLICATION = "application"
    INFRASTRUCTURE = "infrastructure"
    DATABASE = "database"
    IDENTITY = "identity"
    NETWORK = "network"
    CLOUD = "cloud"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AuditEvent(BaseModel):
    """A normalized audit event."""

    id: str = ""
    source: AuditSource = AuditSource.APPLICATION
    actor: str = ""
    action: str = ""
    resource: str = ""
    timestamp: float = 0.0
    outcome: str = ""
    metadata: dict[str, Any] = Field(
        default_factory=dict,
    )


class AuditAnomaly(BaseModel):
    """A detected anomaly in audit events."""

    id: str = ""
    event_ids: list[str] = Field(default_factory=list)
    anomaly_type: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    confidence: float = 0.0


class AuditFinding(BaseModel):
    """A correlated audit finding."""

    id: str = ""
    anomaly_ids: list[str] = Field(default_factory=list)
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    actor: str = ""
    recommendation: str = ""


class AuditTrailAnalyzerState(BaseModel):
    """Main state for the Audit Trail Analyzer."""

    request_id: str = ""
    tenant_id: str = ""
    stage: ATAStage = ATAStage.COLLECT_LOGS

    # Pipeline data
    events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    anomalies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metrics
    total_events: int = 0
    anomalies_detected: int = 0
    critical_findings: int = 0

    # Output
    report: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
