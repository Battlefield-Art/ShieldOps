"""Cloud Audit Logger Agent — Pydantic state and data models."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AuditStage(StrEnum):
    INGEST_LOGS = "ingest_logs"
    PARSE_EVENTS = "parse_events"
    DETECT_ANOMALIES = "detect_anomalies"
    CORRELATE_ACTIVITY = "correlate_activity"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class AuditLogSource(StrEnum):
    CLOUDTRAIL = "cloudtrail"
    GCP_AUDIT = "gcp_audit"
    AZURE_ACTIVITY = "azure_activity"
    KUBERNETES_AUDIT = "kubernetes_audit"
    CUSTOM = "custom"


class AuditEventSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuditEvent(BaseModel):
    """A single cloud audit log event."""

    id: str = ""
    source: AuditLogSource = AuditLogSource.CLOUDTRAIL
    event_name: str = ""
    principal: str = ""
    source_ip: str = ""
    region: str = ""
    resource_type: str = ""
    resource_id: str = ""
    timestamp: float = Field(default_factory=time.time)
    raw_event: dict[str, Any] = Field(default_factory=dict)


class SuspiciousActivity(BaseModel):
    """A suspicious activity detected from audit logs."""

    id: str = ""
    event_ids: list[str] = Field(default_factory=list)
    activity_type: str = ""
    severity: AuditEventSeverity = AuditEventSeverity.MEDIUM
    principal: str = ""
    description: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    mitre_technique: str = ""
    recommended_action: str = ""


class AuditCorrelation(BaseModel):
    """A correlated activity chain across multiple events."""

    id: str = ""
    activity_ids: list[str] = Field(default_factory=list)
    chain_type: str = ""
    description: str = ""
    blast_radius: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudAuditLoggerState(BaseModel):
    """Main state for the Cloud Audit Logger agent graph."""

    request_id: str = ""
    stage: AuditStage = AuditStage.INGEST_LOGS
    tenant_id: str = ""
    sources: list[str] = Field(default_factory=list)
    time_range_hours: int = 24

    # Pipeline data
    audit_events: list[dict[str, Any]] = Field(default_factory=list)
    suspicious_activities: list[dict[str, Any]] = Field(default_factory=list)
    correlations: list[dict[str, Any]] = Field(default_factory=list)

    # Risk assessment
    risk_score: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""

    # Timing
    session_start: float = Field(default_factory=time.time)
    session_duration_ms: float = 0.0

    # Error
    error: str = ""
