"""Regulatory Change Tracker Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RCTStage(StrEnum):
    SCAN_SOURCES = "scan_sources"
    PARSE_UPDATES = "parse_updates"
    ASSESS_IMPACT = "assess_impact"
    MAP_CONTROLS = "map_controls"
    NOTIFY_STAKEHOLDERS = "notify_stakeholders"
    REPORT = "report"


class RegulationType(StrEnum):
    GDPR = "gdpr"
    CCPA = "ccpa"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOX = "sox"
    NIST = "nist"


class ImpactLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class RegulatoryUpdate(BaseModel):
    """A parsed regulatory change or update."""

    id: str = ""
    regulation: RegulationType = RegulationType.GDPR
    title: str = ""
    summary: str = ""
    effective_date: str = ""
    source_url: str = ""
    impact: ImpactLevel = ImpactLevel.MEDIUM


class ControlMapping(BaseModel):
    """Mapping of a regulatory change to internal controls."""

    update_id: str = ""
    control_id: str = ""
    gap_description: str = ""
    remediation_needed: bool = False
    effort_hours: float = 0.0


class StakeholderNotification(BaseModel):
    """Notification sent to a stakeholder."""

    stakeholder: str = ""
    channel: str = ""
    update_id: str = ""
    sent: bool = False


class RegulatoryChangeTrackerState(BaseModel):
    """Main state for the Regulatory Change Tracker agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: RCTStage = RCTStage.SCAN_SOURCES

    # Pipeline data
    sources_scanned: int = 0
    updates: list[dict[str, Any]] = Field(default_factory=list)
    control_mappings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    notifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metrics
    critical_changes: int = 0
    controls_affected: int = 0

    # Output
    report: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
