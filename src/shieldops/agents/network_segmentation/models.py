"""Network Segmentation Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SegmentationStage(StrEnum):
    DISCOVER_ZONES = "discover_zones"
    MAP_TRAFFIC = "map_traffic"
    DETECT_VIOLATIONS = "detect_violations"
    ASSESS_RISK = "assess_risk"
    ENFORCE_POLICIES = "enforce_policies"
    REPORT = "report"


class ZoneType(StrEnum):
    DMZ = "dmz"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    PUBLIC = "public"
    MANAGEMENT = "management"


class ViolationSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class NetworkZone(BaseModel):
    """A logical network zone with associated CIDR ranges and access rules."""

    id: str = ""
    name: str = ""
    zone_type: ZoneType = ZoneType.INTERNAL
    cidrs: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    ingress_rules: list[str] = Field(default_factory=list)
    egress_rules: list[str] = Field(default_factory=list)


class TrafficFlow(BaseModel):
    """An observed traffic flow between two network zones."""

    id: str = ""
    source_zone: str = ""
    dest_zone: str = ""
    protocol: str = ""
    port: int = 0
    bytes_per_day: float = 0.0
    authorized: bool = False


class SegmentationViolation(BaseModel):
    """A violation of micro-segmentation policy."""

    id: str = ""
    flow_id: str = ""
    source_zone: str = ""
    dest_zone: str = ""
    violation_type: str = ""
    description: str = ""
    severity: ViolationSeverity = ViolationSeverity.MEDIUM
    mitre_technique: str = ""


class PolicyEnforcement(BaseModel):
    """A policy enforcement action taken to remediate a violation."""

    id: str = ""
    violation_id: str = ""
    action: str = ""
    target: str = ""
    applied: bool = False
    success: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class NetworkSegmentationState(BaseModel):
    """Main state for the Network Segmentation graph."""

    # Input
    tenant_id: str = ""
    environment: str = "production"
    target_zones: list[str] = Field(default_factory=list)

    # Discovery
    zones: list[dict[str, Any]] = Field(default_factory=list)
    traffic_flows: list[dict[str, Any]] = Field(default_factory=list)

    # Analysis
    violations: list[dict[str, Any]] = Field(default_factory=list)
    risk_scores: dict[str, float] = Field(default_factory=dict)

    # Enforcement
    enforcements: list[dict[str, Any]] = Field(default_factory=list)

    # Metadata
    current_stage: SegmentationStage = SegmentationStage.DISCOVER_ZONES
    reasoning_chain: list[str] = Field(default_factory=list)
    session_start: float = 0.0
    session_duration_ms: float = 0.0

    # Stats
    total_zones: int = 0
    total_flows: int = 0
    total_violations: int = 0
    total_enforcements: int = 0
    critical_violations: int = 0
