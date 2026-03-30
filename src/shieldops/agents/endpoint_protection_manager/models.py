"""Endpoint Protection Manager Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EPMStage(StrEnum):
    INVENTORY_ENDPOINTS = "inventory_endpoints"
    CHECK_AGENTS = "check_agents"
    ASSESS_PATCHES = "assess_patches"
    SCAN_MALWARE = "scan_malware"
    REMEDIATE_GAPS = "remediate_gaps"
    REPORT = "report"


class EndpointOS(StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    CONTAINER = "container"
    EMBEDDED = "embedded"


class ProtectionStatus(StrEnum):
    PROTECTED = "protected"
    PARTIALLY_PROTECTED = "partially_protected"
    UNPROTECTED = "unprotected"
    OFFLINE = "offline"
    QUARANTINED = "quarantined"


class EndpointDevice(BaseModel):
    """A managed endpoint device."""

    id: str = ""
    hostname: str = ""
    os: EndpointOS = EndpointOS.LINUX
    os_version: str = ""
    ip_address: str = ""
    last_seen: str = ""
    status: ProtectionStatus = ProtectionStatus.PROTECTED
    environment: str = "production"
    tags: dict[str, str] = Field(default_factory=dict)


class AgentHealth(BaseModel):
    """Health status of a security agent on an endpoint."""

    endpoint_id: str = ""
    agent_name: str = ""
    agent_version: str = ""
    running: bool = True
    last_checkin: str = ""
    definitions_version: str = ""
    definitions_age_days: int = 0
    cpu_pct: float = 0.0
    memory_mb: float = 0.0
    issues: list[str] = Field(default_factory=list)


class PatchStatus(BaseModel):
    """Patch compliance status for an endpoint."""

    endpoint_id: str = ""
    total_patches: int = 0
    installed: int = 0
    missing_critical: int = 0
    missing_high: int = 0
    missing_medium: int = 0
    last_scan: str = ""
    reboot_pending: bool = False


class MalwareScan(BaseModel):
    """Results of a malware scan on an endpoint."""

    endpoint_id: str = ""
    scan_type: str = "quick"
    threats_found: int = 0
    threats_quarantined: int = 0
    threats_removed: int = 0
    scan_duration_sec: float = 0.0
    last_full_scan: str = ""
    threat_names: list[str] = Field(default_factory=list)


class RemediationAction(BaseModel):
    """An action taken to remediate an endpoint gap."""

    id: str = ""
    endpoint_id: str = ""
    action_type: str = ""
    description: str = ""
    status: str = "pending"
    auto_executable: bool = False
    risk: str = "low"
    result: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class EndpointProtectionManagerState(BaseModel):
    """Main state for the Endpoint Protection Manager agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: EPMStage = EPMStage.INVENTORY_ENDPOINTS

    endpoints: list[EndpointDevice] = Field(
        default_factory=list,
    )
    agent_health: list[AgentHealth] = Field(
        default_factory=list,
    )
    patch_statuses: list[PatchStatus] = Field(
        default_factory=list,
    )
    malware_scans: list[MalwareScan] = Field(
        default_factory=list,
    )
    remediation_actions: list[RemediationAction] = Field(
        default_factory=list,
    )

    report: str = ""
    total_endpoints: int = 0
    protected_count: int = 0
    at_risk_count: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
