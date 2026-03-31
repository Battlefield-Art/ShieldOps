"""Endpoint Hardening Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EHAStage(StrEnum):
    SCAN_ENDPOINTS = "scan_endpoints"
    CHECK_BASELINE = "check_baseline"
    DETECT_DEVIATIONS = "detect_deviations"
    GENERATE_FIXES = "generate_fixes"
    APPLY_HARDENING = "apply_hardening"
    REPORT = "report"


class BenchmarkType(StrEnum):
    CIS_LINUX = "cis_linux"
    CIS_WINDOWS = "cis_windows"
    CIS_MACOS = "cis_macos"
    STIG = "stig"
    NIST_800_53 = "nist_800_53"
    CUSTOM = "custom"


class DeviationSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EndpointScan(BaseModel):
    """Result of scanning a single endpoint."""

    id: str = ""
    hostname: str = ""
    os_type: str = ""
    os_version: str = ""
    agent_version: str = ""
    last_patched: str = ""
    open_ports: list[int] = Field(default_factory=list)
    services_running: int = 0
    disk_encrypted: bool = False
    firewall_enabled: bool = True


class BaselineCheck(BaseModel):
    """Result of checking an endpoint against a baseline."""

    id: str = ""
    hostname: str = ""
    benchmark: BenchmarkType = BenchmarkType.CIS_LINUX
    total_controls: int = 0
    passing: int = 0
    failing: int = 0
    score_pct: float = 0.0


class Deviation(BaseModel):
    """A detected deviation from the security baseline."""

    id: str = ""
    hostname: str = ""
    control_id: str = ""
    control_name: str = ""
    severity: DeviationSeverity = DeviationSeverity.MEDIUM
    current_value: str = ""
    expected_value: str = ""
    remediation_available: bool = True


class HardeningFix(BaseModel):
    """A generated hardening fix for a deviation."""

    id: str = ""
    deviation_id: str = ""
    hostname: str = ""
    fix_type: str = ""
    command: str = ""
    rollback_command: str = ""
    risk_level: str = "low"
    requires_reboot: bool = False


class HardeningResult(BaseModel):
    """Result of applying a hardening fix."""

    id: str = ""
    fix_id: str = ""
    hostname: str = ""
    applied: bool = False
    status: str = ""
    duration_ms: int = 0
    error: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class EndpointHardeningAgentState(BaseModel):
    """Main state for the Endpoint Hardening agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: EHAStage = EHAStage.SCAN_ENDPOINTS

    scans: list[EndpointScan] = Field(
        default_factory=list,
    )
    baselines: list[BaselineCheck] = Field(
        default_factory=list,
    )
    deviations: list[Deviation] = Field(
        default_factory=list,
    )
    fixes: list[HardeningFix] = Field(
        default_factory=list,
    )
    hardening_results: list[HardeningResult] = Field(
        default_factory=list,
    )

    report: str = ""
    total_endpoints: int = 0
    deviations_found: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
