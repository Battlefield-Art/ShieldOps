"""Security Config Assessor Agent — Pydantic state and data models."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SCAStage(StrEnum):
    INVENTORY_SYSTEMS = "inventory_systems"
    SCAN_CONFIGS = "scan_configs"
    BENCHMARK_CHECK = "benchmark_check"
    DETECT_DRIFT = "detect_drift"
    GENERATE_FIXES = "generate_fixes"
    REPORT = "report"


class BenchmarkType(StrEnum):
    CIS_AWS = "cis_aws"
    CIS_GCP = "cis_gcp"
    CIS_AZURE = "cis_azure"
    CIS_K8S = "cis_k8s"
    CIS_LINUX = "cis_linux"
    CIS_DOCKER = "cis_docker"


class ComplianceLevel(StrEnum):
    LEVEL_1 = "level_1"
    LEVEL_2 = "level_2"
    CUSTOM = "custom"


class SystemInventory(BaseModel):
    """A system discovered during inventory enumeration."""

    id: str = ""
    hostname: str = ""
    platform: str = ""
    benchmark: BenchmarkType = BenchmarkType.CIS_AWS
    region: str = ""
    tags: dict[str, str] = Field(default_factory=dict)
    reachable: bool = True
    last_scanned: float = Field(default_factory=time.time)


class ConfigScan(BaseModel):
    """A configuration item collected from a target system."""

    id: str = ""
    system_id: str = ""
    config_path: str = ""
    current_value: str = ""
    expected_value: str = ""
    compliant: bool = True
    category: str = ""


class BenchmarkResult(BaseModel):
    """Result of evaluating a single CIS benchmark control."""

    id: str = ""
    benchmark: BenchmarkType = BenchmarkType.CIS_AWS
    level: ComplianceLevel = ComplianceLevel.LEVEL_1
    control_id: str = ""
    control_name: str = ""
    system_id: str = ""
    status: str = "pass"
    severity: str = "medium"
    description: str = ""
    remediation_hint: str = ""


class ConfigDrift(BaseModel):
    """A configuration drift detected against the hardening baseline."""

    id: str = ""
    system_id: str = ""
    control_id: str = ""
    config_path: str = ""
    baseline_value: str = ""
    actual_value: str = ""
    drift_severity: str = "medium"
    first_seen: float = Field(default_factory=time.time)


class RemediationScript(BaseModel):
    """An auto-generated remediation script for a failing control."""

    id: str = ""
    system_id: str = ""
    control_id: str = ""
    script_type: str = "bash"
    script_body: str = ""
    description: str = ""
    reversible: bool = True
    risk_level: str = "low"


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityConfigAssessorState(BaseModel):
    """Main state for the Security Config Assessor graph."""

    request_id: str = ""
    stage: SCAStage = SCAStage.INVENTORY_SYSTEMS
    tenant_id: str = ""
    benchmarks: list[str] = Field(default_factory=list)
    compliance_level: str = ComplianceLevel.LEVEL_1.value

    # Pipeline fields
    systems: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    config_scans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    benchmark_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    drifts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    remediation_scripts: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Scores
    compliance_score: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""

    # Timing
    session_start: float = Field(default_factory=time.time)
    session_duration_ms: float = 0.0

    # Error
    error: str = ""
