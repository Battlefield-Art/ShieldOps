"""Serverless Security Agent — Pydantic state and data models."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ServerlessStage(StrEnum):
    DISCOVER_FUNCTIONS = "discover_functions"
    ANALYZE_PERMISSIONS = "analyze_permissions"
    SCAN_DEPENDENCIES = "scan_dependencies"
    DETECT_THREATS = "detect_threats"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class ServerlessPlatform(StrEnum):
    AWS_LAMBDA = "aws_lambda"
    GCP_CLOUD_FUNCTIONS = "gcp_cloud_functions"
    AZURE_FUNCTIONS = "azure_functions"
    CLOUDFLARE_WORKERS = "cloudflare_workers"


class ServerlessThreatType(StrEnum):
    OVER_PRIVILEGED = "over_privileged"
    COLD_START_ATTACK = "cold_start_attack"
    DEPENDENCY_VULN = "dependency_vuln"
    EVENT_INJECTION = "event_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    RESOURCE_ABUSE = "resource_abuse"


class ServerlessFunction(BaseModel):
    """A discovered serverless function."""

    id: str = ""
    platform: ServerlessPlatform = ServerlessPlatform.AWS_LAMBDA
    function_name: str = ""
    runtime: str = ""
    memory_mb: int = 128
    timeout_seconds: int = 30
    region: str = ""
    role_arn: str = ""
    layers: list[str] = Field(default_factory=list)
    env_var_count: int = 0
    last_invoked: float = Field(default_factory=time.time)


class PermissionFinding(BaseModel):
    """A permission-related finding for a serverless function."""

    id: str = ""
    function_id: str = ""
    finding_type: str = ""
    severity: str = "medium"
    description: str = ""
    policy_statement: str = ""
    recommended_policy: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)


class DependencyVulnerability(BaseModel):
    """A vulnerability found in function dependencies."""

    id: str = ""
    function_id: str = ""
    package_name: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    cve_id: str = ""
    severity: str = "medium"
    description: str = ""


class ThreatDetection(BaseModel):
    """A detected threat targeting serverless functions."""

    id: str = ""
    function_id: str = ""
    threat_type: ServerlessThreatType = ServerlessThreatType.OVER_PRIVILEGED
    severity: str = "medium"
    description: str = ""
    mitre_technique: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ServerlessSecurityState(BaseModel):
    """Main state for the Serverless Security agent graph."""

    request_id: str = ""
    stage: ServerlessStage = ServerlessStage.DISCOVER_FUNCTIONS
    tenant_id: str = ""
    platforms: list[str] = Field(default_factory=list)

    # Pipeline data
    functions: list[dict[str, Any]] = Field(default_factory=list)
    permission_findings: list[dict[str, Any]] = Field(default_factory=list)
    dependency_vulns: list[dict[str, Any]] = Field(default_factory=list)
    threat_detections: list[dict[str, Any]] = Field(default_factory=list)

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
