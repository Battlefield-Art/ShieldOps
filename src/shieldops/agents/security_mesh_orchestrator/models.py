"""State models for the Security Mesh Orchestrator Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class SMOStage(StrEnum):
    """Stages in the security mesh orchestration lifecycle."""

    DISCOVER_SERVICES = "discover_services"
    MAP_MESH = "map_mesh"
    ENFORCE_MTLS = "enforce_mtls"
    MONITOR_TRAFFIC = "monitor_traffic"
    DETECT_ANOMALIES = "detect_anomalies"
    REPORT = "report"


class MeshPlatform(StrEnum):
    """Supported service mesh platforms."""

    ISTIO = "istio"
    LINKERD = "linkerd"
    CONSUL = "consul"
    KUMA = "kuma"
    AWS_APP_MESH = "aws_app_mesh"
    CUSTOM = "custom"


class TrafficPolicy(StrEnum):
    """Traffic policy enforcement levels."""

    STRICT = "strict"
    PERMISSIVE = "permissive"
    DISABLE = "disable"
    CUSTOM = "custom"


# --- Domain models ---


class MeshService(BaseModel):
    """A service discovered in the mesh topology."""

    service_id: str = ""
    name: str = ""
    namespace: str = ""
    platform: MeshPlatform = MeshPlatform.ISTIO
    mtls_enabled: bool = False
    sidecar_injected: bool = False
    endpoints: int = 0
    version: str = ""


class MeshTopology(BaseModel):
    """Topology mapping of the service mesh."""

    mesh_id: str = ""
    platform: MeshPlatform = MeshPlatform.ISTIO
    total_services: int = 0
    total_connections: int = 0
    namespaces: list[str] = Field(default_factory=list)
    unmeshed_services: list[str] = Field(default_factory=list)
    traffic_policies: dict[str, Any] = Field(default_factory=dict)


class MTLSStatus(BaseModel):
    """mTLS enforcement status across the mesh."""

    namespace: str = ""
    policy: TrafficPolicy = TrafficPolicy.PERMISSIVE
    compliant_services: int = 0
    non_compliant_services: int = 0
    certificate_expiry: datetime | None = None
    root_ca_valid: bool = True


class TrafficAnomaly(BaseModel):
    """Anomalous traffic pattern detected in the mesh."""

    anomaly_id: str = ""
    source_service: str = ""
    destination_service: str = ""
    anomaly_type: str = ""
    severity: str = "medium"
    volume_delta: float = 0.0
    description: str = ""
    detected_at: datetime | None = None


class MeshReport(BaseModel):
    """Final report for mesh security assessment."""

    report_id: str = ""
    platform: MeshPlatform = MeshPlatform.ISTIO
    total_services: int = 0
    mtls_coverage: float = 0.0
    anomalies_found: int = 0
    recommendations: list[str] = Field(default_factory=list)
    risk_score: float = 0.0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the orchestrator workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityMeshOrchestratorState(BaseModel):
    """Full state for a security mesh orchestrator run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SMOStage = SMOStage.DISCOVER_SERVICES

    # Inputs
    mesh_name: str = ""
    platform: MeshPlatform = MeshPlatform.ISTIO
    target_namespaces: list[str] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    services: list[dict[str, Any]] = Field(default_factory=list)
    topology: dict[str, Any] = Field(default_factory=dict)
    mtls_status: list[dict[str, Any]] = Field(default_factory=list)
    traffic_data: list[dict[str, Any]] = Field(default_factory=list)
    anomalies: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_services: int = 0
    mtls_coverage: float = 0.0
    anomalies_detected: int = 0
    risk_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
