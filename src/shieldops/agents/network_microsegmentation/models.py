"""State models for the Network Microsegmentation Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class NMSStage(StrEnum):
    """Stages in the microsegmentation lifecycle."""

    MAP_TOPOLOGY = "map_topology"
    ANALYZE_FLOWS = "analyze_flows"
    GENERATE_POLICIES = "generate_policies"
    VALIDATE = "validate"
    DEPLOY = "deploy"
    REPORT = "report"


class SegmentationType(StrEnum):
    """Type of segmentation strategy."""

    WORKLOAD_IDENTITY = "workload_identity"
    ZERO_TRUST = "zero_trust"
    APPLICATION_TIER = "application_tier"
    ENVIRONMENT_BASED = "environment_based"
    COMPLIANCE_DRIVEN = "compliance_driven"
    HYBRID = "hybrid"


class FlowClassification(StrEnum):
    """Classification of observed network flows."""

    LEGITIMATE = "legitimate"
    SUSPICIOUS = "suspicious"
    UNAUTHORIZED = "unauthorized"
    UNKNOWN = "unknown"
    EAST_WEST = "east_west"
    NORTH_SOUTH = "north_south"


# --- Domain models ---


class TopologyNode(BaseModel):
    """A node in the network topology map."""

    node_id: str = ""
    hostname: str = ""
    ip_addresses: list[str] = Field(default_factory=list)
    workload_type: str = ""
    labels: dict[str, str] = Field(default_factory=dict)
    zone: str = ""
    connections: int = 0


class NetworkFlow(BaseModel):
    """Observed east-west traffic flow between workloads."""

    flow_id: str = ""
    source_workload: str = ""
    destination_workload: str = ""
    protocol: str = ""
    port: int = 0
    bytes_transferred: int = 0
    classification: FlowClassification = FlowClassification.UNKNOWN
    frequency: int = 0


class SegmentationPolicy(BaseModel):
    """A generated microsegmentation policy rule."""

    policy_id: str = ""
    source_selector: dict[str, str] = Field(default_factory=dict)
    destination_selector: dict[str, str] = Field(default_factory=dict)
    allowed_protocols: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    action: str = "allow"
    priority: int = 0
    validated: bool = False


class PolicyValidation(BaseModel):
    """Validation result for a segmentation policy."""

    policy_id: str = ""
    valid: bool = False
    conflicts: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    recommendations: list[str] = Field(default_factory=list)


class DeploymentResult(BaseModel):
    """Result of deploying microsegmentation policies."""

    deployment_id: str = ""
    policies_deployed: int = 0
    policies_failed: int = 0
    rollback_available: bool = True
    enforcement_mode: str = "monitor"
    deployed_at: datetime | None = None


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the orchestrator workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class NetworkMicrosegmentationState(BaseModel):
    """Full state for a network microsegmentation run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: NMSStage = NMSStage.MAP_TOPOLOGY

    # Inputs
    network_scope: str = ""
    segmentation_type: SegmentationType = SegmentationType.ZERO_TRUST
    target_zones: list[str] = Field(default_factory=list)
    enforcement_mode: str = "monitor"

    # Pipeline fields
    topology: list[dict[str, Any]] = Field(default_factory=list)
    flows: list[dict[str, Any]] = Field(default_factory=list)
    policies: list[dict[str, Any]] = Field(default_factory=list)
    validations: list[dict[str, Any]] = Field(default_factory=list)
    deployments: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_nodes: int = 0
    total_flows: int = 0
    policies_generated: int = 0
    policies_deployed: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
