"""Unified Cloud Security Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CloudSecStage(StrEnum):
    COLLECT_CLOUD_STATE = "collect_cloud_state"
    ASSESS_POSTURE = "assess_posture"
    DETECT_THREATS = "detect_threats"
    PRIORITIZE_RISKS = "prioritize_risks"
    ORCHESTRATE_RESPONSE = "orchestrate_response"
    REPORT = "report"


class CloudPlatform(StrEnum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    KUBERNETES = "kubernetes"
    MULTI_CLOUD = "multi_cloud"


class SecurityFunction(StrEnum):
    CSPM = "cspm"
    CWPP = "cwpp"
    CDR = "cdr"
    CIEM = "ciem"
    DSPM = "dspm"


class CloudState(BaseModel):
    """Cloud state snapshot."""

    id: str = ""
    platform: CloudPlatform = CloudPlatform.AWS
    region: str = ""
    resource_count: int = 0
    misconfiguration_count: int = 0
    identity_count: int = 0
    workload_count: int = 0
    data_store_count: int = 0
    last_scan: str = ""


class PostureAssessment(BaseModel):
    """Cloud security posture assessment."""

    id: str = ""
    platform: CloudPlatform = CloudPlatform.AWS
    function: SecurityFunction = SecurityFunction.CSPM
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    findings_count: int = 0
    critical_findings: int = 0
    benchmark: str = ""
    compliant_pct: float = Field(default=0.0, ge=0.0, le=100.0)


class CloudThreat(BaseModel):
    """Detected cloud threat."""

    id: str = ""
    platform: CloudPlatform = CloudPlatform.AWS
    threat_type: str = ""
    severity: str = ""
    resource_id: str = ""
    description: str = ""
    mitre_technique: str = ""
    detected_at: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class RiskPriority(BaseModel):
    """Prioritized risk with context."""

    id: str = ""
    threat_id: str = ""
    platform: CloudPlatform = CloudPlatform.AWS
    priority_score: float = Field(default=0.0, ge=0.0, le=10.0)
    blast_radius: str = ""
    business_impact: str = ""
    exploitability: str = ""
    recommended_action: str = ""


class ResponseOrchestration(BaseModel):
    """Response orchestration record."""

    id: str = ""
    risk_id: str = ""
    platform: CloudPlatform = CloudPlatform.AWS
    action_type: str = ""
    automated: bool = False
    status: str = "pending"
    playbook_id: str = ""
    estimated_time_min: int = 0


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class UnifiedCloudSecurityState(BaseModel):
    """Main state for the Unified Cloud Security agent."""

    request_id: str = ""
    tenant_id: str = ""
    providers: list[str] = Field(default_factory=lambda: ["aws"])
    stage: CloudSecStage = CloudSecStage.COLLECT_CLOUD_STATE

    # Cloud states
    cloud_states: list[CloudState] = Field(default_factory=list)

    # Posture assessments
    assessments: list[PostureAssessment] = Field(default_factory=list)

    # Cloud threats
    threats: list[CloudThreat] = Field(default_factory=list)

    # Risk priorities
    priorities: list[RiskPriority] = Field(default_factory=list)

    # Response orchestrations
    responses: list[ResponseOrchestration] = Field(default_factory=list)

    # Summary
    report: str = ""
    total_resources: int = 0
    critical_threats: int = 0
    avg_posture_score: float = 0.0

    # Reasoning
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)

    # Error
    error: str = ""
