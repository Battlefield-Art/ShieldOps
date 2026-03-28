"""State models for the Security Pipeline Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PipelineStage(StrEnum):
    """Stages of the security pipeline workflow."""

    PLAN_PIPELINE = "plan_pipeline"
    DISPATCH_DISCOVERY = "dispatch_discovery"
    DISPATCH_PENTEST = "dispatch_pentest"
    COLLECT_FINDINGS = "collect_findings"
    DISPATCH_REMEDIATION = "dispatch_remediation"
    VERIFY_RESULTS = "verify_results"
    REPORT = "report"


class PipelinePhase(StrEnum):
    """Phases within a pipeline run."""

    DISCOVERY = "discovery"
    TESTING = "testing"
    ANALYSIS = "analysis"
    REMEDIATION = "remediation"
    VERIFICATION = "verification"


class RunStatus(StrEnum):
    """Status of a pipeline run."""

    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


class PipelinePlan(BaseModel):
    """Plan for which agents to invoke in the pipeline."""

    id: str = ""
    phases: list[str] = Field(default_factory=list)
    agents_to_dispatch: list[str] = Field(default_factory=list)
    estimated_duration_minutes: int = 0
    target_assets: list[str] = Field(default_factory=list)
    policy_constraints: dict[str, Any] = Field(default_factory=dict)


class DiscoveryDispatch(BaseModel):
    """Result from dispatching discovery agents."""

    agent_name: str = ""
    status: str = ""
    assets_discovered: int = 0
    findings_count: int = 0
    duration_ms: int = 0
    details: dict[str, Any] = Field(default_factory=dict)


class PentestDispatch(BaseModel):
    """Result from dispatching pentest agents."""

    agent_name: str = ""
    status: str = ""
    vulnerabilities_found: int = 0
    critical_count: int = 0
    high_count: int = 0
    duration_ms: int = 0
    details: dict[str, Any] = Field(default_factory=dict)


class FindingCollection(BaseModel):
    """Aggregated finding from all agents."""

    id: str = ""
    source_agent: str = ""
    severity: str = ""
    title: str = ""
    description: str = ""
    asset: str = ""
    remediation_hint: str = ""
    cvss_score: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class RemediationDispatch(BaseModel):
    """Result from dispatching a remediation action."""

    finding_id: str = ""
    agent_name: str = ""
    status: str = ""
    action_taken: str = ""
    rollback_available: bool = False
    duration_ms: int = 0


class VerificationResult(BaseModel):
    """Result from verifying a remediation was effective."""

    finding_id: str = ""
    verified: bool = False
    retest_passed: bool = False
    remaining_risk: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class SecurityPipelineState(BaseModel):
    """Full state for the security pipeline workflow."""

    # Input
    tenant_id: str = ""
    request_id: str = ""

    # Pipeline data
    pipeline_plan: PipelinePlan = Field(default_factory=PipelinePlan)
    discovery_results: list[DiscoveryDispatch] = Field(default_factory=list)
    pentest_results: list[PentestDispatch] = Field(default_factory=list)
    findings: list[FindingCollection] = Field(default_factory=list)
    remediations: list[RemediationDispatch] = Field(default_factory=list)
    verifications: list[VerificationResult] = Field(default_factory=list)

    # Metrics
    cycle_count: int = 0
    agents_dispatched: int = 0
    findings_resolved: int = 0

    # Workflow tracking
    current_stage: PipelineStage = PipelineStage.PLAN_PIPELINE
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    session_duration_ms: int = 0
