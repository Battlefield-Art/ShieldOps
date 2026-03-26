"""Security App Builder Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class BuilderStage(StrEnum):
    PARSE_REQUIREMENTS = "parse_requirements"
    DESIGN_WORKFLOW = "design_workflow"
    GENERATE_CODE = "generate_code"
    VALIDATE_SECURITY = "validate_security"
    DEPLOY_APP = "deploy_app"
    REPORT = "report"


class AppType(StrEnum):
    DETECTION_RULE = "detection_rule"
    RESPONSE_PLAYBOOK = "response_playbook"
    INVESTIGATION_WORKFLOW = "investigation_workflow"
    COMPLIANCE_CHECK = "compliance_check"
    MONITORING_DASHBOARD = "monitoring_dashboard"


class DeploymentTarget(StrEnum):
    STAGING = "staging"
    PRODUCTION = "production"
    DRY_RUN = "dry_run"


class AppRequirement(BaseModel):
    """Parsed requirement from natural language description."""

    requirement_id: str = ""
    description: str = ""
    app_type: AppType = AppType.DETECTION_RULE
    inputs: list[str] = Field(default_factory=list)
    outputs: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    security_constraints: list[str] = Field(default_factory=list)
    priority: str = "medium"


class WorkflowNode(BaseModel):
    """A single node in the designed workflow."""

    node_id: str = ""
    name: str = ""
    description: str = ""
    node_type: str = "action"
    inputs: list[str] = Field(default_factory=list)
    outputs: list[str] = Field(default_factory=list)


class WorkflowEdge(BaseModel):
    """An edge connecting two workflow nodes."""

    source: str = ""
    target: str = ""
    condition: str = ""


class WorkflowDesign(BaseModel):
    """Complete workflow design with nodes and edges."""

    design_id: str = ""
    app_type: AppType = AppType.DETECTION_RULE
    nodes: list[WorkflowNode] = Field(default_factory=list)
    edges: list[WorkflowEdge] = Field(default_factory=list)
    entry_point: str = ""
    description: str = ""


class GeneratedCode(BaseModel):
    """Generated LangGraph code artifact."""

    file_name: str = ""
    content: str = ""
    language: str = "python"
    line_count: int = 0


class SecurityValidation(BaseModel):
    """Result of security validation on generated code."""

    validation_id: str = ""
    check_name: str = ""
    passed: bool = True
    severity: str = "info"
    details: str = ""


class DeploymentResult(BaseModel):
    """Result of deploying the generated application."""

    deployment_id: str = ""
    target: DeploymentTarget = DeploymentTarget.DRY_RUN
    success: bool = False
    endpoint: str = ""
    details: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityAppBuilderState(BaseModel):
    """Main state for the Security App Builder agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: BuilderStage = BuilderStage.PARSE_REQUIREMENTS

    # Natural language input
    nl_description: str = ""

    # Parsed requirements
    requirements: list[AppRequirement] = Field(default_factory=list)

    # Workflow design
    workflow_design: WorkflowDesign = Field(default_factory=WorkflowDesign)

    # Generated code artifacts
    generated_code: list[GeneratedCode] = Field(default_factory=list)

    # Security validations
    validations: list[SecurityValidation] = Field(default_factory=list)

    # Deployment
    deployment: DeploymentResult = Field(default_factory=DeploymentResult)
    deployment_target: DeploymentTarget = DeploymentTarget.DRY_RUN

    # Metrics
    apps_built: int = 0
    code_quality_score: float = 0.0

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
