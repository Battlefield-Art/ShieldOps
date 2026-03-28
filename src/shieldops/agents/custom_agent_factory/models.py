"""State models for Custom Agent Factory."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class FactoryStage(StrEnum):
    """Stages of the agent factory workflow."""

    PARSE_REQUIREMENTS = "parse_requirements"
    DESIGN_AGENT = "design_agent"
    GENERATE_CODE = "generate_code"
    VALIDATE_AGENT = "validate_agent"
    REGISTER_AGENT = "register_agent"
    REPORT = "report"


class AgentCategory(StrEnum):
    """Categories for generated agents."""

    DETECTION = "detection"
    RESPONSE = "response"
    COMPLIANCE = "compliance"
    MONITORING = "monitoring"
    TESTING = "testing"
    REPORTING = "reporting"


class ValidationStatus(StrEnum):
    """Validation status of a generated agent."""

    VALID = "valid"
    HAS_WARNINGS = "has_warnings"
    INVALID = "invalid"
    NEEDS_REVIEW = "needs_review"


class AgentRequirement(BaseModel):
    """Parsed requirements for a custom agent."""

    id: str = ""
    description: str = ""
    category: AgentCategory = AgentCategory.DETECTION
    agent_name: str = ""
    trigger: str = ""
    data_sources: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    output_format: str = "json"
    schedule: str = "on_demand"


class AgentDesign(BaseModel):
    """Design blueprint for a custom agent."""

    id: str = ""
    agent_name: str = ""
    category: AgentCategory = AgentCategory.DETECTION
    nodes: list[str] = Field(default_factory=list)
    state_fields: list[str] = Field(default_factory=list)
    tools_needed: list[str] = Field(default_factory=list)
    prompts_needed: list[str] = Field(default_factory=list)
    edge_flow: list[str] = Field(default_factory=list)


class GeneratedAgent(BaseModel):
    """Generated agent code artifacts."""

    id: str = ""
    agent_name: str = ""
    files: dict[str, str] = Field(default_factory=dict)
    total_lines: int = 0
    file_count: int = 0


class AgentValidation(BaseModel):
    """Validation result for generated agent."""

    id: str = ""
    status: ValidationStatus = ValidationStatus.NEEDS_REVIEW
    syntax_valid: bool = False
    pattern_compliant: bool = False
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    quality_score: float = 0.0


class RegistrationResult(BaseModel):
    """Result of registering the agent."""

    id: str = ""
    agent_name: str = ""
    registered: bool = False
    registry_id: str = ""
    notes: str = ""


class CustomAgentFactoryState(BaseModel):
    """Full state of a custom agent creation."""

    # Identity
    request_id: str = ""
    stage: FactoryStage = FactoryStage.PARSE_REQUIREMENTS
    tenant_id: str = ""

    # Data
    requirements: AgentRequirement = Field(default_factory=AgentRequirement)
    design: AgentDesign = Field(default_factory=AgentDesign)
    generated_code: GeneratedAgent = Field(default_factory=GeneratedAgent)
    validation: AgentValidation = Field(default_factory=AgentValidation)
    registration: RegistrationResult = Field(default_factory=RegistrationResult)

    # Metrics
    agents_created: int = 0
    code_quality_score: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Tracking
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
