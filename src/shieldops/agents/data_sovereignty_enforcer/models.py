"""Data Sovereignty Enforcer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SovereigntyStage(StrEnum):
    DISCOVER_DATA_FLOWS = "discover_data_flows"
    MAP_JURISDICTIONS = "map_jurisdictions"
    CHECK_RESIDENCY = "check_residency"
    VALIDATE_TRANSFERS = "validate_transfers"
    ENFORCE_POLICIES = "enforce_policies"
    REPORT = "report"


class Jurisdiction(StrEnum):
    EU = "eu"
    US = "us"
    UK = "uk"
    CHINA = "china"
    INDIA = "india"
    BRAZIL = "brazil"
    JAPAN = "japan"
    AUSTRALIA = "australia"
    CANADA = "canada"
    SINGAPORE = "singapore"


class TransferMechanism(StrEnum):
    ADEQUACY_DECISION = "adequacy_decision"
    STANDARD_CONTRACTUAL_CLAUSES = "standard_contractual_clauses"
    BINDING_CORPORATE_RULES = "binding_corporate_rules"
    CONSENT = "consent"
    DEROGATION = "derogation"
    NONE = "none"


class DataFlow(BaseModel):
    """A detected data flow between systems or regions."""

    id: str = ""
    source_system: str = ""
    destination_system: str = ""
    source_region: str = ""
    destination_region: str = ""
    data_categories: list[str] = Field(default_factory=list)
    volume_gb_per_day: float = 0.0
    encrypted: bool = False
    protocol: str = ""


class JurisdictionMapping(BaseModel):
    """Mapping of a data flow to applicable jurisdictions and regulations."""

    id: str = ""
    flow_id: str = ""
    source_jurisdiction: Jurisdiction = Jurisdiction.US
    destination_jurisdiction: Jurisdiction = Jurisdiction.US
    regulations: list[str] = Field(default_factory=list)
    cross_border: bool = False
    restricted: bool = False


class ResidencyViolation(BaseModel):
    """A detected data residency violation."""

    id: str = ""
    flow_id: str = ""
    regulation: str = ""
    requirement: str = ""
    actual_location: str = ""
    required_location: str = ""
    severity: str = "medium"
    remediation: str = ""


class TransferValidation(BaseModel):
    """Validation result for a cross-border data transfer."""

    id: str = ""
    flow_id: str = ""
    mechanism: TransferMechanism = TransferMechanism.NONE
    valid: bool = False
    regulation: str = ""
    details: str = ""
    expiry_date: str = ""


class PolicyEnforcement(BaseModel):
    """Record of a sovereignty policy enforcement action."""

    id: str = ""
    flow_id: str = ""
    action: str = ""
    policy_name: str = ""
    applied: bool = False
    success: bool = False
    details: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class DataSovereigntyEnforcerState(BaseModel):
    """Main state for the Data Sovereignty Enforcer graph."""

    # Input
    request_id: str = ""
    stage: SovereigntyStage = SovereigntyStage.DISCOVER_DATA_FLOWS
    tenant_id: str = ""

    # Data
    data_flows: list[dict[str, Any]] = Field(default_factory=list)
    jurisdiction_mappings: list[dict[str, Any]] = Field(default_factory=list)
    residency_violations: list[dict[str, Any]] = Field(default_factory=list)
    transfer_validations: list[dict[str, Any]] = Field(default_factory=list)
    policy_enforcements: list[dict[str, Any]] = Field(default_factory=list)

    # Findings
    findings: list[dict[str, Any]] = Field(default_factory=list)

    # Stats
    stats: dict[str, Any] = Field(default_factory=dict)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
