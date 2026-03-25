"""Vendor Normalizer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class NormalizerStage(StrEnum):
    INGEST = "ingest"
    DETECT_SCHEMA = "detect_schema"
    MAP_TO_OCSF = "map_to_ocsf"
    VALIDATE = "validate"
    ENRICH = "enrich"
    EMIT = "emit"


class VendorType(StrEnum):
    CROWDSTRIKE = "crowdstrike"
    MICROSOFT_DEFENDER = "microsoft_defender"
    WIZ = "wiz"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    DATADOG = "datadog"
    NEWRELIC = "newrelic"
    PAGERDUTY = "pagerduty"
    SERVICENOW = "servicenow"
    JIRA = "jira"
    OPSGENIE = "opsgenie"
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    KUBERNETES = "kubernetes"
    LINUX = "linux"
    WINDOWS = "windows"


class OCSFCategory(StrEnum):
    SECURITY_FINDING = "security_finding"
    DETECTION_FINDING = "detection_finding"
    VULNERABILITY_FINDING = "vulnerability_finding"
    COMPLIANCE_FINDING = "compliance_finding"
    IDENTITY_ACTIVITY = "identity_activity"
    NETWORK_ACTIVITY = "network_activity"
    SYSTEM_ACTIVITY = "system_activity"
    APPLICATION_ACTIVITY = "application_activity"


class VendorEvent(BaseModel):
    """A raw event ingested from a vendor source."""

    id: str = ""
    vendor: VendorType = VendorType.AWS
    raw_data: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = ""
    event_type: str = ""
    severity: str = ""


class SchemaMapping(BaseModel):
    """A field-level mapping from vendor schema to OCSF schema."""

    id: str = ""
    vendor: VendorType = VendorType.AWS
    vendor_field: str = ""
    ocsf_field: str = ""
    transform_rule: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class NormalizedEvent(BaseModel):
    """An event normalized to OCSF format."""

    id: str = ""
    ocsf_category: OCSFCategory = OCSFCategory.SECURITY_FINDING
    ocsf_class: str = ""
    vendor_source: VendorType = VendorType.AWS
    original_id: str = ""
    severity: str = ""
    timestamp: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    observables: list[dict[str, Any]] = Field(default_factory=list)
    enrichments: list[dict[str, Any]] = Field(default_factory=list)


class ValidationResult(BaseModel):
    """Result of validating a normalized event against OCSF spec."""

    id: str = ""
    event_id: str = ""
    valid: bool = True
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    completeness_score: float = Field(default=0.0, ge=0.0, le=1.0)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class VendorNormalizerState(BaseModel):
    """Main state for the Vendor Normalizer agent graph."""

    request_id: str = ""
    stage: NormalizerStage = NormalizerStage.INGEST

    # Pipeline data
    vendor_events: list[VendorEvent] = Field(default_factory=list)
    schema_mappings: list[SchemaMapping] = Field(default_factory=list)
    normalized_events: list[NormalizedEvent] = Field(default_factory=list)
    validation_results: list[ValidationResult] = Field(default_factory=list)
    enriched_events: list[NormalizedEvent] = Field(default_factory=list)

    # Stats
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""

    # Timing
    session_start: str = ""
    session_duration_ms: float = 0.0

    # Error
    error: str = ""
