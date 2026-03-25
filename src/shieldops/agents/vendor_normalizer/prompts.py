"""Vendor Normalizer Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class SchemaDetectionOutput(BaseModel):
    """Structured output from LLM-assisted schema detection."""

    vendor: str = Field(description="Detected vendor name")
    schema_version: str = Field(description="Detected schema version or format")
    field_hints: list[str] = Field(description="Key fields identified in the vendor event schema")
    suggested_ocsf_category: str = Field(
        description="Recommended OCSF category for this event type"
    )
    confidence: float = Field(description="Confidence score for the detection (0.0-1.0)")


class MappingOutput(BaseModel):
    """Structured output from LLM-assisted field mapping."""

    mappings: list[dict[str, str]] = Field(
        description="List of vendor_field -> ocsf_field mappings"
    )
    unmapped_fields: list[str] = Field(description="Vendor fields that could not be mapped to OCSF")
    transform_notes: list[str] = Field(
        description="Notes on transformations applied (type coercion, renaming, etc.)"
    )


class ValidationOutput(BaseModel):
    """Structured output from LLM-assisted validation."""

    summary: str = Field(description="Brief summary of validation results")
    critical_issues: list[str] = Field(description="Critical OCSF compliance issues found")
    recommendations: list[str] = Field(
        description="Recommendations for improving normalization quality"
    )
    overall_quality: float = Field(
        description="Overall quality score for the normalization (0.0-1.0)"
    )


class EnrichmentOutput(BaseModel):
    """Structured output from LLM-assisted enrichment."""

    enrichment_sources: list[str] = Field(
        description="Sources used for enrichment (geo-IP, threat intel, etc.)"
    )
    observables_found: list[str] = Field(
        description="Observables extracted (IPs, domains, hashes, etc.)"
    )
    threat_context: str = Field(description="Additional threat context from enrichment")
    risk_adjustment: float = Field(
        description="Risk score adjustment based on enrichment (-1.0 to 1.0)"
    )


SYSTEM_SCHEMA_DETECTION = (
    "You are a telemetry schema analyst for an AI Security Control Plane.\n"
    "Given raw vendor event data, detect the vendor schema format:\n"
    "1. Identify the vendor source (CrowdStrike, Splunk, AWS, etc.)\n"
    "2. Detect the schema version and event format\n"
    "3. Identify key fields (timestamp, severity, event_type, identifiers)\n"
    "4. Recommend the appropriate OCSF category for normalization\n"
    "5. Provide a confidence score for your detection"
)

SYSTEM_FIELD_MAPPING = (
    "You are an OCSF schema mapping specialist.\n"
    "Given vendor-specific fields and the target OCSF category:\n"
    "1. Map each vendor field to the corresponding OCSF field path\n"
    "2. Specify any transformation rules (type coercion, timestamp format, enum mapping)\n"
    "3. Identify unmapped vendor fields that have no OCSF equivalent\n"
    "4. Flag required OCSF fields that have no vendor source\n"
    "5. Ensure observables (IPs, domains, hashes) are extracted into the observables array"
)

SYSTEM_VALIDATION = (
    "You are an OCSF compliance validator for normalized security telemetry.\n"
    "Given a normalized event and the OCSF spec:\n"
    "1. Verify all required fields are present and correctly typed\n"
    "2. Check that enum values match OCSF-defined allowed values\n"
    "3. Validate timestamp formats (ISO 8601) and severity mappings\n"
    "4. Assess completeness — percentage of optional fields populated\n"
    "5. Flag any fields that violate OCSF naming conventions or nesting rules"
)

SYSTEM_ENRICHMENT = (
    "You are a threat intelligence enrichment analyst.\n"
    "Given a normalized OCSF event:\n"
    "1. Extract observables (IP addresses, domains, file hashes, user identifiers)\n"
    "2. Suggest geo-IP enrichment for network-related observables\n"
    "3. Recommend threat intel lookups for indicators of compromise\n"
    "4. Add asset context (owner, criticality, environment) where available\n"
    "5. Adjust risk scoring based on enrichment findings"
)
