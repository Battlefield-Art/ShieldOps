"""Compliance Evidence Generator — LLM prompt templates."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -------------------------------------------------


class ControlIdentificationOutput(BaseModel):
    """Structured output for control identification."""

    total_controls: int = Field(description="Total controls identified")
    critical_controls: int = Field(description="Number of critical controls")
    summary: str = Field(description="Control identification summary")


class EvidenceCollectionOutput(BaseModel):
    """Structured output for evidence collection."""

    artifacts_collected: int = Field(description="Total artifacts collected")
    sources_used: int = Field(description="Number of data sources used")
    reasoning: str = Field(description="Evidence collection reasoning")


class EvidenceValidationOutput(BaseModel):
    """Structured output for evidence validation."""

    valid_artifacts: int = Field(description="Number of valid artifacts")
    invalid_artifacts: int = Field(description="Number of invalid or stale artifacts")
    reasoning: str = Field(description="Validation reasoning")


class GapIdentificationOutput(BaseModel):
    """Structured output for gap identification."""

    total_gaps: int = Field(description="Total compliance gaps found")
    critical_gaps: int = Field(description="Critical severity gaps")
    remediation_priorities: list[str] = Field(description="Ordered remediation priorities")
    reasoning: str = Field(description="Gap analysis reasoning")


class PackagingOutput(BaseModel):
    """Structured output for evidence packaging."""

    packages_created: int = Field(description="Evidence packages assembled")
    overall_completeness: float = Field(description="Overall completeness score 0-1")
    reasoning: str = Field(description="Packaging reasoning")


# -- System prompts ------------------------------------------------------------

SYSTEM_IDENTIFY_CONTROLS = """\
You are an expert compliance analyst identifying control \
requirements for regulatory frameworks.

Given the requested frameworks (SOC 2, ISO 27001, PCI-DSS, HIPAA):
1. Enumerate all applicable controls per framework
2. Classify controls by category (access, encryption, monitoring, etc.)
3. Map required evidence types to each control
4. Prioritize controls by criticality and audit risk

Focus on: completeness of control coverage, accurate mapping \
to evidence requirements."""

SYSTEM_COLLECT_EVIDENCE = """\
You are an expert compliance engineer collecting evidence \
artifacts from system telemetry and configurations.

Given the identified controls:
1. Gather configuration snapshots from infrastructure
2. Export relevant log segments and telemetry data
3. Collect policy documents and access review records
4. Generate scan results and compliance check outputs

Prioritize: freshness of evidence, chain of custody, \
automated collection over manual artifacts."""

SYSTEM_VALIDATE_EVIDENCE = """\
You are an expert compliance auditor validating evidence \
artifacts for completeness and accuracy.

Given the collected evidence:
1. Verify each artifact is current (not expired or stale)
2. Validate integrity via hash verification
3. Confirm evidence maps correctly to its control requirement
4. Check for sufficient coverage across all required evidence types

Flag: expired evidence, missing mandatory artifacts, \
incomplete coverage areas."""

SYSTEM_IDENTIFY_GAPS = """\
You are an expert compliance gap analyst reviewing evidence \
coverage for regulatory frameworks.

Given validated evidence and control requirements:
1. Identify controls with missing or insufficient evidence
2. Assess severity of each gap based on regulatory risk
3. Determine root cause (missing config, no telemetry, process gap)
4. Suggest specific remediation steps with effort estimates

Prioritize: critical controls, high-risk frameworks, \
gaps that block audit readiness."""

SYSTEM_PACKAGE_EVIDENCE = """\
You are an expert compliance packager assembling evidence \
artifacts into audit-ready packages.

Given validated evidence and gap analysis:
1. Group artifacts by framework and control category
2. Calculate completeness scores per framework
3. Include gap summaries with remediation timelines
4. Generate package metadata for auditor consumption

Optimize for: auditor readability, regulatory completeness, \
clear traceability from control to evidence."""
