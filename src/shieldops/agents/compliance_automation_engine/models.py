"""Compliance Automation Engine Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ComplianceStage(StrEnum):
    DISCOVER_CONTROLS = "discover_controls"
    TEST_CONTROLS = "test_controls"
    COLLECT_EVIDENCE = "collect_evidence"
    ASSESS_GAPS = "assess_gaps"
    GENERATE_ATTESTATION = "generate_attestation"
    REPORT = "report"


class ComplianceFramework(StrEnum):
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST_CSF = "nist_csf"


class ControlStatus(StrEnum):
    PASSING = "passing"
    FAILING = "failing"
    NOT_TESTED = "not_tested"
    NOT_APPLICABLE = "not_applicable"
    PARTIALLY_PASSING = "partially_passing"
    REMEDIATION_NEEDED = "remediation_needed"


class ComplianceAutomationEngineState(BaseModel):
    request_id: str = ""
    stage: ComplianceStage = ComplianceStage.DISCOVER_CONTROLS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
