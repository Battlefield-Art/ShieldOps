"""CNAPP Analyzer Agent — Pydantic state and data models."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CNAPPStage(StrEnum):
    SCAN_CLOUD_POSTURE = "scan_cloud_posture"
    ASSESS_WORKLOAD_PROTECTION = "assess_workload_protection"
    ANALYZE_IDENTITY_ENTITLEMENTS = "analyze_identity_entitlements"
    SCAN_CODE_SECURITY = "scan_code_security"
    CORRELATE_RISKS = "correlate_risks"
    REPORT = "report"


class SecurityDomain(StrEnum):
    CSPM = "cspm"
    CWPP = "cwpp"
    CIEM = "ciem"
    CODE_SECURITY = "code_security"
    DATA_SECURITY = "data_security"


class ComplianceFramework(StrEnum):
    CIS = "cis"
    NIST = "nist"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    ISO27001 = "iso27001"


class SeverityLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PostureFinding(BaseModel):
    """A cloud posture finding from CSPM scanning."""

    id: str = ""
    provider: str = ""
    resource_type: str = ""
    resource_id: str = ""
    region: str = ""
    benchmark: str = ""
    control_id: str = ""
    control_name: str = ""
    status: str = "pass"
    severity: SeverityLevel = SeverityLevel.MEDIUM
    description: str = ""
    remediation: str = ""
    auto_remediable: bool = False
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)


class WorkloadThreat(BaseModel):
    """A workload protection threat from CWPP scanning."""

    id: str = ""
    workload_type: str = ""
    workload_id: str = ""
    image: str = ""
    threat_type: str = ""
    severity: SeverityLevel = SeverityLevel.MEDIUM
    cve_id: str = ""
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    description: str = ""
    fix_available: bool = False
    runtime_detected: bool = False


class EntitlementRisk(BaseModel):
    """An identity entitlement risk from CIEM analysis."""

    id: str = ""
    provider: str = ""
    identity_type: str = ""
    identity_arn: str = ""
    permission_count: int = 0
    used_permission_count: int = 0
    unused_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: SeverityLevel = SeverityLevel.MEDIUM
    risk_type: str = ""
    description: str = ""
    right_sized_policy: str = ""


class CodeVulnerability(BaseModel):
    """A code or IaC vulnerability from code security scanning."""

    id: str = ""
    source_type: str = ""
    file_path: str = ""
    line_number: int = 0
    vuln_type: str = ""
    severity: SeverityLevel = SeverityLevel.MEDIUM
    description: str = ""
    cwe_id: str = ""
    fix_suggestion: str = ""
    iac_provider: str = ""


class UnifiedRiskScore(BaseModel):
    """Unified risk score correlating all CNAPP domains."""

    overall_score: float = Field(default=0.0, ge=0.0, le=100.0)
    cspm_score: float = Field(default=0.0, ge=0.0, le=100.0)
    cwpp_score: float = Field(default=0.0, ge=0.0, le=100.0)
    ciem_score: float = Field(default=0.0, ge=0.0, le=100.0)
    code_security_score: float = Field(default=0.0, ge=0.0, le=100.0)
    risk_level: str = "medium"
    attack_paths: list[str] = Field(default_factory=list)
    top_recommendations: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CNAPPAnalyzerState(BaseModel):
    """Main state for the CNAPP Analyzer agent graph."""

    request_id: str = ""
    stage: CNAPPStage = CNAPPStage.SCAN_CLOUD_POSTURE
    tenant_id: str = ""
    providers: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)

    # CSPM results
    posture_findings: list[dict[str, Any]] = Field(default_factory=list)

    # CWPP results
    workload_threats: list[dict[str, Any]] = Field(default_factory=list)

    # CIEM results
    entitlement_risks: list[dict[str, Any]] = Field(default_factory=list)

    # Code security results
    code_vulns: list[dict[str, Any]] = Field(default_factory=list)

    # Unified risk correlation
    unified_risk_score: dict[str, Any] = Field(default_factory=dict)

    # Compliance coverage
    compliance_coverage: dict[str, Any] = Field(default_factory=dict)

    # Stats / summary
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""

    # Timing
    session_start: float = Field(default_factory=time.time)
    session_duration_ms: float = 0.0

    # Error
    error: str = ""
