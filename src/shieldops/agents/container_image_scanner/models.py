"""Container Image Scanner Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ImageScanStage(StrEnum):
    DISCOVER_IMAGES = "discover_images"
    ANALYZE_LAYERS = "analyze_layers"
    SCAN_VULNERABILITIES = "scan_vulnerabilities"
    CHECK_COMPLIANCE = "check_compliance"
    PRIORITIZE = "prioritize"
    REPORT = "report"


class LayerRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CLEAN = "clean"


class ComplianceStatus(StrEnum):
    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"
    SKIPPED = "skipped"


class ImageLayer(BaseModel):
    """A single layer in a container image."""

    id: str = ""
    digest: str = ""
    size_bytes: int = 0
    command: str = ""
    created_by: str = ""
    risk: LayerRisk = LayerRisk.CLEAN
    has_secrets: bool = False
    has_malware: bool = False
    package_count: int = 0
    vuln_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ImageVuln(BaseModel):
    """A vulnerability found in a container image."""

    id: str = ""
    image_ref: str = ""
    layer_digest: str = ""
    package_name: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    cve_id: str = ""
    severity: str = "medium"
    cvss_score: float = 0.0
    description: str = ""
    is_fixable: bool = False
    is_os_package: bool = True
    exploit_available: bool = False
    remediation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ContainerImageScannerState(BaseModel):
    """Full state for the Container Image Scanner agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: ImageScanStage = ImageScanStage.DISCOVER_IMAGES
    image_refs: list[str] = Field(default_factory=list)
    discovered_images: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_images: int = 0
    layers: list[dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    compliance_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    prioritized: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_findings: int = 0
    critical_count: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
