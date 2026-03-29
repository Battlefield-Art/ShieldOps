"""SCA Dependency Checker Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SCAStage(StrEnum):
    DISCOVER_MANIFESTS = "discover_manifests"
    PARSE_DEPENDENCIES = "parse_dependencies"
    MATCH_CVES = "match_cves"
    CHECK_LICENSES = "check_licenses"
    PRIORITIZE = "prioritize"
    REPORT = "report"


class DependencyRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class LicenseType(StrEnum):
    MIT = "mit"
    APACHE_2 = "apache_2"
    GPL_3 = "gpl_3"
    GPL_2 = "gpl_2"
    BSD_2 = "bsd_2"
    BSD_3 = "bsd_3"
    LGPL = "lgpl"
    MPL = "mpl"
    AGPL = "agpl"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


class CVEMatch(BaseModel):
    """A CVE matched to a dependency."""

    cve_id: str = ""
    cvss_score: float = 0.0
    severity: DependencyRisk = DependencyRisk.MEDIUM
    description: str = ""
    fixed_version: str = ""
    published_date: str = ""
    exploitability: str = ""
    is_exploitable: bool = False
    references: list[str] = Field(default_factory=list)


class DependencyRecord(BaseModel):
    """A single dependency record."""

    id: str = ""
    package_name: str = ""
    installed_version: str = ""
    latest_version: str = ""
    ecosystem: str = ""
    is_direct: bool = True
    is_outdated: bool = False
    license_type: LicenseType = LicenseType.UNKNOWN
    license_compatible: bool = True
    cves: list[CVEMatch] = Field(default_factory=list)
    risk: DependencyRisk = DependencyRisk.NONE
    transitive_depth: int = 0
    dependents: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SCADependencyCheckerState(BaseModel):
    """Full state for the SCA Dependency Checker agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SCAStage = SCAStage.DISCOVER_MANIFESTS
    scan_targets: list[str] = Field(default_factory=list)
    manifests: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    dependencies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_dependencies: int = 0
    cve_matches: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    license_violations: list[dict[str, Any]] = Field(
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
