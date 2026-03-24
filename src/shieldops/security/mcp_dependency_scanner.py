"""MCP Dependency Scanner — scan MCP server dependencies for vulnerabilities."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class VulnerabilitySeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class DependencyStatus(StrEnum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    ABANDONED = "abandoned"
    VULNERABLE = "vulnerable"
    UP_TO_DATE = "up_to_date"


class ScanResult(StrEnum):
    CLEAN = "clean"
    VULNERABLE = "vulnerable"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


# --- Models ---


class DependencyRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    package_name: str = ""
    version: str = ""
    server_id: str = ""
    status: DependencyStatus = DependencyStatus.ACTIVE
    last_updated: float = Field(default_factory=time.time)
    vulnerabilities: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)


class ScanRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    server_id: str = ""
    total_dependencies: int = 0
    vulnerable_count: int = 0
    abandoned_count: int = 0
    conflict_count: int = 0
    result: ScanResult = ScanResult.CLEAN
    scanned_at: float = Field(default_factory=time.time)


class DependencyScanReport(BaseModel):
    total_dependencies: int = 0
    total_scans: int = 0
    vulnerable_count: int = 0
    abandoned_count: int = 0
    conflict_count: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class MCPDependencyScanner:
    """Scan MCP server dependencies for vulnerabilities and issues."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._dependencies: list[DependencyRecord] = []
        self._scans: list[ScanRecord] = []
        logger.info("mcp_dependency_scanner.initialized", max_records=max_records)

    def register_dependency(
        self,
        package_name: str,
        version: str = "",
        server_id: str = "",
        status: DependencyStatus = DependencyStatus.ACTIVE,
    ) -> DependencyRecord:
        record = DependencyRecord(
            package_name=package_name,
            version=version,
            server_id=server_id,
            status=status,
        )
        self._dependencies.append(record)
        if len(self._dependencies) > self._max_records:
            self._dependencies = self._dependencies[-self._max_records :]
        return record

    def scan_dependencies(
        self,
        server_id: str = "",
        vuln_db: dict[str, list[str]] | None = None,
    ) -> ScanRecord:
        deps = (
            [d for d in self._dependencies if d.server_id == server_id]
            if server_id
            else list(self._dependencies)
        )
        vuln_db = vuln_db or {}
        vuln_count = 0
        for dep in deps:
            known_vulns = vuln_db.get(dep.package_name, [])
            if known_vulns:
                dep.vulnerabilities = known_vulns
                dep.status = DependencyStatus.VULNERABLE
                vuln_count += 1
        abandoned = sum(1 for d in deps if d.status == DependencyStatus.ABANDONED)
        conflicts = len(self.detect_version_conflicts(server_id))
        result = ScanResult.CLEAN
        if vuln_count > 0:
            result = ScanResult.VULNERABLE
        elif conflicts > 0:
            result = ScanResult.CONFLICT
        scan = ScanRecord(
            server_id=server_id,
            total_dependencies=len(deps),
            vulnerable_count=vuln_count,
            abandoned_count=abandoned,
            conflict_count=conflicts,
            result=result,
        )
        self._scans.append(scan)
        if len(self._scans) > self._max_records:
            self._scans = self._scans[-self._max_records :]
        return scan

    def detect_abandoned(self, stale_days: int = 365) -> list[DependencyRecord]:
        cutoff = time.time() - stale_days * 86400
        results: list[DependencyRecord] = []
        for d in self._dependencies:
            if d.last_updated < cutoff:
                d.status = DependencyStatus.ABANDONED
                results.append(d)
        return results

    def detect_version_conflicts(self, server_id: str = "") -> list[dict[str, Any]]:
        deps = (
            [d for d in self._dependencies if d.server_id == server_id]
            if server_id
            else list(self._dependencies)
        )
        pkg_versions: dict[str, dict[str, list[str]]] = {}
        for d in deps:
            pkg_versions.setdefault(d.package_name, {}).setdefault(d.version, []).append(
                d.server_id
            )
        conflicts: list[dict[str, Any]] = []
        for pkg, versions in pkg_versions.items():
            if len(versions) > 1:
                conflicts.append(
                    {
                        "package": pkg,
                        "versions": list(versions.keys()),
                        "servers": [s for slist in versions.values() for s in slist],
                    }
                )
        return conflicts

    def generate_report(self) -> DependencyScanReport:
        by_status: dict[str, int] = {}
        for d in self._dependencies:
            by_status[d.status.value] = by_status.get(d.status.value, 0) + 1
        vuln = sum(1 for d in self._dependencies if d.status == DependencyStatus.VULNERABLE)
        abandoned = sum(1 for d in self._dependencies if d.status == DependencyStatus.ABANDONED)
        conflicts = len(self.detect_version_conflicts())
        recs: list[str] = []
        if vuln > 0:
            recs.append(f"{vuln} vulnerable dependencies need patching")
        if abandoned > 0:
            recs.append(f"{abandoned} abandoned dependencies need replacement")
        if conflicts > 0:
            recs.append(f"{conflicts} version conflict(s) detected")
        if not recs:
            recs.append("All MCP dependencies are clean and up to date")
        return DependencyScanReport(
            total_dependencies=len(self._dependencies),
            total_scans=len(self._scans),
            vulnerable_count=vuln,
            abandoned_count=abandoned,
            conflict_count=conflicts,
            by_status=by_status,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_dependencies": len(self._dependencies),
            "total_scans": len(self._scans),
            "unique_packages": len({d.package_name for d in self._dependencies}),
            "unique_servers": len({d.server_id for d in self._dependencies}),
        }

    def clear_data(self) -> dict[str, str]:
        self._dependencies.clear()
        self._scans.clear()
        return {"status": "cleared"}
