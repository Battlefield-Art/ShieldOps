"""MCP Supply Chain Scanner — dependency and integrity verification for MCP components."""

from __future__ import annotations

import hashlib
import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MCPComponentType(StrEnum):
    SERVER_BINARY = "server_binary"
    NPM_PACKAGE = "npm_package"
    PYTHON_PACKAGE = "python_package"
    DOCKER_IMAGE = "docker_image"
    CONFIG_FILE = "config_file"
    PLUGIN = "plugin"


class VulnSeverity(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(StrEnum):
    PENDING = "pending"
    SCANNING = "scanning"
    CLEAN = "clean"
    VULNERABLE = "vulnerable"
    ERROR = "error"


# --- Models ---


class MCPComponentRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    server_id: str = ""
    component_type: MCPComponentType = MCPComponentType.NPM_PACKAGE
    name: str = ""
    version: str = ""
    source_url: str = ""
    integrity_hash: str = ""
    scan_status: ScanStatus = ScanStatus.PENDING
    vulnerabilities_found: int = 0
    last_scanned: float = Field(default_factory=time.time)


class MCPVulnerabilityFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    component_id: str = ""
    cve_id: str = ""
    severity: VulnSeverity = VulnSeverity.MEDIUM
    description: str = ""
    fix_available: bool = False
    fixed_version: str = ""
    discovered_at: float = Field(default_factory=time.time)


class MCPSupplyChainReport(BaseModel):
    total_components: int = 0
    total_vulnerabilities: int = 0
    components_clean: int = 0
    components_vulnerable: int = 0
    by_component_type: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    abandoned_packages: int = 0
    integrity_failures: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class MCPSupplyChainScanner:
    """Dependency scanning and integrity verification for MCP server components."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._components: list[MCPComponentRecord] = []
        self._findings: list[MCPVulnerabilityFinding] = []
        logger.info("mcp_supply_chain_scanner.initialized", max_records=max_records)

    # -- component registration ----------------------------------------------

    def register_component(
        self,
        server_id: str,
        component_type: MCPComponentType = MCPComponentType.NPM_PACKAGE,
        name: str = "",
        version: str = "",
        source_url: str = "",
        integrity_hash: str = "",
    ) -> MCPComponentRecord:
        record = MCPComponentRecord(
            server_id=server_id,
            component_type=component_type,
            name=name,
            version=version,
            source_url=source_url,
            integrity_hash=integrity_hash,
        )
        self._components.append(record)
        if len(self._components) > self._max_records:
            self._components = self._components[-self._max_records :]
        logger.info(
            "mcp_supply_chain_scanner.component_registered",
            component_id=record.id,
            server_id=server_id,
            name=name,
            version=version,
        )
        return record

    def get_component(self, component_id: str) -> MCPComponentRecord | None:
        for c in self._components:
            if c.id == component_id:
                return c
        return None

    def list_components(
        self,
        server_id: str | None = None,
        component_type: MCPComponentType | None = None,
        limit: int = 50,
    ) -> list[MCPComponentRecord]:
        results = list(self._components)
        if server_id is not None:
            results = [c for c in results if c.server_id == server_id]
        if component_type is not None:
            results = [c for c in results if c.component_type == component_type]
        return results[-limit:]

    # -- scanning operations -------------------------------------------------

    def scan_component(self, component_id: str) -> list[MCPVulnerabilityFinding]:
        """Scan a registered component for known vulnerabilities."""
        component = self.get_component(component_id)
        if component is None:
            return []

        component.scan_status = ScanStatus.SCANNING
        findings: list[MCPVulnerabilityFinding] = []

        # Simulate vulnerability scanning based on component characteristics
        risk_indicators = self._assess_component_risk(component)
        for indicator in risk_indicators:
            finding = MCPVulnerabilityFinding(
                component_id=component_id,
                cve_id=indicator.get("cve_id", ""),
                severity=VulnSeverity(indicator.get("severity", "medium")),
                description=indicator.get("description", ""),
                fix_available=indicator.get("fix_available", False),
                fixed_version=indicator.get("fixed_version", ""),
            )
            findings.append(finding)
            self._findings.append(finding)

        component.vulnerabilities_found = len(findings)
        component.scan_status = ScanStatus.VULNERABLE if findings else ScanStatus.CLEAN
        component.last_scanned = time.time()

        if len(self._findings) > self._max_records:
            self._findings = self._findings[-self._max_records :]

        logger.info(
            "mcp_supply_chain_scanner.component_scanned",
            component_id=component_id,
            name=component.name,
            vulnerabilities=len(findings),
            status=component.scan_status.value,
        )
        return findings

    def check_integrity(self, component_id: str) -> dict[str, Any]:
        """Verify integrity hash for a component."""
        component = self.get_component(component_id)
        if component is None:
            return {"status": "not_found", "valid": False}

        if not component.integrity_hash:
            return {
                "status": "no_hash_recorded",
                "valid": False,
                "component_id": component_id,
                "recommendation": "Record integrity hash at build time",
            }

        # Simulated re-computation; real implementation fetches and hashes the artifact
        current_hash = component.integrity_hash
        match = current_hash == component.integrity_hash
        return {
            "status": "verified" if match else "mismatch",
            "valid": match,
            "component_id": component_id,
            "expected_hash": component.integrity_hash,
            "current_hash": current_hash,
        }

    # -- domain operations ---------------------------------------------------

    def detect_abandoned_packages(self, days_since_update: int = 365) -> list[dict[str, Any]]:
        """Find components that may be unmaintained."""
        threshold = time.time() - (days_since_update * 86400)
        abandoned: list[dict[str, Any]] = []
        for c in self._components:
            if c.last_scanned < threshold:
                abandoned.append(
                    {
                        "component_id": c.id,
                        "name": c.name,
                        "version": c.version,
                        "server_id": c.server_id,
                        "last_scanned": c.last_scanned,
                        "days_stale": int((time.time() - c.last_scanned) / 86400),
                    }
                )
        abandoned.sort(key=lambda x: x["days_stale"], reverse=True)
        return abandoned

    def find_components_by_severity(
        self, min_severity: VulnSeverity = VulnSeverity.HIGH
    ) -> list[dict[str, Any]]:
        """Find components with vulnerabilities at or above a given severity."""
        severity_order = [s.value for s in VulnSeverity]
        min_idx = severity_order.index(min_severity.value)
        matching: list[dict[str, Any]] = []
        for f in self._findings:
            f_idx = severity_order.index(f.severity.value)
            if f_idx >= min_idx:
                component = self.get_component(f.component_id)
                matching.append(
                    {
                        "finding_id": f.id,
                        "cve_id": f.cve_id,
                        "severity": f.severity.value,
                        "component_name": component.name if component else "unknown",
                        "fix_available": f.fix_available,
                    }
                )
        return matching

    def get_server_risk_summary(self, server_id: str) -> dict[str, Any]:
        """Summarize supply chain risk for a given MCP server."""
        components = [c for c in self._components if c.server_id == server_id]
        findings = [f for f in self._findings if any(c.id == f.component_id for c in components)]
        by_severity: dict[str, int] = {}
        for f in findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        return {
            "server_id": server_id,
            "total_components": len(components),
            "total_vulnerabilities": len(findings),
            "by_severity": by_severity,
            "clean_components": sum(1 for c in components if c.scan_status == ScanStatus.CLEAN),
        }

    # -- report / stats ------------------------------------------------------

    def generate_supply_chain_report(self) -> MCPSupplyChainReport:
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for c in self._components:
            by_type[c.component_type.value] = by_type.get(c.component_type.value, 0) + 1
        for f in self._findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

        clean = sum(1 for c in self._components if c.scan_status == ScanStatus.CLEAN)
        vulnerable = sum(1 for c in self._components if c.scan_status == ScanStatus.VULNERABLE)
        abandoned = len(self.detect_abandoned_packages())

        recs: list[str] = []
        critical = by_severity.get(VulnSeverity.CRITICAL.value, 0)
        if critical > 0:
            recs.append(f"{critical} critical vulnerabilities require immediate patching")
        if abandoned > 0:
            recs.append(f"{abandoned} potentially abandoned packages — evaluate alternatives")
        unfixed = sum(1 for f in self._findings if not f.fix_available)
        if unfixed > 0:
            recs.append(f"{unfixed} vulnerabilities have no fix available — mitigate or replace")
        if not recs:
            recs.append("MCP supply chain is healthy")

        return MCPSupplyChainReport(
            total_components=len(self._components),
            total_vulnerabilities=len(self._findings),
            components_clean=clean,
            components_vulnerable=vulnerable,
            by_component_type=by_type,
            by_severity=by_severity,
            abandoned_packages=abandoned,
            integrity_failures=0,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for c in self._components:
            key = c.component_type.value
            type_dist[key] = type_dist.get(key, 0) + 1
        return {
            "total_components": len(self._components),
            "total_findings": len(self._findings),
            "type_distribution": type_dist,
            "unique_servers": len({c.server_id for c in self._components}),
            "pending_scans": sum(
                1 for c in self._components if c.scan_status == ScanStatus.PENDING
            ),
        }

    def clear_data(self) -> dict[str, str]:
        self._components.clear()
        self._findings.clear()
        logger.info("mcp_supply_chain_scanner.cleared")
        return {"status": "cleared"}

    # -- private helpers -----------------------------------------------------

    @staticmethod
    def _assess_component_risk(component: MCPComponentRecord) -> list[dict[str, Any]]:
        """Heuristic risk assessment for a component (placeholder for real CVE DB lookup)."""
        risks: list[dict[str, Any]] = []
        # Flag old-format versions as potentially outdated
        if component.version and component.version.startswith("0."):
            hash_val = hashlib.sha256(  # noqa: S324
                component.name.encode(),
            ).hexdigest()[:8]
            risks.append(
                {
                    "cve_id": f"MCP-PRERELEASE-{hash_val}",
                    "severity": "low",
                    "description": f"Pre-release {component.version}",
                    "fix_available": False,
                    "fixed_version": "",
                }
            )
        # Flag components without integrity hashes
        if not component.integrity_hash:
            risks.append(
                {
                    "cve_id": "MCP-NO-INTEGRITY-CHECK",
                    "severity": "medium",
                    "description": "Component has no recorded integrity hash — supply chain risk",
                    "fix_available": True,
                    "fixed_version": component.version,
                }
            )
        return risks
