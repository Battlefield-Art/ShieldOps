"""SCA Dependency Checker Agent — Tool functions for dependency analysis."""

from __future__ import annotations

import hashlib
from typing import Any

import structlog

from .models import (
    CVEMatch,
    DependencyRecord,
    DependencyRisk,
    LicenseType,
)

logger = structlog.get_logger()

# -----------------------------------------------------------
# Simulated CVE database
# -----------------------------------------------------------
_CVE_DB: list[dict[str, Any]] = [
    {
        "package": "requests",
        "affected": "<2.31.0",
        "cve": "CVE-2023-32681",
        "cvss": 6.1,
        "severity": DependencyRisk.MEDIUM,
        "desc": "Proxy-Authorization header leak",
        "fixed": "2.31.0",
        "ecosystem": "pypi",
    },
    {
        "package": "flask",
        "affected": "<2.3.2",
        "cve": "CVE-2023-30861",
        "cvss": 7.5,
        "severity": DependencyRisk.HIGH,
        "desc": "Cookie visible on redirect",
        "fixed": "2.3.2",
        "ecosystem": "pypi",
    },
    {
        "package": "lodash",
        "affected": "<4.17.21",
        "cve": "CVE-2021-23337",
        "cvss": 7.2,
        "severity": DependencyRisk.HIGH,
        "desc": "Command injection via template",
        "fixed": "4.17.21",
        "ecosystem": "npm",
    },
    {
        "package": "langchain",
        "affected": "<0.1.0",
        "cve": "CVE-2024-LC001",
        "cvss": 9.1,
        "severity": DependencyRisk.CRITICAL,
        "desc": "Arbitrary code via prompt injection",
        "fixed": "0.1.0",
        "ecosystem": "pypi",
    },
    {
        "package": "numpy",
        "affected": "<1.24.0",
        "cve": "CVE-2023-NP001",
        "cvss": 5.3,
        "severity": DependencyRisk.MEDIUM,
        "desc": "Buffer overflow in array parsing",
        "fixed": "1.24.0",
        "ecosystem": "pypi",
    },
]

# -----------------------------------------------------------
# License risk mapping
# -----------------------------------------------------------
_LICENSE_RISK: dict[LicenseType, bool] = {
    LicenseType.MIT: True,
    LicenseType.APACHE_2: True,
    LicenseType.BSD_2: True,
    LicenseType.BSD_3: True,
    LicenseType.GPL_3: False,
    LicenseType.GPL_2: False,
    LicenseType.AGPL: False,
    LicenseType.LGPL: True,
    LicenseType.MPL: True,
    LicenseType.PROPRIETARY: False,
    LicenseType.UNKNOWN: False,
}


def _hash_id(prefix: str, *parts: str) -> str:
    raw = ":".join(parts)
    return prefix + hashlib.sha256(raw.encode()).hexdigest()[:12]


class SCADependencyCheckerToolkit:
    """Tools for software composition analysis."""

    def __init__(
        self,
        registry_client: Any | None = None,
    ) -> None:
        self._registry_client = registry_client

    async def discover_manifests(
        self,
        tenant_id: str,
        targets: list[str],
    ) -> list[dict[str, Any]]:
        """Discover dependency manifest files."""
        logger.info(
            "sca_checker.discover_manifests",
            tenant_id=tenant_id,
            target_count=len(targets),
        )
        manifests: list[dict[str, Any]] = []
        manifest_names = {
            "requirements.txt",
            "pyproject.toml",
            "package.json",
            "go.mod",
            "Gemfile",
            "Cargo.toml",
            "pom.xml",
        }
        for target in targets:
            name = target.rsplit("/", 1)[-1]
            if name in manifest_names:
                manifests.append(
                    {
                        "id": _hash_id("manifest-", target),
                        "path": target,
                        "type": name,
                        "ecosystem": self._infer_ecosystem(name),
                    }
                )
        if not manifests:
            for target in targets:
                manifests.append(
                    {
                        "id": _hash_id("manifest-", target),
                        "path": target,
                        "type": "unknown",
                        "ecosystem": "pypi",
                    }
                )
        return manifests

    async def parse_dependencies(
        self,
        manifests: list[dict[str, Any]],
        targets: list[str],
    ) -> list[DependencyRecord]:
        """Parse dependencies from manifests."""
        logger.info(
            "sca_checker.parse_dependencies",
            manifest_count=len(manifests),
        )
        deps: list[DependencyRecord] = []
        # Simulated dependency parsing
        simulated = [
            ("requests", "2.28.0", "2.31.0", "pypi", LicenseType.APACHE_2),
            ("flask", "2.2.0", "2.3.3", "pypi", LicenseType.BSD_3),
            ("lodash", "4.17.19", "4.17.21", "npm", LicenseType.MIT),
            ("langchain", "0.0.300", "0.1.5", "pypi", LicenseType.MIT),
            ("numpy", "1.23.0", "1.26.0", "pypi", LicenseType.BSD_3),
            ("pydantic", "2.5.0", "2.6.0", "pypi", LicenseType.MIT),
            ("fastapi", "0.109.0", "0.110.0", "pypi", LicenseType.MIT),
        ]
        for name, ver, latest, eco, lic in simulated:
            deps.append(
                DependencyRecord(
                    id=_hash_id("dep-", name, ver),
                    package_name=name,
                    installed_version=ver,
                    latest_version=latest,
                    ecosystem=eco,
                    is_direct=True,
                    is_outdated=ver != latest,
                    license_type=lic,
                    license_compatible=_LICENSE_RISK.get(
                        lic,
                        True,
                    ),
                )
            )
        return deps

    async def match_cves(
        self,
        dependencies: list[DependencyRecord],
    ) -> list[CVEMatch]:
        """Match dependencies against CVE database."""
        logger.info(
            "sca_checker.match_cves",
            dep_count=len(dependencies),
        )
        matches: list[CVEMatch] = []
        dep_names = {d.package_name for d in dependencies}
        for entry in _CVE_DB:
            if entry["package"] in dep_names:
                matches.append(
                    CVEMatch(
                        cve_id=entry["cve"],
                        cvss_score=entry["cvss"],
                        severity=entry["severity"],
                        description=entry["desc"],
                        fixed_version=entry["fixed"],
                        exploitability="network",
                        is_exploitable=entry["cvss"] >= 7.0,
                    )
                )
        return matches

    async def check_licenses(
        self,
        dependencies: list[DependencyRecord],
    ) -> list[dict[str, Any]]:
        """Check license compatibility."""
        logger.info(
            "sca_checker.check_licenses",
            dep_count=len(dependencies),
        )
        violations: list[dict[str, Any]] = []
        for dep in dependencies:
            if not dep.license_compatible:
                violations.append(
                    {
                        "package": dep.package_name,
                        "license": dep.license_type.value,
                        "reason": (f"{dep.license_type.value} not compatible with commercial use"),
                        "severity": "high",
                    }
                )
        return violations

    def prioritize(
        self,
        cves: list[CVEMatch],
        license_violations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Prioritize all SCA findings."""
        logger.info(
            "sca_checker.prioritize",
            cves=len(cves),
            licenses=len(license_violations),
        )
        prioritized: list[dict[str, Any]] = []
        for cve in cves:
            prioritized.append(
                {
                    "id": _hash_id("p-", cve.cve_id),
                    "type": "cve",
                    "cve_id": cve.cve_id,
                    "severity": cve.severity.value,
                    "score": cve.cvss_score / 10.0,
                    "description": cve.description,
                    "fix": cve.fixed_version,
                }
            )
        for v in license_violations:
            prioritized.append(
                {
                    "id": _hash_id("p-", v["package"], "lic"),
                    "type": "license",
                    "package": v["package"],
                    "severity": v["severity"],
                    "score": 0.7,
                    "description": v["reason"],
                }
            )
        prioritized.sort(
            key=lambda x: x.get("score", 0),
            reverse=True,
        )
        return prioritized

    @staticmethod
    def _infer_ecosystem(manifest_name: str) -> str:
        mapping = {
            "requirements.txt": "pypi",
            "pyproject.toml": "pypi",
            "package.json": "npm",
            "go.mod": "go",
            "Gemfile": "rubygems",
            "Cargo.toml": "crates",
            "pom.xml": "maven",
        }
        return mapping.get(manifest_name, "unknown")
