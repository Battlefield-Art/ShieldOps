"""Container Image Scanner Agent — Tool functions for image scanning."""

from __future__ import annotations

import hashlib
from typing import Any

import structlog

from .models import (
    ComplianceStatus,
    ImageLayer,
    ImageVuln,
    LayerRisk,
)

logger = structlog.get_logger()

# -----------------------------------------------------------
# Simulated image vulnerability data
# -----------------------------------------------------------
_IMAGE_VULNS: list[dict[str, Any]] = [
    {
        "pkg": "openssl",
        "ver": "1.1.1k",
        "fixed": "1.1.1w",
        "cve": "CVE-2023-5678",
        "cvss": 7.5,
        "severity": "high",
        "desc": "Buffer overread in X.509 parsing",
        "os_pkg": True,
    },
    {
        "pkg": "curl",
        "ver": "7.88.0",
        "fixed": "8.4.0",
        "cve": "CVE-2023-46218",
        "cvss": 6.5,
        "severity": "medium",
        "desc": "Cookie injection with mixed case",
        "os_pkg": True,
    },
    {
        "pkg": "python3.12",
        "ver": "3.12.0",
        "fixed": "3.12.1",
        "cve": "CVE-2023-PY001",
        "cvss": 5.3,
        "severity": "medium",
        "desc": "tempfile race condition",
        "os_pkg": True,
    },
    {
        "pkg": "pip",
        "ver": "23.0",
        "fixed": "23.3",
        "cve": "CVE-2023-PIP01",
        "cvss": 4.2,
        "severity": "low",
        "desc": "Command injection in URL parsing",
        "os_pkg": False,
    },
]

# -----------------------------------------------------------
# Compliance checks
# -----------------------------------------------------------
_COMPLIANCE_CHECKS: list[dict[str, str]] = [
    {
        "id": "CIS-4.1",
        "title": "Ensure a user for the container is created",
        "check": "user_not_root",
    },
    {
        "id": "CIS-4.2",
        "title": "Ensure containers use trusted base images",
        "check": "trusted_base",
    },
    {
        "id": "CIS-4.6",
        "title": "Ensure HEALTHCHECK is added",
        "check": "has_healthcheck",
    },
    {
        "id": "CIS-4.9",
        "title": "Ensure unnecessary packages are removed",
        "check": "minimal_packages",
    },
    {
        "id": "CIS-4.10",
        "title": "Ensure secrets are not stored in images",
        "check": "no_secrets",
    },
]


def _hash_id(prefix: str, *parts: str) -> str:
    raw = ":".join(parts)
    return prefix + hashlib.sha256(raw.encode()).hexdigest()[:12]


class ContainerImageScannerToolkit:
    """Tools for container image security scanning."""

    def __init__(
        self,
        registry_client: Any | None = None,
    ) -> None:
        self._registry_client = registry_client

    async def discover_images(
        self,
        tenant_id: str,
        image_refs: list[str],
    ) -> list[dict[str, Any]]:
        """Discover and resolve container image references."""
        logger.info(
            "container_scanner.discover_images",
            tenant_id=tenant_id,
            image_count=len(image_refs),
        )
        images: list[dict[str, Any]] = []
        for ref in image_refs:
            images.append(
                {
                    "id": _hash_id("img-", ref),
                    "ref": ref,
                    "registry": self._extract_registry(ref),
                    "tag": self._extract_tag(ref),
                    "digest": _hash_id("sha256:", ref),
                    "size_mb": 256,
                    "os": "linux",
                    "arch": "amd64",
                }
            )
        return images

    async def analyze_layers(
        self,
        images: list[dict[str, Any]],
    ) -> list[ImageLayer]:
        """Analyze image layers for security issues."""
        logger.info(
            "container_scanner.analyze_layers",
            image_count=len(images),
        )
        layers: list[ImageLayer] = []
        for img in images:
            ref = img.get("ref", "")
            # Base image layer
            layers.append(
                ImageLayer(
                    id=_hash_id("layer-", ref, "base"),
                    digest=_hash_id("sha256:", ref, "0"),
                    size_bytes=80_000_000,
                    command="FROM ubuntu:22.04",
                    created_by="base",
                    risk=LayerRisk.LOW,
                    package_count=142,
                )
            )
            # Application layer
            layers.append(
                ImageLayer(
                    id=_hash_id("layer-", ref, "app"),
                    digest=_hash_id("sha256:", ref, "1"),
                    size_bytes=45_000_000,
                    command="COPY . /app",
                    created_by="application",
                    risk=LayerRisk.MEDIUM,
                    package_count=28,
                )
            )
            # Config layer (potential secrets)
            layers.append(
                ImageLayer(
                    id=_hash_id("layer-", ref, "config"),
                    digest=_hash_id("sha256:", ref, "2"),
                    size_bytes=1_024,
                    command="COPY config/ /etc/app/",
                    created_by="configuration",
                    risk=LayerRisk.HIGH,
                    has_secrets=True,
                )
            )
        return layers

    async def scan_vulnerabilities(
        self,
        images: list[dict[str, Any]],
        layers: list[ImageLayer],
    ) -> list[ImageVuln]:
        """Scan images for known vulnerabilities."""
        logger.info(
            "container_scanner.scan_vulns",
            image_count=len(images),
        )
        vulns: list[ImageVuln] = []
        for img in images:
            ref = img.get("ref", "")
            for v in _IMAGE_VULNS:
                vulns.append(
                    ImageVuln(
                        id=_hash_id(
                            "vuln-",
                            ref,
                            v["cve"],
                        ),
                        image_ref=ref,
                        layer_digest=_hash_id(
                            "sha256:",
                            ref,
                            "0",
                        ),
                        package_name=v["pkg"],
                        installed_version=v["ver"],
                        fixed_version=v["fixed"],
                        cve_id=v["cve"],
                        severity=v["severity"],
                        cvss_score=v["cvss"],
                        description=v["desc"],
                        is_fixable=True,
                        is_os_package=v["os_pkg"],
                        exploit_available=v["cvss"] >= 7.0,
                    )
                )
        return vulns

    async def check_compliance(
        self,
        images: list[dict[str, Any]],
        layers: list[ImageLayer],
    ) -> list[dict[str, Any]]:
        """Check images against compliance benchmarks."""
        logger.info(
            "container_scanner.check_compliance",
            image_count=len(images),
        )
        results: list[dict[str, Any]] = []
        for img in images:
            ref = img.get("ref", "")
            has_secrets = any(layer.has_secrets for layer in layers)
            for check in _COMPLIANCE_CHECKS:
                status = ComplianceStatus.PASS
                if check["check"] == "no_secrets" and has_secrets:
                    status = ComplianceStatus.FAIL
                if check["check"] == "user_not_root":
                    status = ComplianceStatus.WARNING
                results.append(
                    {
                        "id": _hash_id(
                            "comp-",
                            ref,
                            check["id"],
                        ),
                        "image_ref": ref,
                        "check_id": check["id"],
                        "title": check["title"],
                        "status": status.value,
                    }
                )
        return results

    def prioritize(
        self,
        vulns: list[ImageVuln],
        compliance: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Prioritize all container findings."""
        logger.info(
            "container_scanner.prioritize",
            vulns=len(vulns),
            compliance=len(compliance),
        )
        prioritized: list[dict[str, Any]] = []
        for v in vulns:
            prioritized.append(
                {
                    "id": v.id,
                    "type": "vulnerability",
                    "severity": v.severity,
                    "score": v.cvss_score / 10.0,
                    "title": f"{v.package_name} {v.cve_id}",
                    "description": v.description,
                    "fixable": v.is_fixable,
                }
            )
        for c in compliance:
            if c["status"] == "fail":
                prioritized.append(
                    {
                        "id": c["id"],
                        "type": "compliance",
                        "severity": "high",
                        "score": 0.8,
                        "title": c["title"],
                        "description": c["title"],
                    }
                )
        prioritized.sort(
            key=lambda x: x.get("score", 0),
            reverse=True,
        )
        return prioritized

    @staticmethod
    def _extract_registry(ref: str) -> str:
        parts = ref.split("/")
        if len(parts) >= 2 and "." in parts[0]:
            return parts[0]
        return "docker.io"

    @staticmethod
    def _extract_tag(ref: str) -> str:
        if ":" in ref:
            return ref.rsplit(":", 1)[-1]
        return "latest"
