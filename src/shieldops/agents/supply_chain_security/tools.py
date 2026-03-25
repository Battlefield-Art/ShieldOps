"""Supply Chain Security Agent — Tool functions for SBOM, dependency scanning, and CI/CD audit."""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any

import structlog

from .models import (
    DependencyRisk,
    DependencyVulnerability,
    PipelineFinding,
    PipelineThreat,
    SBOMEntry,
    SignatureVerification,
)

logger = structlog.get_logger()

# Known vulnerable package patterns (simulated threat intel)
_KNOWN_VULN_PACKAGES: dict[str, list[dict[str, Any]]] = {
    "lodash": [
        {
            "cve_id": "CVE-2021-23337",
            "severity": "high",
            "cvss_score": 7.2,
            "fixed_version": "4.17.21",
            "exploitable": True,
        }
    ],
    "requests": [
        {
            "cve_id": "CVE-2023-32681",
            "severity": "medium",
            "cvss_score": 5.9,
            "fixed_version": "2.31.0",
            "exploitable": False,
        }
    ],
    "log4j-core": [
        {
            "cve_id": "CVE-2021-44228",
            "severity": "critical",
            "cvss_score": 10.0,
            "fixed_version": "2.17.1",
            "exploitable": True,
        }
    ],
}

# CI/CD threat signatures
_PIPELINE_THREAT_SIGNATURES: list[dict[str, Any]] = [
    {
        "pattern": "curl.*|.*sh",
        "threat_type": PipelineThreat.CODE_INJECTION,
        "severity": "critical",
        "description": "Remote script execution detected in pipeline",
        "remediation": "Pin scripts to verified checksums; avoid piping curl to shell",
    },
    {
        "pattern": "npm install.*--ignore-scripts",
        "threat_type": PipelineThreat.DEPENDENCY_CONFUSION,
        "severity": "high",
        "description": "npm install with --ignore-scripts may bypass security checks",
        "remediation": "Use scoped packages and configure .npmrc with registry mapping",
    },
    {
        "pattern": "uses:.*@master",
        "threat_type": PipelineThreat.COMPROMISED_ACTION,
        "severity": "high",
        "description": "GitHub Action pinned to mutable branch instead of SHA",
        "remediation": "Pin GitHub Actions to full SHA commit hashes",
    },
    {
        "pattern": "echo.*SECRET|echo.*TOKEN|echo.*PASSWORD",
        "threat_type": PipelineThreat.SECRET_EXPOSURE,
        "severity": "critical",
        "description": "Potential secret exposure in pipeline logs",
        "remediation": "Use masked environment variables; never echo secrets",
    },
]


class SupplyChainSecurityToolkit:
    """Tools for SBOM generation, dependency scanning, and CI/CD pipeline security."""

    def __init__(
        self,
        git_client: Any | None = None,
        registry_client: Any | None = None,
        ci_client: Any | None = None,
    ) -> None:
        self._git_client = git_client
        self._registry_client = registry_client
        self._ci_client = ci_client
        self._sbom_cache: dict[str, list[SBOMEntry]] = {}

    async def generate_sbom(
        self,
        tenant_id: str,
        repos: list[str] | None = None,
    ) -> list[SBOMEntry]:
        """Generate Software Bill of Materials for given repositories."""
        logger.info(
            "supply_chain.generate_sbom",
            tenant_id=tenant_id,
            repo_count=len(repos or []),
        )
        repos = repos or ["default-service"]
        entries: list[SBOMEntry] = []

        for repo in repos:
            repo_entries = await self._scan_repo_dependencies(tenant_id, repo)
            entries.extend(repo_entries)

        # Cache for later use
        self._sbom_cache[tenant_id] = entries
        return entries

    async def scan_dependencies(
        self,
        sbom: list[SBOMEntry],
    ) -> list[DependencyVulnerability]:
        """Scan SBOM entries for known vulnerabilities."""
        logger.info(
            "supply_chain.scan_dependencies",
            entry_count=len(sbom),
        )
        vulnerabilities: list[DependencyVulnerability] = []

        for entry in sbom:
            pkg_vulns = _KNOWN_VULN_PACKAGES.get(entry.package_name, [])
            for vuln in pkg_vulns:
                vulnerabilities.append(
                    DependencyVulnerability(
                        id=str(uuid.uuid4())[:8],
                        package_name=entry.package_name,
                        version=entry.version,
                        cve_id=vuln["cve_id"],
                        severity=vuln["severity"],
                        cvss_score=vuln["cvss_score"],
                        fix_available=bool(vuln.get("fixed_version")),
                        fixed_version=vuln.get("fixed_version", ""),
                        exploitable=vuln.get("exploitable", False),
                    )
                )

            # Check registry for additional advisories if client available
            if self._registry_client:
                try:
                    advisories = await self._registry_client.get_advisories(
                        entry.package_name, entry.version
                    )
                    for adv in advisories:
                        vulnerabilities.append(
                            DependencyVulnerability(
                                id=str(uuid.uuid4())[:8],
                                package_name=entry.package_name,
                                version=entry.version,
                                cve_id=adv.get("cve_id", ""),
                                severity=adv.get("severity", "medium"),
                                cvss_score=adv.get("cvss_score", 0.0),
                                fix_available=adv.get("fix_available", False),
                                fixed_version=adv.get("fixed_version", ""),
                                exploitable=adv.get("exploitable", False),
                            )
                        )
                except Exception:
                    logger.debug(
                        "supply_chain.registry_lookup_failed",
                        package=entry.package_name,
                    )

        return vulnerabilities

    async def audit_cicd_pipelines(
        self,
        tenant_id: str,
    ) -> list[PipelineFinding]:
        """Audit CI/CD pipeline configurations for security threats."""
        logger.info("supply_chain.audit_cicd", tenant_id=tenant_id)
        findings: list[PipelineFinding] = []

        # If CI client available, fetch real pipeline configs
        pipeline_configs = await self._get_pipeline_configs(tenant_id)

        for config in pipeline_configs:
            pipeline_name = config.get("name", "unknown")
            file_path = config.get("file_path", "")
            content = config.get("content", "")

            for sig in _PIPELINE_THREAT_SIGNATURES:
                if self._match_pattern(content, sig["pattern"]):
                    findings.append(
                        PipelineFinding(
                            id=str(uuid.uuid4())[:8],
                            pipeline_name=pipeline_name,
                            stage=config.get("stage", "build"),
                            threat_type=sig["threat_type"],
                            description=sig["description"],
                            severity=sig["severity"],
                            file_path=file_path,
                            remediation=sig["remediation"],
                        )
                    )

            # Check for unsigned artifact outputs
            if "docker push" in content and "cosign sign" not in content:
                findings.append(
                    PipelineFinding(
                        id=str(uuid.uuid4())[:8],
                        pipeline_name=pipeline_name,
                        stage="publish",
                        threat_type=PipelineThreat.UNSIGNED_ARTIFACT,
                        description="Container image pushed without signature",
                        severity="high",
                        file_path=file_path,
                        remediation="Sign images with cosign/sigstore before pushing",
                    )
                )

        return findings

    async def verify_signatures(
        self,
        tenant_id: str,
    ) -> list[SignatureVerification]:
        """Verify artifact signatures and trust chains."""
        logger.info("supply_chain.verify_signatures", tenant_id=tenant_id)
        verifications: list[SignatureVerification] = []

        artifacts = await self._get_artifacts(tenant_id)
        for artifact in artifacts:
            name = artifact.get("name", "unknown")
            artifact_type = artifact.get("type", "container")
            signature = artifact.get("signature")

            signed = signature is not None
            trust_valid = False
            signer = ""

            if signed and signature:
                signer = signature.get("signer", "unknown")
                trust_valid = signature.get("trust_chain_valid", False)

            verifications.append(
                SignatureVerification(
                    id=str(uuid.uuid4())[:8],
                    artifact_name=name,
                    artifact_type=artifact_type,
                    signed=signed,
                    signer=signer,
                    trust_chain_valid=trust_valid,
                    timestamp=time.time(),
                )
            )

        return verifications

    # -- internal helpers --

    async def _scan_repo_dependencies(
        self,
        tenant_id: str,
        repo: str,
    ) -> list[SBOMEntry]:
        """Scan a repository for dependencies."""
        if self._git_client:
            try:
                manifest = await self._git_client.get_dependency_manifest(tenant_id, repo)
                return [
                    SBOMEntry(
                        id=str(uuid.uuid4())[:8],
                        package_name=dep["name"],
                        version=dep["version"],
                        ecosystem=dep.get("ecosystem", "pip"),
                        license=dep.get("license", "unknown"),
                        direct=dep.get("direct", True),
                    )
                    for dep in manifest
                ]
            except Exception:
                logger.debug("supply_chain.git_scan_failed", repo=repo)

        # Simulated SBOM for when no client is available
        repo_hash = hashlib.sha256(f"{tenant_id}:{repo}".encode()).hexdigest()[:6]
        return [
            SBOMEntry(
                id=f"sbom-{repo_hash}-001",
                package_name="requests",
                version="2.28.0",
                ecosystem="pip",
                license="Apache-2.0",
                direct=True,
                risk_level=DependencyRisk.MEDIUM,
            ),
            SBOMEntry(
                id=f"sbom-{repo_hash}-002",
                package_name="lodash",
                version="4.17.19",
                ecosystem="npm",
                license="MIT",
                direct=True,
                risk_level=DependencyRisk.HIGH,
            ),
            SBOMEntry(
                id=f"sbom-{repo_hash}-003",
                package_name="fastapi",
                version="0.110.0",
                ecosystem="pip",
                license="MIT",
                direct=True,
                risk_level=DependencyRisk.SAFE,
            ),
            SBOMEntry(
                id=f"sbom-{repo_hash}-004",
                package_name="pydantic",
                version="2.6.0",
                ecosystem="pip",
                license="MIT",
                direct=False,
                risk_level=DependencyRisk.SAFE,
            ),
            SBOMEntry(
                id=f"sbom-{repo_hash}-005",
                package_name="log4j-core",
                version="2.14.0",
                ecosystem="maven",
                license="Apache-2.0",
                direct=False,
                risk_level=DependencyRisk.CRITICAL,
            ),
        ]

    async def _get_pipeline_configs(
        self,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Retrieve CI/CD pipeline configurations."""
        if self._ci_client:
            try:
                return await self._ci_client.list_pipelines(tenant_id)
            except Exception:
                logger.debug("supply_chain.ci_fetch_failed", tenant_id=tenant_id)

        # Simulated pipeline configs
        return [
            {
                "name": "build-deploy",
                "file_path": ".github/workflows/ci.yml",
                "stage": "build",
                "content": (
                    "uses: actions/checkout@master\n"
                    "run: npm install\n"
                    "run: docker push registry/app:latest\n"
                ),
            },
            {
                "name": "security-scan",
                "file_path": ".github/workflows/security.yml",
                "stage": "test",
                "content": (
                    "uses: actions/setup-node@v4\nrun: npm audit\nrun: echo $SECRET_TOKEN\n"
                ),
            },
        ]

    async def _get_artifacts(
        self,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Retrieve artifact information for signature verification."""
        if self._registry_client:
            try:
                return await self._registry_client.list_artifacts(tenant_id)
            except Exception:
                logger.debug(
                    "supply_chain.artifact_fetch_failed",
                    tenant_id=tenant_id,
                )

        # Simulated artifacts
        return [
            {
                "name": "app-service:v1.2.3",
                "type": "container",
                "signature": {
                    "signer": "ci-bot@company.com",
                    "trust_chain_valid": True,
                },
            },
            {
                "name": "worker-service:v0.9.1",
                "type": "container",
                "signature": None,
            },
            {
                "name": "shieldops-sdk-1.0.0.tar.gz",
                "type": "python_package",
                "signature": {
                    "signer": "release@shieldops.io",
                    "trust_chain_valid": True,
                },
            },
            {
                "name": "config-bundle.zip",
                "type": "archive",
                "signature": None,
            },
        ]

    @staticmethod
    def _match_pattern(content: str, pattern: str) -> bool:
        """Simple pattern matching for pipeline content scanning."""
        # Check each sub-pattern separated by |
        for sub in pattern.split("|"):
            sub = sub.strip().replace(".*", "")
            if sub and sub in content:
                return True
        return False
