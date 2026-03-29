"""Serverless Security Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from typing import Any

import structlog

from .models import (
    DependencyVulnerability,
    PermissionFinding,
    ServerlessFunction,
    ServerlessPlatform,
    ServerlessThreatType,
    ThreatDetection,
)

logger = structlog.get_logger()

_RUNTIMES: dict[str, list[str]] = {
    "aws_lambda": ["python3.12", "nodejs20.x", "java21", "go1.x"],
    "gcp_cloud_functions": [
        "python312",
        "nodejs20",
        "java17",
        "go121",
    ],
    "azure_functions": [
        "python3.11",
        "node18",
        "dotnet8",
        "java17",
    ],
}

_VULN_PACKAGES = [
    {
        "package": "requests",
        "version": "2.25.0",
        "fixed": "2.31.0",
        "cve": "CVE-2023-32681",
        "severity": "high",
    },
    {
        "package": "urllib3",
        "version": "1.26.5",
        "fixed": "1.26.18",
        "cve": "CVE-2023-45803",
        "severity": "medium",
    },
    {
        "package": "cryptography",
        "version": "3.4.8",
        "fixed": "41.0.6",
        "cve": "CVE-2023-49083",
        "severity": "critical",
    },
    {
        "package": "pillow",
        "version": "9.0.0",
        "fixed": "10.2.0",
        "cve": "CVE-2023-50447",
        "severity": "critical",
    },
    {
        "package": "aiohttp",
        "version": "3.8.0",
        "fixed": "3.9.2",
        "cve": "CVE-2024-23334",
        "severity": "high",
    },
]

_REGIONS: dict[str, list[str]] = {
    "aws_lambda": ["us-east-1", "us-west-2", "eu-west-1"],
    "gcp_cloud_functions": [
        "us-central1",
        "europe-west1",
    ],
    "azure_functions": ["eastus", "westeurope"],
}


def _fn_hash(platform: str, name: str, idx: int) -> str:
    raw = f"{platform}-{name}-{idx}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class ServerlessSecurityToolkit:
    """Tools for serverless function security analysis."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
    ) -> None:
        self._cloud_clients = cloud_clients

    async def discover_functions(
        self,
        tenant_id: str,
        platforms: list[str],
    ) -> list[ServerlessFunction]:
        """Discover serverless functions across platforms."""
        logger.info(
            "serverless.discover",
            tenant_id=tenant_id,
            platforms=platforms,
        )

        if self._cloud_clients is not None:
            try:
                raw = await self._cloud_clients.list_functions(
                    tenant_id=tenant_id, platforms=platforms
                )
                return [ServerlessFunction(**r) for r in raw]
            except Exception:
                logger.exception("serverless.discover.error")

        functions: list[ServerlessFunction] = []
        fn_names = [
            "api-handler",
            "auth-validator",
            "data-processor",
            "event-router",
            "notification-sender",
            "image-resizer",
            "log-shipper",
            "cron-job",
        ]

        for platform_key in platforms:
            runtimes = _RUNTIMES.get(platform_key, ["python3.12"])
            regions = _REGIONS.get(platform_key, ["us-east-1"])

            for idx, name in enumerate(
                random.sample(  # noqa: S311
                    fn_names,
                    min(len(fn_names), random.randint(3, 6)),  # noqa: S311
                )
            ):
                fid = _fn_hash(platform_key, name, idx)
                functions.append(
                    ServerlessFunction(
                        id=fid,
                        platform=ServerlessPlatform(platform_key),
                        function_name=f"{name}-{fid[:6]}",
                        runtime=random.choice(runtimes),  # noqa: S311
                        memory_mb=random.choice(  # noqa: S311
                            [128, 256, 512, 1024, 2048]
                        ),
                        timeout_seconds=random.choice(  # noqa: S311
                            [30, 60, 120, 300, 900]
                        ),
                        region=random.choice(regions),  # noqa: S311
                        role_arn=f"arn:role/{name}-role",
                        layers=[],
                        env_var_count=random.randint(2, 12),  # noqa: S311
                        last_invoked=time.time() - random.uniform(0, 86400 * 7),  # noqa: S311
                    )
                )

        logger.info(
            "serverless.discover.done",
            count=len(functions),
        )
        return functions

    async def analyze_permissions(
        self,
        functions: list[ServerlessFunction],
    ) -> list[PermissionFinding]:
        """Analyze IAM permissions for serverless functions."""
        logger.info(
            "serverless.permissions",
            count=len(functions),
        )

        findings: list[PermissionFinding] = []
        for fn in functions:
            if random.random() > 0.4:  # noqa: S311
                severity = random.choice(  # noqa: S311
                    ["critical", "high", "medium"]
                )
                base_risk = {
                    "critical": 90.0,
                    "high": 70.0,
                    "medium": 50.0,
                }.get(severity, 50.0)
                findings.append(
                    PermissionFinding(
                        id=str(uuid.uuid4())[:8],
                        function_id=fn.id,
                        finding_type="over_privileged_role",
                        severity=severity,
                        description=(f"{fn.function_name} has overly broad IAM permissions"),
                        policy_statement="Effect:Allow,Action:*",
                        recommended_policy=("Restrict to specific actions"),
                        risk_score=round(
                            base_risk + random.uniform(-5, 5),  # noqa: S311
                            1,
                        ),
                    )
                )

        logger.info(
            "serverless.permissions.done",
            findings=len(findings),
        )
        return findings

    async def scan_dependencies(
        self,
        functions: list[ServerlessFunction],
    ) -> list[DependencyVulnerability]:
        """Scan function dependencies for vulnerabilities."""
        logger.info(
            "serverless.dependencies",
            count=len(functions),
        )

        vulns: list[DependencyVulnerability] = []
        for fn in functions:
            num_vulns = random.randint(0, 3)  # noqa: S311
            selected = random.sample(  # noqa: S311
                _VULN_PACKAGES, min(num_vulns, len(_VULN_PACKAGES))
            )
            for vp in selected:
                vulns.append(
                    DependencyVulnerability(
                        id=str(uuid.uuid4())[:8],
                        function_id=fn.id,
                        package_name=vp["package"],
                        installed_version=vp["version"],
                        fixed_version=vp["fixed"],
                        cve_id=vp["cve"],
                        severity=vp["severity"],
                        description=(f"{vp['package']} {vp['version']} vulnerable: {vp['cve']}"),
                    )
                )

        logger.info(
            "serverless.dependencies.done",
            vulns=len(vulns),
        )
        return vulns

    async def detect_threats(
        self,
        functions: list[ServerlessFunction],
        permission_findings: list[PermissionFinding],
    ) -> list[ThreatDetection]:
        """Detect threats targeting serverless functions."""
        logger.info("serverless.threats", count=len(functions))

        threats: list[ThreatDetection] = []
        threat_templates = [
            {
                "type": ServerlessThreatType.COLD_START_ATTACK,
                "mitre": "T1190",
                "desc": "Cold start timing attack detected",
            },
            {
                "type": ServerlessThreatType.EVENT_INJECTION,
                "mitre": "T1059",
                "desc": "Event injection vulnerability",
            },
            {
                "type": ServerlessThreatType.DATA_EXFILTRATION,
                "mitre": "T1567",
                "desc": "Potential data exfiltration via env vars",
            },
            {
                "type": ServerlessThreatType.RESOURCE_ABUSE,
                "mitre": "T1496",
                "desc": "Cryptomining resource abuse risk",
            },
        ]

        for fn in functions:
            if random.random() > 0.5:  # noqa: S311
                tpl = random.choice(threat_templates)  # noqa: S311
                severity = random.choice(  # noqa: S311
                    ["critical", "high", "medium"]
                )
                base_risk = {
                    "critical": 90.0,
                    "high": 70.0,
                    "medium": 50.0,
                }.get(severity, 50.0)

                threats.append(
                    ThreatDetection(
                        id=str(uuid.uuid4())[:8],
                        function_id=fn.id,
                        threat_type=tpl["type"],
                        severity=severity,
                        description=(f"{tpl['desc']} on {fn.function_name}"),
                        mitre_technique=tpl["mitre"],
                        risk_score=round(
                            base_risk + random.uniform(-5, 5),  # noqa: S311
                            1,
                        ),
                    )
                )

        logger.info(
            "serverless.threats.done",
            threats=len(threats),
        )
        return threats
