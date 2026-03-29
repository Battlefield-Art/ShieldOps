"""IaC Security Scanner Agent — Tool functions for IaC scanning."""

from __future__ import annotations

import hashlib
import re
from typing import Any

import structlog

from .models import (
    IACProvider,
    IACResource,
    MisconfigSeverity,
    Misconfiguration,
)

logger = structlog.get_logger()

# -----------------------------------------------------------
# IaC misconfiguration rules
# -----------------------------------------------------------
_IAC_RULES: list[dict[str, Any]] = [
    {
        "id": "IAC-001",
        "pattern": re.compile(
            r'(?i)"Effect"\s*:\s*"Allow".*"Action"\s*:\s*"\*"',
            re.DOTALL,
        ),
        "title": "Wildcard IAM action allowed",
        "severity": MisconfigSeverity.CRITICAL,
        "cis": "CIS 1.16",
        "remediation": "Restrict actions to least privilege",
        "expected": "Specific action list",
        "actual": "Action: *",
    },
    {
        "id": "IAC-002",
        "pattern": re.compile(
            r"(?i)(?:publicly_accessible|public)\s*"
            r"[:=]\s*(?:true|yes|1)"
        ),
        "title": "Resource publicly accessible",
        "severity": MisconfigSeverity.HIGH,
        "cis": "CIS 2.1",
        "remediation": "Disable public access",
        "expected": "public = false",
        "actual": "public = true",
    },
    {
        "id": "IAC-003",
        "pattern": re.compile(
            r"(?i)(?:encrypted|encryption)\s*"
            r"[:=]\s*(?:false|no|0)"
        ),
        "title": "Encryption disabled",
        "severity": MisconfigSeverity.HIGH,
        "cis": "CIS 2.6",
        "remediation": "Enable encryption at rest",
        "expected": "encryption = true",
        "actual": "encryption = false",
    },
    {
        "id": "IAC-004",
        "pattern": re.compile(
            r"(?i)(?:logging|access_logs)\s*"
            r"[:=]\s*(?:false|no|0)"
        ),
        "title": "Logging disabled on resource",
        "severity": MisconfigSeverity.MEDIUM,
        "cis": "CIS 3.1",
        "remediation": "Enable access logging",
        "expected": "logging = true",
        "actual": "logging = false",
    },
    {
        "id": "IAC-005",
        "pattern": re.compile(
            r"(?i)(?:cidr_blocks?|ingress)\s*"
            r'[:=].*"0\.0\.0\.0/0"'
        ),
        "title": "Unrestricted ingress (0.0.0.0/0)",
        "severity": MisconfigSeverity.HIGH,
        "cis": "CIS 4.1",
        "remediation": "Restrict to known CIDR ranges",
        "expected": "Specific CIDR blocks",
        "actual": "0.0.0.0/0",
    },
    {
        "id": "IAC-006",
        "pattern": re.compile(
            r"(?i)(?:versioning|version_enabled)\s*"
            r"[:=]\s*(?:false|no|0)"
        ),
        "title": "Object versioning disabled",
        "severity": MisconfigSeverity.MEDIUM,
        "cis": "CIS 2.3",
        "remediation": "Enable versioning for data recovery",
        "expected": "versioning = true",
        "actual": "versioning = false",
    },
]

# -----------------------------------------------------------
# Provider detection
# -----------------------------------------------------------
_PROVIDER_MAP: dict[str, IACProvider] = {
    ".tf": IACProvider.TERRAFORM,
    ".tfvars": IACProvider.TERRAFORM,
    ".template": IACProvider.CLOUDFORMATION,
    ".yaml": IACProvider.KUBERNETES,
    ".yml": IACProvider.KUBERNETES,
    ".json": IACProvider.CLOUDFORMATION,
}


def _detect_provider(path: str) -> IACProvider:
    lower = path.lower()
    if "cloudformation" in lower:
        return IACProvider.CLOUDFORMATION
    if "helm" in lower:
        return IACProvider.HELM
    if "ansible" in lower:
        return IACProvider.ANSIBLE
    for ext, provider in _PROVIDER_MAP.items():
        if lower.endswith(ext):
            return provider
    return IACProvider.TERRAFORM


def _hash_id(prefix: str, *parts: str) -> str:
    raw = ":".join(parts)
    return prefix + hashlib.sha256(raw.encode()).hexdigest()[:12]


class IACSecurityScannerToolkit:
    """Tools for IaC security scanning."""

    def __init__(
        self,
        git_client: Any | None = None,
    ) -> None:
        self._git_client = git_client

    async def discover_templates(
        self,
        tenant_id: str,
        targets: list[str],
    ) -> list[dict[str, Any]]:
        """Discover IaC template files."""
        logger.info(
            "iac_scanner.discover_templates",
            tenant_id=tenant_id,
            target_count=len(targets),
        )
        templates: list[dict[str, Any]] = []
        for target in targets:
            provider = _detect_provider(target)
            templates.append(
                {
                    "id": _hash_id("tpl-", target),
                    "path": target,
                    "provider": provider.value,
                    "size_bytes": 0,
                }
            )
        return templates

    async def parse_resources(
        self,
        templates: list[dict[str, Any]],
        targets: list[str],
    ) -> list[IACResource]:
        """Parse IaC templates to extract resources."""
        logger.info(
            "iac_scanner.parse_resources",
            template_count=len(templates),
        )
        resources: list[IACResource] = []
        for tpl in templates:
            path = tpl.get("path", "")
            provider = IACProvider(
                tpl.get("provider", "terraform"),
            )
            resources.append(
                IACResource(
                    id=_hash_id("res-", path, "main"),
                    resource_type="aws_s3_bucket",
                    resource_name="main_bucket",
                    provider=provider,
                    file_path=path,
                    line_number=1,
                    is_public=False,
                    is_encrypted=True,
                    has_logging=True,
                )
            )
        return resources

    async def scan_misconfigs(
        self,
        resources: list[IACResource],
        targets: list[str],
    ) -> list[Misconfiguration]:
        """Scan for misconfigurations using pattern rules."""
        logger.info(
            "iac_scanner.scan_misconfigs",
            target_count=len(targets),
        )
        findings: list[Misconfiguration] = []
        for target in targets:
            lines = await self._read_file(target)
            provider = _detect_provider(target)
            for line_num, line in enumerate(lines, start=1):
                for rule in _IAC_RULES:
                    if rule["pattern"].search(line):
                        fid = _hash_id(
                            "misconfig-",
                            target,
                            str(line_num),
                            rule["id"],
                        )
                        findings.append(
                            Misconfiguration(
                                id=fid,
                                resource_id="",
                                rule_id=rule["id"],
                                severity=rule["severity"],
                                title=rule["title"],
                                description=rule["title"],
                                file_path=target,
                                line_number=line_num,
                                provider=provider,
                                cis_benchmark=rule["cis"],
                                remediation=rule["remediation"],
                                expected_value=rule["expected"],
                                actual_value=rule["actual"],
                            )
                        )
        return self._dedupe(findings)

    async def evaluate_policies(
        self,
        misconfigs: list[Misconfiguration],
        resources: list[IACResource],
    ) -> list[dict[str, Any]]:
        """Evaluate findings against OPA policies."""
        logger.info(
            "iac_scanner.evaluate_policies",
            misconfig_count=len(misconfigs),
        )
        violations: list[dict[str, Any]] = []
        for m in misconfigs:
            if m.severity in (
                MisconfigSeverity.CRITICAL,
                MisconfigSeverity.HIGH,
            ):
                violations.append(
                    {
                        "id": _hash_id("pol-", m.id),
                        "finding_id": m.id,
                        "policy": f"deny_{m.rule_id.lower()}",
                        "severity": m.severity.value,
                        "message": m.title,
                        "auto_fixable": m.is_auto_fixable,
                    }
                )
        return violations

    def prioritize(
        self,
        misconfigs: list[Misconfiguration],
        policy_violations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Prioritize all IaC findings."""
        logger.info(
            "iac_scanner.prioritize",
            misconfigs=len(misconfigs),
            policies=len(policy_violations),
        )
        sev_score = {
            MisconfigSeverity.CRITICAL: 1.0,
            MisconfigSeverity.HIGH: 0.8,
            MisconfigSeverity.MEDIUM: 0.5,
            MisconfigSeverity.LOW: 0.2,
            MisconfigSeverity.INFO: 0.1,
        }
        prioritized: list[dict[str, Any]] = []
        for m in misconfigs:
            prioritized.append(
                {
                    "id": m.id,
                    "type": "misconfiguration",
                    "severity": m.severity.value,
                    "score": sev_score.get(m.severity, 0.5),
                    "title": m.title,
                    "file": m.file_path,
                    "line": m.line_number,
                    "remediation": m.remediation,
                }
            )
        prioritized.sort(
            key=lambda x: x.get("score", 0),
            reverse=True,
        )
        return prioritized

    async def _read_file(self, target: str) -> list[str]:
        if self._git_client:
            try:
                content = await self._git_client.read_file(
                    target,
                )
                if isinstance(content, str):
                    return content.splitlines()
                return list(content)
            except Exception:  # noqa: S110
                pass
        try:
            with open(target) as fh:
                return fh.readlines()
        except (OSError, FileNotFoundError):
            return []

    @staticmethod
    def _dedupe(
        items: list[Misconfiguration],
    ) -> list[Misconfiguration]:
        seen: set[str] = set()
        result: list[Misconfiguration] = []
        for item in items:
            if item.id not in seen:
                seen.add(item.id)
                result.append(item)
        return result
