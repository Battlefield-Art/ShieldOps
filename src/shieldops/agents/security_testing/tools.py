"""Automated Security Testing Agent — Tool functions for security assessment."""

from __future__ import annotations

import hashlib
import random
import time
from typing import Any

import structlog

from .models import (
    FindingSeverity,
    SecurityFinding,
    TestCategory,
    TestReport,
    TestScope,
)

logger = structlog.get_logger()

# Common CVEs by category for mock scanning
_MOCK_CVES: dict[TestCategory, list[dict[str, Any]]] = {
    TestCategory.VULNERABILITY: [
        {
            "cve_id": "CVE-2024-3094",
            "title": "XZ Utils Backdoor",
            "severity": FindingSeverity.CRITICAL,
            "remediation": "Upgrade xz-utils to version 5.6.1+",
            "risk_score": 95,
        },
        {
            "cve_id": "CVE-2024-21762",
            "title": "FortiOS Out-of-Bound Write",
            "severity": FindingSeverity.CRITICAL,
            "remediation": "Upgrade FortiOS to patched version",
            "risk_score": 90,
        },
        {
            "cve_id": "CVE-2023-44487",
            "title": "HTTP/2 Rapid Reset DDoS",
            "severity": FindingSeverity.HIGH,
            "remediation": "Apply vendor patches for HTTP/2 implementation",
            "risk_score": 75,
        },
    ],
    TestCategory.CONFIGURATION: [
        {
            "cve_id": "",
            "title": "SSH Root Login Enabled",
            "severity": FindingSeverity.HIGH,
            "remediation": "Set PermitRootLogin to no in sshd_config",
            "risk_score": 70,
        },
        {
            "cve_id": "",
            "title": "TLS 1.0/1.1 Still Enabled",
            "severity": FindingSeverity.MEDIUM,
            "remediation": "Disable TLS 1.0 and 1.1, enforce TLS 1.2+",
            "risk_score": 55,
        },
        {
            "cve_id": "",
            "title": "Directory Listing Enabled on Web Server",
            "severity": FindingSeverity.LOW,
            "remediation": "Disable directory listing in web server config",
            "risk_score": 25,
        },
    ],
    TestCategory.NETWORK: [
        {
            "cve_id": "",
            "title": "Unrestricted Outbound Access from DB Subnet",
            "severity": FindingSeverity.HIGH,
            "remediation": "Restrict egress rules to required destinations only",
            "risk_score": 80,
        },
        {
            "cve_id": "",
            "title": "Flat Network — No Segmentation Between Prod and Dev",
            "severity": FindingSeverity.CRITICAL,
            "remediation": "Implement VLAN segmentation and firewall rules",
            "risk_score": 85,
        },
    ],
    TestCategory.CREDENTIAL: [
        {
            "cve_id": "",
            "title": "Service Account With Stale Password (>90 days)",
            "severity": FindingSeverity.HIGH,
            "remediation": "Rotate service account credentials every 90 days",
            "risk_score": 70,
        },
        {
            "cve_id": "",
            "title": "API Key Exposed in Environment Variable Logs",
            "severity": FindingSeverity.CRITICAL,
            "remediation": "Use secret manager; redact secrets from log output",
            "risk_score": 90,
        },
        {
            "cve_id": "",
            "title": "Weak Password Policy — Minimum Length 6 Characters",
            "severity": FindingSeverity.MEDIUM,
            "remediation": "Enforce minimum 12-character passwords with complexity",
            "risk_score": 50,
        },
    ],
    TestCategory.COMPLIANCE: [
        {
            "cve_id": "",
            "title": "Encryption at Rest Not Enabled on S3 Bucket",
            "severity": FindingSeverity.HIGH,
            "remediation": "Enable SSE-S3 or SSE-KMS on all S3 buckets",
            "risk_score": 65,
        },
        {
            "cve_id": "",
            "title": "CloudTrail Logging Disabled in us-west-2",
            "severity": FindingSeverity.CRITICAL,
            "remediation": "Enable CloudTrail in all regions with log validation",
            "risk_score": 85,
        },
    ],
}

# CIS benchmark checks for config audit
_CIS_CHECKS: list[dict[str, str]] = [
    {"id": "CIS-1.1", "name": "Ensure MFA is enabled for root account"},
    {"id": "CIS-1.4", "name": "Ensure access keys are rotated every 90 days"},
    {"id": "CIS-2.1", "name": "Ensure CloudTrail is enabled in all regions"},
    {"id": "CIS-3.1", "name": "Ensure log metric filter exists for unauthorized API calls"},
    {"id": "CIS-4.1", "name": "Ensure no security groups allow 0.0.0.0/0 ingress to port 22"},
    {"id": "CIS-5.1", "name": "Ensure VPC flow logging is enabled"},
]


class SecurityTestingToolkit:
    """Tools for automated security testing workflows."""

    def __init__(
        self,
        scanner_client: Any | None = None,
        config_client: Any | None = None,
        credential_store: Any | None = None,
    ) -> None:
        self._scanner_client = scanner_client
        self._config_client = config_client
        self._credential_store = credential_store

    async def define_scope(
        self,
        targets: list[str],
        categories: list[TestCategory],
        exclusions: list[str] | None = None,
    ) -> TestScope:
        """Define the scope of a security testing engagement.

        Validates targets, resolves category defaults, and applies exclusions.
        """
        logger.info(
            "security_testing.define_scope",
            target_count=len(targets),
            categories=[c.value for c in categories],
        )

        resolved_categories = categories if categories else list(TestCategory)
        resolved_exclusions = exclusions if exclusions else []

        return TestScope(
            targets=targets,
            categories=resolved_categories,
            exclusions=resolved_exclusions,
        )

    async def run_vulnerability_scan(self, target: str) -> list[SecurityFinding]:
        """Scan a target for known CVEs and software vulnerabilities.

        Uses the scanner client if available, otherwise returns mock findings.
        """
        logger.info("security_testing.run_vulnerability_scan", target=target)

        if self._scanner_client is not None:
            try:
                raw = await self._scanner_client.scan(target=target)
                return [SecurityFinding(**r) for r in raw]
            except Exception:
                logger.exception("security_testing.run_vulnerability_scan.error")

        # Mock fallback — select random subset of vulnerability findings
        findings: list[SecurityFinding] = []
        vuln_pool = _MOCK_CVES[TestCategory.VULNERABILITY]
        selected = random.sample(vuln_pool, k=min(len(vuln_pool), random.randint(1, 3)))

        for vuln in selected:
            finding_id = hashlib.sha256(
                f"{target}:{vuln['title']}:{time.time()}".encode()
            ).hexdigest()[:12]
            findings.append(
                SecurityFinding(
                    finding_id=finding_id,
                    category=TestCategory.VULNERABILITY,
                    severity=vuln["severity"],
                    title=vuln["title"],
                    description=f"Detected {vuln['title']} on {target}",
                    affected_resource=target,
                    remediation=vuln["remediation"],
                    risk_score=vuln["risk_score"],
                    cve_id=vuln["cve_id"],
                )
            )
        return findings

    async def run_config_audit(self, target: str) -> list[SecurityFinding]:
        """Audit target configuration against CIS benchmarks.

        Checks security hardening, service configuration, and compliance posture.
        """
        logger.info("security_testing.run_config_audit", target=target)

        if self._config_client is not None:
            try:
                raw = await self._config_client.audit(target=target)
                return [SecurityFinding(**r) for r in raw]
            except Exception:
                logger.exception("security_testing.run_config_audit.error")

        # Mock fallback — select config and compliance findings
        findings: list[SecurityFinding] = []
        config_pool = _MOCK_CVES[TestCategory.CONFIGURATION]
        selected = random.sample(config_pool, k=min(len(config_pool), random.randint(1, 3)))

        for item in selected:
            finding_id = hashlib.sha256(
                f"{target}:config:{item['title']}:{time.time()}".encode()
            ).hexdigest()[:12]
            findings.append(
                SecurityFinding(
                    finding_id=finding_id,
                    category=TestCategory.CONFIGURATION,
                    severity=item["severity"],
                    title=item["title"],
                    description=f"Configuration issue on {target}: {item['title']}",
                    affected_resource=target,
                    remediation=item["remediation"],
                    risk_score=item["risk_score"],
                    cve_id=item.get("cve_id", ""),
                )
            )
        return findings

    async def run_credential_check(self, target: str) -> list[SecurityFinding]:
        """Check credential hygiene for a target.

        Validates password policies, key rotation, secret exposure, and MFA status.
        """
        logger.info("security_testing.run_credential_check", target=target)

        if self._credential_store is not None:
            try:
                raw = await self._credential_store.check(target=target)
                return [SecurityFinding(**r) for r in raw]
            except Exception:
                logger.exception("security_testing.run_credential_check.error")

        # Mock fallback
        findings: list[SecurityFinding] = []
        cred_pool = _MOCK_CVES[TestCategory.CREDENTIAL]
        selected = random.sample(cred_pool, k=min(len(cred_pool), random.randint(1, 2)))

        for item in selected:
            finding_id = hashlib.sha256(
                f"{target}:cred:{item['title']}:{time.time()}".encode()
            ).hexdigest()[:12]
            findings.append(
                SecurityFinding(
                    finding_id=finding_id,
                    category=TestCategory.CREDENTIAL,
                    severity=item["severity"],
                    title=item["title"],
                    description=f"Credential issue on {target}: {item['title']}",
                    affected_resource=target,
                    remediation=item["remediation"],
                    risk_score=item["risk_score"],
                    cve_id="",
                )
            )
        return findings

    async def generate_report(
        self,
        findings: list[SecurityFinding],
        scope: TestScope,
    ) -> TestReport:
        """Generate a prioritized security testing report.

        Aggregates findings, calculates risk scores using RBA methodology,
        and produces summary statistics.
        """
        logger.info(
            "security_testing.generate_report",
            finding_count=len(findings),
        )

        # Sort findings by risk score descending (RBA prioritization)
        sorted_findings = sorted(findings, key=lambda f: f.risk_score, reverse=True)

        critical_count = sum(1 for f in sorted_findings if f.severity == FindingSeverity.CRITICAL)
        high_count = sum(1 for f in sorted_findings if f.severity == FindingSeverity.HIGH)
        risk_score_total = sum(f.risk_score for f in sorted_findings)

        # Pass rate: percentage of targets with no critical/high findings
        targets_with_issues = {
            f.affected_resource
            for f in sorted_findings
            if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
        }
        total_targets = len(scope.targets) if scope.targets else 1
        pass_rate = round(1.0 - (len(targets_with_issues) / total_targets), 4)
        pass_rate = max(pass_rate, 0.0)

        return TestReport(
            scope=scope,
            findings=sorted_findings,
            critical_count=critical_count,
            high_count=high_count,
            risk_score_total=risk_score_total,
            pass_rate=pass_rate,
        )
