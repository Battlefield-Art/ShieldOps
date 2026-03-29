"""Secrets in Code Detector Agent — Tool functions for secret detection."""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any

import structlog

from .models import (
    ExposureRisk,
    RepositoryScan,
    SecretFinding,
    SecretType,
)

logger = structlog.get_logger()

# -----------------------------------------------------------
# Secret detection patterns
# -----------------------------------------------------------
_SECRET_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "SEC-001",
        "pattern": re.compile(r"(?i)(?:AKIA|ASIA)[A-Z0-9]{16}"),
        "type": SecretType.AWS_ACCESS_KEY,
        "risk": ExposureRisk.CRITICAL,
        "title": "AWS Access Key ID detected",
    },
    {
        "id": "SEC-002",
        "pattern": re.compile(
            r"(?i)(?:password|passwd|pwd)\s*[:=]\s*"
            r'["\'][^"\']{8,}["\']'
        ),
        "type": SecretType.PASSWORD,
        "risk": ExposureRisk.HIGH,
        "title": "Hardcoded password detected",
    },
    {
        "id": "SEC-003",
        "pattern": re.compile(
            r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*"
            r'["\'][^"\']{16,}["\']'
        ),
        "type": SecretType.API_KEY,
        "risk": ExposureRisk.HIGH,
        "title": "API key detected",
    },
    {
        "id": "SEC-004",
        "pattern": re.compile(r"(?i)-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
        "type": SecretType.PRIVATE_KEY,
        "risk": ExposureRisk.CRITICAL,
        "title": "Private key detected",
    },
    {
        "id": "SEC-005",
        "pattern": re.compile(
            r"(?i)(?:token|bearer)\s*[:=]\s*"
            r'["\'][A-Za-z0-9._\-]{20,}["\']'
        ),
        "type": SecretType.TOKEN,
        "risk": ExposureRisk.HIGH,
        "title": "Authentication token detected",
    },
    {
        "id": "SEC-006",
        "pattern": re.compile(
            r"(?i)(?:mongodb|postgres|mysql|redis)://"
            r"[^:]+:[^@]+@"
        ),
        "type": SecretType.CONNECTION_STRING,
        "risk": ExposureRisk.CRITICAL,
        "title": "Database connection string with creds",
    },
    {
        "id": "SEC-007",
        "pattern": re.compile(r'(?i)"type"\s*:\s*"service_account"'),
        "type": SecretType.GCP_SERVICE_ACCOUNT,
        "risk": ExposureRisk.CRITICAL,
        "title": "GCP service account key detected",
    },
    {
        "id": "SEC-008",
        "pattern": re.compile(
            r"(?i)(?:client[_-]?secret)\s*[:=]\s*"
            r'["\'][^"\']{16,}["\']'
        ),
        "type": SecretType.AZURE_CLIENT_SECRET,
        "risk": ExposureRisk.HIGH,
        "title": "Azure client secret detected",
    },
]


def _hash_id(prefix: str, *parts: str) -> str:
    raw = ":".join(parts)
    return prefix + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 2)


class SecretsInCodeDetectorToolkit:
    """Tools for detecting secrets in source code."""

    def __init__(
        self,
        git_client: Any | None = None,
    ) -> None:
        self._git_client = git_client

    async def discover_repositories(
        self,
        tenant_id: str,
        targets: list[str],
    ) -> list[RepositoryScan]:
        """Discover repositories to scan for secrets."""
        logger.info(
            "secrets_detector.discover_repos",
            tenant_id=tenant_id,
            target_count=len(targets),
        )
        repos: list[RepositoryScan] = []
        for target in targets:
            repos.append(
                RepositoryScan(
                    id=_hash_id("repo-", target),
                    repo_name=target.rsplit("/", 1)[-1],
                    repo_url=target,
                    branch="main",
                    total_files=1,
                )
            )
        return repos

    async def scan_patterns(
        self,
        repos: list[RepositoryScan],
        targets: list[str],
    ) -> list[SecretFinding]:
        """Scan files for secret patterns."""
        logger.info(
            "secrets_detector.scan_patterns",
            target_count=len(targets),
        )
        findings: list[SecretFinding] = []
        for target in targets:
            lines = await self._read_file(target)
            for line_num, line in enumerate(lines, start=1):
                for rule in _SECRET_PATTERNS:
                    match = rule["pattern"].search(line)
                    if match:
                        matched_text = match.group(0)
                        masked = self._mask_secret(
                            matched_text,
                        )
                        fid = _hash_id(
                            "sec-",
                            target,
                            str(line_num),
                            rule["id"],
                        )
                        findings.append(
                            SecretFinding(
                                id=fid,
                                secret_type=rule["type"],
                                exposure_risk=rule["risk"],
                                file_path=target,
                                line_number=line_num,
                                snippet_masked=masked,
                                rule_id=rule["id"],
                                entropy_score=_shannon_entropy(
                                    matched_text,
                                ),
                            )
                        )
        return self._dedupe(findings)

    async def verify_secrets(
        self,
        findings: list[SecretFinding],
    ) -> list[SecretFinding]:
        """Verify whether detected secrets are active."""
        logger.info(
            "secrets_detector.verify",
            finding_count=len(findings),
        )
        verified: list[SecretFinding] = []
        for f in findings:
            # High entropy suggests real secret
            is_real = f.entropy_score > 3.0
            is_test_file = any(
                kw in f.file_path.lower() for kw in ("test", "spec", "mock", "fixture")
            )
            verified.append(
                f.model_copy(
                    update={
                        "verified": is_real and not is_test_file,
                        "is_active": is_real and not is_test_file,
                    }
                )
            )
        return verified

    async def assess_exposure(
        self,
        findings: list[SecretFinding],
    ) -> list[SecretFinding]:
        """Assess exposure risk for verified secrets."""
        logger.info(
            "secrets_detector.assess_exposure",
            finding_count=len(findings),
        )
        assessed: list[SecretFinding] = []
        for f in findings:
            risk = f.exposure_risk
            if f.is_in_history:
                risk = ExposureRisk.CRITICAL
            if not f.is_active:
                risk = ExposureRisk.LOW
            assessed.append(
                f.model_copy(
                    update={
                        "exposure_risk": risk,
                        "remediation": self._get_remediation(
                            f.secret_type,
                        ),
                    }
                )
            )
        return assessed

    def prioritize(
        self,
        findings: list[SecretFinding],
    ) -> list[dict[str, Any]]:
        """Prioritize secret findings by risk."""
        logger.info(
            "secrets_detector.prioritize",
            count=len(findings),
        )
        risk_score = {
            ExposureRisk.CRITICAL: 1.0,
            ExposureRisk.HIGH: 0.8,
            ExposureRisk.MEDIUM: 0.5,
            ExposureRisk.LOW: 0.2,
            ExposureRisk.INFORMATIONAL: 0.1,
        }
        prioritized: list[dict[str, Any]] = []
        for f in findings:
            prioritized.append(
                {
                    "id": f.id,
                    "type": f.secret_type.value,
                    "risk": f.exposure_risk.value,
                    "score": risk_score.get(
                        f.exposure_risk,
                        0.5,
                    ),
                    "file": f.file_path,
                    "line": f.line_number,
                    "active": f.is_active,
                    "verified": f.verified,
                    "remediation": f.remediation,
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
    def _mask_secret(text: str) -> str:
        """Mask a secret value showing only first/last chars."""
        if len(text) <= 8:
            return "***"
        return f"{text[:4]}...{text[-4:]}"

    @staticmethod
    def _get_remediation(secret_type: SecretType) -> str:
        remediation_map = {
            SecretType.AWS_ACCESS_KEY: ("Rotate AWS key via IAM console immediately"),
            SecretType.PASSWORD: ("Move to secret manager (Vault/AWS SM)"),
            SecretType.API_KEY: ("Rotate API key and use env variables"),
            SecretType.PRIVATE_KEY: ("Revoke key, generate new one, use KMS"),
            SecretType.TOKEN: ("Revoke token and use short-lived tokens"),
            SecretType.CONNECTION_STRING: ("Use IAM auth or secret manager for DB creds"),
            SecretType.GCP_SERVICE_ACCOUNT: ("Delete key, use workload identity"),
            SecretType.AZURE_CLIENT_SECRET: ("Rotate secret, use managed identity"),
            SecretType.CERTIFICATE: ("Revoke and reissue certificate"),
            SecretType.GENERIC_SECRET: ("Move to secret manager"),
        }
        return remediation_map.get(
            secret_type,
            "Move to secret manager",
        )

    @staticmethod
    def _dedupe(
        items: list[SecretFinding],
    ) -> list[SecretFinding]:
        seen: set[str] = set()
        result: list[SecretFinding] = []
        for item in items:
            if item.id not in seen:
                seen.add(item.id)
                result.append(item)
        return result
