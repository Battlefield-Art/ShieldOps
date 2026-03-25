"""Secrets Scanner Agent — Tool functions for secret detection and remediation."""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from typing import Any

import structlog

from .models import (
    ExposureLevel,
    RemediationAction,
    SecretFinding,
    SecretType,
    SeverityAssessment,
    SourceType,
)

logger = structlog.get_logger()

# Regex patterns for detecting common secret types
SECRET_PATTERNS: dict[SecretType, list[re.Pattern[str]]] = {
    SecretType.AWS_ACCESS_KEY: [
        re.compile(r"(?:^|[^A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)"),
        re.compile(
            r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
    ],
    SecretType.GCP_SERVICE_KEY: [
        re.compile(r'"type"\s*:\s*"service_account"'),
        re.compile(r"(?i)google[_\-]?api[_\-]?key\s*[:=]\s*['\"]?(AIza[A-Za-z0-9_-]{35})"),
    ],
    SecretType.AZURE_SECRET: [
        re.compile(
            r"(?i)azure[_\-]?(?:client|tenant|subscription)"
            r"[_\-]?(?:secret|id)\s*[:=]\s*['\"]?([A-Za-z0-9_\-.~]{32,})['\"]?"
        ),
    ],
    SecretType.DATABASE_URL: [
        re.compile(
            r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)"
            r"://[^\s'\"]{10,}"
        ),
    ],
    SecretType.PRIVATE_KEY: [
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ],
    SecretType.JWT_SECRET: [
        re.compile(r"(?i)jwt[_\-]?secret\s*[:=]\s*['\"]?([A-Za-z0-9_\-.]{16,})['\"]?"),
        re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    ],
    SecretType.OAUTH_TOKEN: [
        re.compile(r"(?i)oauth[_\-]?token\s*[:=]\s*['\"]?([A-Za-z0-9_\-.]{20,})['\"]?"),
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}"),
        re.compile(r"xox[bpoas]-[A-Za-z0-9\-]{10,}"),
    ],
    SecretType.WEBHOOK_SECRET: [
        re.compile(r"(?i)webhook[_\-]?secret\s*[:=]\s*['\"]?([A-Za-z0-9_\-.]{16,})['\"]?"),
        re.compile(r"whsec_[A-Za-z0-9]{32,}"),
    ],
    SecretType.API_KEY: [
        re.compile(r"(?i)api[_\-]?key\s*[:=]\s*['\"]?([A-Za-z0-9_\-.]{20,})['\"]?"),
        re.compile(r"sk-[A-Za-z0-9]{32,}"),
        re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{20,}"),
    ],
    SecretType.GENERIC_PASSWORD: [
        re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?"),
    ],
}

# Severity mapping by secret type
_SEVERITY_MAP: dict[SecretType, str] = {
    SecretType.AWS_ACCESS_KEY: "critical",
    SecretType.GCP_SERVICE_KEY: "critical",
    SecretType.AZURE_SECRET: "critical",
    SecretType.PRIVATE_KEY: "critical",
    SecretType.DATABASE_URL: "high",
    SecretType.JWT_SECRET: "high",
    SecretType.OAUTH_TOKEN: "high",
    SecretType.API_KEY: "medium",
    SecretType.WEBHOOK_SECRET: "medium",
    SecretType.GENERIC_PASSWORD: "medium",
}


def _mask_value(raw: str) -> str:
    """Mask a secret value, showing only prefix and suffix."""
    if len(raw) <= 8:
        return raw[:2] + "***"
    return raw[:4] + "***" + raw[-4:]


def _infer_source_type(target: str) -> SourceType:
    """Infer source type from the target path or identifier."""
    lower = target.lower()
    if lower.endswith((".env", ".env.local", ".env.production")):
        return SourceType.ENV_VARIABLE
    if lower.endswith((".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf")):
        return SourceType.CONFIG_FILE
    if "dockerfile" in lower or "docker-compose" in lower or ".tar" in lower:
        return SourceType.CONTAINER_IMAGE
    if ".log" in lower or "/logs/" in lower:
        return SourceType.LOG_FILE
    if ".github/" in lower or "ci" in lower or "pipeline" in lower:
        return SourceType.CI_CD_PIPELINE
    return SourceType.GIT_REPO


class SecretsScannerToolkit:
    """Tools for scanning and remediating leaked secrets."""

    def __init__(
        self,
        git_client: Any | None = None,
        vault_client: Any | None = None,
        registry_client: Any | None = None,
    ) -> None:
        self._git_client = git_client
        self._vault_client = vault_client
        self._registry_client = registry_client
        self._scan_cache: dict[str, list[SecretFinding]] = {}

    async def scan_sources(
        self,
        tenant_id: str,
        targets: list[str],
    ) -> list[SecretFinding]:
        """Scan repositories, configs, images, and logs for secret patterns."""
        logger.info(
            "secrets_scanner.scan_sources",
            tenant_id=tenant_id,
            target_count=len(targets),
        )
        findings: list[SecretFinding] = []

        for target in targets:
            source_type = _infer_source_type(target)
            content_lines = await self._read_source(target)

            for line_num, line in enumerate(content_lines, start=1):
                for secret_type, patterns in SECRET_PATTERNS.items():
                    for pattern in patterns:
                        match = pattern.search(line)
                        if match:
                            matched_text = match.group(1) if match.lastindex else match.group(0)
                            finding_id = hashlib.sha256(
                                f"{target}:{line_num}:{secret_type}".encode()
                            ).hexdigest()[:16]
                            finding = SecretFinding(
                                id=finding_id,
                                secret_type=secret_type,
                                source_type=source_type,
                                source_path=target,
                                line_number=line_num,
                                masked_value=_mask_value(matched_text),
                                exposure_level=ExposureLevel.UNKNOWN,
                                confidence=0.85,
                                is_active=False,
                                created_at=time.time(),
                                repository=self._extract_repo(target),
                                branch="main",
                            )
                            findings.append(finding)
                            break  # one match per pattern-group per line

        # Deduplicate by finding id
        seen: set[str] = set()
        deduped: list[SecretFinding] = []
        for f in findings:
            if f.id not in seen:
                seen.add(f.id)
                deduped.append(f)

        self._scan_cache[tenant_id] = deduped
        logger.info(
            "secrets_scanner.scan_sources.complete",
            finding_count=len(deduped),
        )
        return deduped

    async def classify_severity(
        self,
        findings: list[SecretFinding],
    ) -> list[SeverityAssessment]:
        """Assess severity based on secret type, exposure level, and blast radius."""
        logger.info(
            "secrets_scanner.classify_severity",
            finding_count=len(findings),
        )
        assessments: list[SeverityAssessment] = []

        for finding in findings:
            base_severity = _SEVERITY_MAP.get(finding.secret_type, "medium")

            # Elevate severity for public exposure
            if finding.exposure_level == ExposureLevel.PUBLIC:
                if base_severity == "medium":
                    base_severity = "high"
                elif base_severity == "high":
                    base_severity = "critical"

            blast_radius = self._estimate_blast_radius(finding)
            affected = self._estimate_affected_services(finding)

            assessment = SeverityAssessment(
                id=str(uuid.uuid4())[:8],
                finding_id=finding.id,
                severity=base_severity,
                blast_radius=blast_radius,
                affected_services=affected,
                data_at_risk=self._estimate_data_at_risk(finding),
                is_rotated=False,
            )
            assessments.append(assessment)

        return assessments

    async def verify_exposure(
        self,
        findings: list[SecretFinding],
    ) -> list[SecretFinding]:
        """Check if secrets are still active and publicly exposed."""
        logger.info(
            "secrets_scanner.verify_exposure",
            finding_count=len(findings),
        )
        verified: list[SecretFinding] = []

        for finding in findings:
            # Determine exposure level based on source
            exposure = self._assess_exposure(finding)

            # Check if credential is likely active (heuristic)
            is_active = await self._check_active(finding)

            updated = finding.model_copy(
                update={
                    "exposure_level": exposure,
                    "is_active": is_active,
                    "confidence": min(finding.confidence + 0.1, 1.0),
                }
            )
            verified.append(updated)

        return verified

    async def remediate_secrets(
        self,
        findings: list[SecretFinding],
        assessments: list[SeverityAssessment],
    ) -> list[RemediationAction]:
        """Rotate or revoke leaked secrets based on findings and assessments."""
        logger.info(
            "secrets_scanner.remediate_secrets",
            finding_count=len(findings),
            assessment_count=len(assessments),
        )
        assessment_map = {a.finding_id: a for a in assessments}
        actions: list[RemediationAction] = []

        for finding in findings:
            if not finding.is_active:
                continue

            assessment = assessment_map.get(finding.id)
            severity = assessment.severity if assessment else "medium"

            action = self._plan_remediation(finding, severity)
            executed = await self._execute_remediation(action)
            actions.append(executed)

        return actions

    # ----------------------------------------------------------------
    # Private helpers
    # ----------------------------------------------------------------

    async def _read_source(self, target: str) -> list[str]:
        """Read content from a source target (file, repo, image layer)."""
        if self._git_client:
            try:
                content = await self._git_client.read_file(target)
                if isinstance(content, str):
                    return content.splitlines()
                return list(content)
            except Exception:
                logger.debug("secrets_scanner.read_source.git_fallback", target=target)

        # Fallback: attempt local file read
        try:
            with open(target) as fh:
                return fh.readlines()
        except (OSError, FileNotFoundError):
            logger.debug("secrets_scanner.read_source.not_found", target=target)
            return []

    @staticmethod
    def _extract_repo(target: str) -> str:
        """Extract a repository name from a file path."""
        parts = target.replace("\\", "/").split("/")
        # Heuristic: look for common repo-level directories
        for i, part in enumerate(parts):
            if part in (".git", "src", "lib", "app"):
                return "/".join(parts[max(0, i - 1) : i]) or parts[0]
        return parts[0] if parts else "unknown"

    @staticmethod
    def _estimate_blast_radius(finding: SecretFinding) -> str:
        """Estimate blast radius of a leaked secret."""
        if finding.secret_type in (
            SecretType.AWS_ACCESS_KEY,
            SecretType.GCP_SERVICE_KEY,
            SecretType.AZURE_SECRET,
        ):
            return "cloud_account"
        if finding.secret_type == SecretType.DATABASE_URL:
            return "database"
        if finding.secret_type == SecretType.PRIVATE_KEY:
            return "infrastructure"
        return "service"

    @staticmethod
    def _estimate_affected_services(finding: SecretFinding) -> list[str]:
        """Estimate affected services from a leaked secret."""
        mapping: dict[SecretType, list[str]] = {
            SecretType.AWS_ACCESS_KEY: ["aws-iam", "aws-s3", "aws-ec2"],
            SecretType.GCP_SERVICE_KEY: ["gcp-iam", "gcp-gcs", "gcp-compute"],
            SecretType.AZURE_SECRET: ["azure-ad", "azure-storage", "azure-keyvault"],
            SecretType.DATABASE_URL: ["database", "backend-api"],
            SecretType.PRIVATE_KEY: ["ssh", "tls", "infrastructure"],
            SecretType.OAUTH_TOKEN: ["oauth-provider", "api-gateway"],
            SecretType.JWT_SECRET: ["auth-service", "api-gateway"],
        }
        return mapping.get(finding.secret_type, ["unknown-service"])

    @staticmethod
    def _estimate_data_at_risk(finding: SecretFinding) -> str:
        """Describe data at risk from the leaked secret."""
        risk_map: dict[SecretType, str] = {
            SecretType.AWS_ACCESS_KEY: "cloud resources, S3 buckets, EC2 instances",
            SecretType.GCP_SERVICE_KEY: "GCP project resources, GCS buckets",
            SecretType.AZURE_SECRET: "Azure tenant resources, Key Vault secrets",
            SecretType.DATABASE_URL: "database records, PII, application data",
            SecretType.PRIVATE_KEY: "encrypted communications, server access",
            SecretType.OAUTH_TOKEN: "user data, API access, third-party integrations",
            SecretType.JWT_SECRET: "session tokens, user impersonation",
            SecretType.API_KEY: "API access, rate limits, billing",
            SecretType.WEBHOOK_SECRET: "webhook payloads, event data",
            SecretType.GENERIC_PASSWORD: "account access, lateral movement",
        }
        return risk_map.get(finding.secret_type, "unknown data")

    @staticmethod
    def _assess_exposure(finding: SecretFinding) -> ExposureLevel:
        """Determine exposure level based on source characteristics."""
        if finding.source_type == SourceType.GIT_REPO:
            return ExposureLevel.PUBLIC
        if finding.source_type in (SourceType.CI_CD_PIPELINE, SourceType.SLACK_MESSAGE):
            return ExposureLevel.INTERNAL
        if finding.source_type == SourceType.ENV_VARIABLE:
            return ExposureLevel.RESTRICTED
        return ExposureLevel.INTERNAL

    async def _check_active(self, finding: SecretFinding) -> bool:
        """Check whether a detected credential is still active."""
        # With a vault client, verify rotation status
        if self._vault_client:
            try:
                status = await self._vault_client.check_credential(
                    finding.secret_type.value,
                    finding.masked_value,
                )
                return bool(status.get("active", True))
            except Exception:
                logger.debug("secrets_scanner.check_active.vault_error")

        # Heuristic: assume active if recently created
        age_hours = (time.time() - finding.created_at) / 3600
        return age_hours < 24 * 30  # active if less than 30 days old

    def _plan_remediation(
        self,
        finding: SecretFinding,
        severity: str,
    ) -> RemediationAction:
        """Plan a remediation action for a finding."""
        action_map: dict[SecretType, str] = {
            SecretType.AWS_ACCESS_KEY: "rotate_aws_key",
            SecretType.GCP_SERVICE_KEY: "rotate_gcp_sa_key",
            SecretType.AZURE_SECRET: "rotate_azure_secret",
            SecretType.DATABASE_URL: "rotate_db_password",
            SecretType.PRIVATE_KEY: "revoke_and_reissue_key",
            SecretType.OAUTH_TOKEN: "revoke_oauth_token",
            SecretType.JWT_SECRET: "rotate_jwt_secret",
            SecretType.API_KEY: "rotate_api_key",
            SecretType.WEBHOOK_SECRET: "rotate_webhook_secret",
            SecretType.GENERIC_PASSWORD: "force_password_reset",
        }
        action_name = action_map.get(finding.secret_type, "manual_review")
        auto = severity in ("critical", "high") and self._vault_client is not None

        return RemediationAction(
            id=str(uuid.uuid4())[:8],
            finding_id=finding.id,
            action=action_name,
            target=finding.source_path,
            description=(
                f"{action_name} for {finding.secret_type.value} "
                f"found in {finding.source_path}:{finding.line_number}"
            ),
            auto_executed=auto,
            success=False,
            rotated_credential_id="",
        )

    async def _execute_remediation(
        self,
        action: RemediationAction,
    ) -> RemediationAction:
        """Execute a planned remediation action."""
        if not action.auto_executed:
            logger.info(
                "secrets_scanner.remediation.manual_required",
                action=action.action,
                target=action.target,
            )
            return action

        if self._vault_client:
            try:
                result = await self._vault_client.rotate_credential(
                    action.action,
                    action.target,
                )
                return action.model_copy(
                    update={
                        "success": True,
                        "rotated_credential_id": result.get("new_credential_id", ""),
                    }
                )
            except Exception:
                logger.warning(
                    "secrets_scanner.remediation.failed",
                    action=action.action,
                )
                return action.model_copy(update={"success": False})

        return action
