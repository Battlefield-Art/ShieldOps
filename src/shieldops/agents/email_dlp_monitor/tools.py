"""Email DLP Monitor Agent — Tool functions."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

import structlog

from .models import (
    DLPViolation,
    EmailScan,
    PolicyAction,
    SensitiveDataType,
)

logger = structlog.get_logger()

# PII detection patterns
PII_PATTERNS: dict[SensitiveDataType, re.Pattern[str]] = {
    SensitiveDataType.SSN: re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    SensitiveDataType.CREDIT_CARD: re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    SensitiveDataType.PHONE_NUMBER: re.compile(
        r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}"
        r"[-.\s]?\d{4}\b"
    ),
    SensitiveDataType.EMAIL_ADDRESS: re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+"
        r"\.[a-zA-Z]{2,}\b"
    ),
    SensitiveDataType.API_KEY: re.compile(r"\b(?:AKIA|sk-|ghp_|glpat-)[A-Za-z0-9]{16,}\b"),
}

# Sensitive file extensions
SENSITIVE_EXTENSIONS = {
    ".csv",
    ".xlsx",
    ".xls",
    ".pdf",
    ".docx",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".sql",
    ".bak",
    ".dump",
}

# Internal domain patterns
INTERNAL_DOMAINS = {"company.com", "corp.internal"}

# DLP policy rules
DLP_POLICIES: list[dict[str, Any]] = [
    {
        "name": "block_ssn_external",
        "data_type": SensitiveDataType.SSN,
        "external_only": True,
        "action": PolicyAction.BLOCK,
        "severity": "critical",
    },
    {
        "name": "block_credit_card",
        "data_type": SensitiveDataType.CREDIT_CARD,
        "external_only": False,
        "action": PolicyAction.BLOCK,
        "severity": "critical",
    },
    {
        "name": "warn_api_key",
        "data_type": SensitiveDataType.API_KEY,
        "external_only": False,
        "action": PolicyAction.BLOCK,
        "severity": "high",
    },
    {
        "name": "encrypt_pii_external",
        "data_type": SensitiveDataType.PII_GENERIC,
        "external_only": True,
        "action": PolicyAction.ENCRYPT,
        "severity": "medium",
    },
]


def _gen_id() -> str:
    return str(uuid.uuid4())[:12]


class EmailDLPMonitorToolkit:
    """Tools for email DLP monitoring."""

    def __init__(
        self,
        dlp_client: Any | None = None,
        policy_client: Any | None = None,
    ) -> None:
        self._dlp = dlp_client
        self._policy = policy_client

    async def scan_outbound(
        self,
        tenant_id: str,
        emails: list[dict[str, Any]] | None = None,
    ) -> list[EmailScan]:
        """Scan outbound emails for sensitive data."""
        logger.info(
            "email_dlp.scan_outbound",
            tenant_id=tenant_id,
        )
        emails = emails or self._sample_emails()
        scans: list[EmailScan] = []

        for email_data in emails:
            recipients = email_data.get("to", [])
            if isinstance(recipients, str):
                recipients = [recipients]

            external = sum(
                1 for r in recipients if not any(d in r.lower() for d in INTERNAL_DOMAINS)
            )

            scan = EmailScan(
                id=_gen_id(),
                sender=email_data.get("from", ""),
                recipients=recipients,
                subject=email_data.get("subject", ""),
                body_preview=email_data.get("body", "")[:500],
                has_attachments=bool(email_data.get("attachments")),
                attachment_names=[a.get("name", "") for a in email_data.get("attachments", [])],
                external_recipients=external,
                scanned_at=time.time(),
            )
            scans.append(scan)

        return scans

    async def detect_pii(
        self,
        scans: list[EmailScan],
    ) -> tuple[list[dict[str, Any]], int]:
        """Detect PII in email content."""
        logger.info(
            "email_dlp.detect_pii",
            scan_count=len(scans),
        )
        detections: list[dict[str, Any]] = []

        for scan in scans:
            text = f"{scan.subject} {scan.body_preview}"

            for data_type, pattern in PII_PATTERNS.items():
                matches = pattern.findall(text)
                for match in matches:
                    # Redact for logging
                    redacted = match[:4] + "***"
                    detections.append(
                        {
                            "email_id": scan.id,
                            "sender": scan.sender,
                            "data_type": data_type.value,
                            "location": "body",
                            "snippet": redacted,
                            "external": scan.external_recipients > 0,
                            "detected_at": time.time(),
                        }
                    )
                    scan.sensitive_data_found = True

        return detections, len(detections)

    async def analyze_attachments(
        self,
        scans: list[EmailScan],
    ) -> tuple[list[dict[str, Any]], int]:
        """Analyze email attachments for sensitive data."""
        logger.info(
            "email_dlp.analyze_attachments",
            scan_count=len(scans),
        )
        results: list[dict[str, Any]] = []
        risky_count = 0

        for scan in scans:
            for name in scan.attachment_names:
                ext = ""
                if "." in name:
                    ext = "." + name.rsplit(".", 1)[-1].lower()

                is_risky = ext in SENSITIVE_EXTENSIONS
                size_mb = hash(name) % 50 + 1

                results.append(
                    {
                        "email_id": scan.id,
                        "filename": name,
                        "extension": ext,
                        "size_mb": size_mb,
                        "is_risky": is_risky,
                        "external": scan.external_recipients > 0,
                        "scanned_at": time.time(),
                    }
                )
                if is_risky:
                    risky_count += 1

        return results, risky_count

    async def enforce_policy(
        self,
        pii_detections: list[dict[str, Any]],
        attachment_scans: list[dict[str, Any]],
    ) -> tuple[list[DLPViolation], int]:
        """Enforce DLP policies on detections."""
        logger.info(
            "email_dlp.enforce_policy",
            detections=len(pii_detections),
        )
        violations: list[DLPViolation] = []
        blocked = 0

        for det in pii_detections:
            data_type = SensitiveDataType(det.get("data_type", "pii_generic"))
            is_external = det.get("external", False)

            action = PolicyAction.WARN
            policy_name = "default_warn"
            severity = "low"

            for policy in DLP_POLICIES:
                if policy["data_type"] == data_type:
                    if policy["external_only"] and not is_external:
                        continue
                    action = policy["action"]
                    policy_name = policy["name"]
                    severity = policy["severity"]
                    break

            violation = DLPViolation(
                id=_gen_id(),
                email_id=det.get("email_id", ""),
                sender=det.get("sender", ""),
                data_type=data_type,
                location=det.get("location", "body"),
                snippet=det.get("snippet", ""),
                action_taken=action,
                policy_name=policy_name,
                severity=severity,
                detected_at=time.time(),
            )
            violations.append(violation)
            if action == PolicyAction.BLOCK:
                blocked += 1

        # Attachment violations
        for att in attachment_scans:
            if att.get("is_risky") and att.get("external"):
                violation = DLPViolation(
                    id=_gen_id(),
                    email_id=att.get("email_id", ""),
                    sender="",
                    data_type=SensitiveDataType.PII_GENERIC,
                    location="attachment",
                    snippet=att.get("filename", ""),
                    action_taken=PolicyAction.QUARANTINE,
                    policy_name="risky_attachment_external",
                    severity="high",
                    detected_at=time.time(),
                )
                violations.append(violation)

        return violations, blocked

    async def audit_log(
        self,
        violations: list[DLPViolation],
    ) -> list[dict[str, Any]]:
        """Create audit log entries for violations."""
        logger.info(
            "email_dlp.audit_log",
            violation_count=len(violations),
        )
        entries: list[dict[str, Any]] = []

        for violation in violations:
            entries.append(
                {
                    "violation_id": violation.id,
                    "email_id": violation.email_id,
                    "data_type": violation.data_type.value,
                    "action": violation.action_taken.value,
                    "policy": violation.policy_name,
                    "severity": violation.severity,
                    "timestamp": time.time(),
                    "immutable": True,
                }
            )

        return entries

    @staticmethod
    def _sample_emails() -> list[dict[str, Any]]:
        return [
            {
                "from": "analyst@company.com",
                "to": ["partner@external.com"],
                "subject": "Customer Data Export",
                "body": ("Here is the data: SSN 123-45-6789, card 4111-1111-1111-1111"),
                "attachments": [
                    {"name": "customers.csv"},
                ],
            },
            {
                "from": "dev@company.com",
                "to": ["dev2@company.com"],
                "subject": "Config update",
                "body": ("Updated API key: AKIA1234567890ABCDEF"),
                "attachments": [],
            },
            {
                "from": "hr@company.com",
                "to": ["employee@company.com"],
                "subject": "Benefits update",
                "body": "Review your benefits package.",
                "attachments": [
                    {"name": "benefits.pdf"},
                ],
            },
        ]
