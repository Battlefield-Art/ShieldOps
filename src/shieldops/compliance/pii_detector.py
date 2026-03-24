"""PII Detection and Redaction Engine.

Scans agent inputs/outputs for personally identifiable information (PII),
protected health information (PHI/HIPAA), and payment card data (PCI-DSS).
Redacts or masks sensitive data before logging/storage.
"""

import re
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel

logger = structlog.get_logger()


class PIICategory(StrEnum):
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    AWS_KEY = "aws_key"
    API_KEY = "api_key"
    PASSWORD = "password"
    PHI_MRN = "phi_mrn"
    PHI_DOB = "phi_dob"
    PHI_DIAGNOSIS = "phi_diagnosis"


class PIIMatch(BaseModel):
    """Represents a detected PII match in text."""

    category: PIICategory
    original: str
    redacted: str
    start: int
    end: int
    framework: str  # hipaa, pci_dss, gdpr, soc2


class PIIDetector:
    """Detect and redact PII/PHI/PCI data from text."""

    # Regex patterns: (pattern, replacement, compliance_framework)
    PATTERNS: dict[PIICategory, tuple[str, str, str]] = {
        PIICategory.SSN: (
            r"\b\d{3}-\d{2}-\d{4}\b",
            "***-**-****",
            "soc2",
        ),
        PIICategory.CREDIT_CARD: (
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
            "****-****-****-****",
            "pci_dss",
        ),
        PIICategory.EMAIL: (
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "[EMAIL_REDACTED]",
            "gdpr",
        ),
        PIICategory.PHONE: (
            r"\b(?:\+1[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b",
            "[PHONE_REDACTED]",
            "gdpr",
        ),
        PIICategory.IP_ADDRESS: (
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "[IP_REDACTED]",
            "gdpr",
        ),
        PIICategory.AWS_KEY: (
            r"(?:AKIA|ASIA)[A-Z0-9]{16}",
            "[AWS_KEY_REDACTED]",
            "soc2",
        ),
        PIICategory.API_KEY: (
            r"(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|xoxb-[a-zA-Z0-9-]+)",
            "[API_KEY_REDACTED]",
            "soc2",
        ),
        PIICategory.PASSWORD: (
            r"(?:password|passwd|pwd)\s*[=:]\s*\S+",
            "[PASSWORD_REDACTED]",
            "soc2",
        ),
        PIICategory.PHI_MRN: (
            r"\bMRN[:\s]*\d{6,10}\b",
            "[MRN_REDACTED]",
            "hipaa",
        ),
        PIICategory.PHI_DOB: (
            r"\bDOB[:\s]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
            "[DOB_REDACTED]",
            "hipaa",
        ),
        PIICategory.PHI_DIAGNOSIS: (
            r"\b(?:diagnosis|dx)[:\s]+[A-Za-z\s]{3,50}(?=\.|,|\n|$)",
            "[DIAGNOSIS_REDACTED]",
            "hipaa",
        ),
    }

    def __init__(self) -> None:
        self._compiled: dict[PIICategory, re.Pattern[str]] = {}
        for category, (pattern, _, _) in self.PATTERNS.items():
            self._compiled[category] = re.compile(pattern, re.IGNORECASE)

    def scan(self, text: str) -> list[PIIMatch]:
        """Find all PII matches in text without modifying it."""
        matches: list[PIIMatch] = []
        for category, compiled in self._compiled.items():
            _, replacement, framework = self.PATTERNS[category]
            for match in compiled.finditer(text):
                matches.append(
                    PIIMatch(
                        category=category,
                        original=match.group(),
                        redacted=replacement,
                        start=match.start(),
                        end=match.end(),
                        framework=framework,
                    )
                )
        # Sort by position for deterministic output
        matches.sort(key=lambda m: m.start)
        return matches

    def redact(self, text: str) -> tuple[str, list[PIIMatch]]:
        """Replace all PII in text with redaction masks.

        Returns the redacted text and a list of all matches found.
        """
        matches = self.scan(text)
        if not matches:
            return text, []

        # Process replacements from end to start to preserve positions
        result = text
        for match in reversed(matches):
            result = result[: match.start] + match.redacted + result[match.end :]

        logger.info(
            "pii_redacted",
            match_count=len(matches),
            categories=[m.category for m in matches],
        )
        return result, matches

    def scan_dict(self, data: dict[str, Any]) -> list[PIIMatch]:
        """Recursively scan a dict (including nested dicts/lists) for PII."""
        all_matches: list[PIIMatch] = []
        self._walk_structure(data, all_matches, scan_only=True)
        return all_matches

    def redact_dict(self, data: dict[str, Any]) -> tuple[dict[str, Any], list[PIIMatch]]:
        """Recursively redact PII in a dict (including nested dicts/lists).

        Returns a new dict with PII redacted and the list of matches.
        """
        all_matches: list[PIIMatch] = []
        redacted = self._redact_value(data, all_matches)
        return redacted, all_matches

    def _walk_structure(
        self,
        value: Any,
        matches: list[PIIMatch],
        scan_only: bool = True,
    ) -> None:
        """Walk a nested structure scanning for PII."""
        if isinstance(value, str):
            matches.extend(self.scan(value))
        elif isinstance(value, dict):
            for v in value.values():
                self._walk_structure(v, matches, scan_only)
        elif isinstance(value, list):
            for item in value:
                self._walk_structure(item, matches, scan_only)

    def _redact_value(self, value: Any, matches: list[PIIMatch]) -> Any:
        """Recursively redact PII in a value, returning the redacted copy."""
        if isinstance(value, str):
            redacted_text, found = self.redact(value)
            matches.extend(found)
            return redacted_text
        elif isinstance(value, dict):
            return {k: self._redact_value(v, matches) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._redact_value(item, matches) for item in value]
        return value
