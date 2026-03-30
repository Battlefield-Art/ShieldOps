"""Privacy Consent Manager Agent — Tool functions."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .models import ConsentStatus, ConsentType

logger = structlog.get_logger()

_MOCK_CONSENTS: list[dict[str, Any]] = [
    {
        "subject_id": "user-001",
        "consent_type": "marketing",
        "status": "active",
        "purpose": "Email marketing campaigns",
    },
    {
        "subject_id": "user-001",
        "consent_type": "analytics",
        "status": "active",
        "purpose": "Usage analytics tracking",
    },
    {
        "subject_id": "user-002",
        "consent_type": "marketing",
        "status": "withdrawn",
        "purpose": "Email marketing campaigns",
    },
    {
        "subject_id": "user-002",
        "consent_type": "functional",
        "status": "active",
        "purpose": "Personalization features",
    },
    {
        "subject_id": "user-003",
        "consent_type": "third_party",
        "status": "expired",
        "purpose": "Third-party data sharing",
    },
    {
        "subject_id": "user-003",
        "consent_type": "essential",
        "status": "active",
        "purpose": "Service delivery",
    },
    {
        "subject_id": "user-004",
        "consent_type": "research",
        "status": "pending",
        "purpose": "Product research participation",
    },
    {
        "subject_id": "user-004",
        "consent_type": "analytics",
        "status": "invalid",
        "purpose": "Missing consent proof",
    },
]


class PrivacyConsentManagerToolkit:
    """Tools for privacy consent management."""

    def __init__(
        self,
        consent_store: Any | None = None,
        preference_api: Any | None = None,
        audit_logger: Any | None = None,
    ) -> None:
        self._consent_store = consent_store
        self._preference_api = preference_api
        self._audit_logger = audit_logger

    async def discover_consents(
        self,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Discover all consent records."""
        logger.info(
            "pcm.discover",
            tenant_id=tenant_id,
        )

        if self._consent_store is not None:
            try:
                return await self._consent_store.list(
                    tenant_id=tenant_id,
                )
            except Exception:
                logger.exception("pcm.discover.error")

        results: list[dict[str, Any]] = []
        for i, c in enumerate(_MOCK_CONSENTS):
            results.append(
                {
                    "id": f"cns-{i:03d}",
                    "subject_id": c["subject_id"],
                    "consent_type": c["consent_type"],
                    "status": c["status"],
                    "granted_at": "2025-01-15",
                    "expires_at": "2026-01-15",
                    "purpose": c["purpose"],
                    "source": "consent_platform",
                }
            )
        return results

    def validate_record(
        self,
        consent: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate a consent record."""
        issues: list[str] = []
        status = consent.get("status", "")

        if not consent.get("subject_id"):
            issues.append("Missing subject identifier")
        if not consent.get("granted_at"):
            issues.append("Missing grant timestamp")
        if not consent.get("purpose"):
            issues.append("Missing consent purpose")
        if status == ConsentStatus.INVALID.value:
            issues.append("Consent record is invalid")

        consent["validation_issues"] = issues
        consent["valid"] = len(issues) == 0
        return consent

    async def enforce_preference(
        self,
        consent: dict[str, Any],
    ) -> dict[str, Any]:
        """Enforce a consent preference downstream."""
        logger.info(
            "pcm.enforce",
            consent_id=consent.get("id"),
        )

        status = consent.get("status", "")
        action = "no_action"
        enforced = False
        systems = 0

        if status in (
            ConsentStatus.WITHDRAWN.value,
            ConsentStatus.EXPIRED.value,
        ):
            action = "disable_processing"
            enforced = True
            systems = 3
        elif status == ConsentStatus.ACTIVE.value:
            action = "allow_processing"
            enforced = True
            systems = 3

        if self._preference_api is not None:
            try:
                return await self._preference_api.enforce(
                    consent=consent,
                )
            except Exception:
                logger.exception("pcm.enforce.error")

        return {
            "consent_id": consent.get("id", ""),
            "subject_id": consent.get("subject_id", ""),
            "action": action,
            "enforced": enforced,
            "systems_updated": systems,
        }

    def audit_consent(
        self,
        consent: dict[str, Any],
    ) -> dict[str, Any]:
        """Audit a consent record for compliance."""
        issues: list[str] = []

        if not consent.get("valid", True):
            issues.extend(
                consent.get("validation_issues", []),
            )

        status = consent.get("status", "")
        if status == ConsentStatus.EXPIRED.value:
            issues.append(
                "Consent expired, processing must stop",
            )
        if status == ConsentStatus.INVALID.value:
            issues.append(
                "Invalid consent, no legal basis",
            )

        ctype = consent.get("consent_type", "")
        if ctype == ConsentType.THIRD_PARTY.value and status != ConsentStatus.ACTIVE.value:
            issues.append(
                "Third-party sharing without active consent",
            )

        return {
            "consent_id": consent.get("id", ""),
            "compliant": len(issues) == 0,
            "issues": issues,
            "audited_at": time.time(),
        }

    def generate_report(
        self,
        consents: list[dict[str, Any]],
        enforcements: list[dict[str, Any]],
        audit_entries: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate consent compliance report."""
        active = sum(1 for c in consents if c.get("status") == "active")
        expired = sum(1 for c in consents if c.get("status") == "expired")
        withdrawn = sum(1 for c in consents if c.get("status") == "withdrawn")
        compliant = sum(1 for a in audit_entries if a.get("compliant"))
        total_audited = len(audit_entries)
        rate = round(compliant / total_audited * 100, 1) if total_audited > 0 else 0.0

        return {
            "total_consents": len(consents),
            "active_consents": active,
            "expired_consents": expired,
            "withdrawn_consents": withdrawn,
            "compliance_rate": rate,
            "enforcements_applied": sum(1 for e in enforcements if e.get("enforced")),
            "audit_issues": sum(len(a.get("issues", [])) for a in audit_entries),
            "generated_at": time.time(),
        }
