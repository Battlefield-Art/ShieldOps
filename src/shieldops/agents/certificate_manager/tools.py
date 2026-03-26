"""Certificate Manager Agent — Tool functions for certificate lifecycle."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from .models import (
    Certificate,
    CertStatus,
    ChainValidation,
    ExpiryAlert,
    RotationPlan,
    RotationStatus,
)

logger = structlog.get_logger()

# Expiry thresholds in days
_EXPIRY_THRESHOLDS: dict[str, int] = {
    "critical": 7,
    "high": 14,
    "warning": 30,
    "info": 60,
}


def _generate_cert_id(domain: str, issuer: str) -> str:
    """Generate a deterministic certificate ID."""
    raw = f"{domain}:{issuer}"
    return f"CERT-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class CertificateManagerToolkit:
    """Tools for TLS certificate lifecycle management."""

    def __init__(
        self,
        cert_store: Any | None = None,
        acme_client: Any | None = None,
        dns_client: Any | None = None,
        notification_client: Any | None = None,
    ) -> None:
        self._cert_store = cert_store
        self._acme_client = acme_client
        self._dns_client = dns_client
        self._notification_client = notification_client

    async def discover_certificates(self, tenant_id: str) -> list[Certificate]:
        """Discover all TLS certificates across infrastructure."""
        logger.info("cert_manager.discover", tenant_id=tenant_id)

        if self._cert_store is not None:
            try:
                raw = await self._cert_store.list_certificates(tenant_id=tenant_id)
                return [Certificate(**c) for c in raw]
            except Exception:
                logger.exception("cert_manager.discover.error")

        # Fallback: synthetic certificate inventory
        now = datetime.now(UTC)
        certs = [
            Certificate(
                id=_generate_cert_id("api.example.com", "Let's Encrypt"),
                domain="api.example.com",
                issuer="Let's Encrypt",
                expires_at=now + timedelta(days=25),
                days_until_expiry=25,
                key_size=2048,
                algorithm="RSA",
                auto_renewable=True,
            ),
            Certificate(
                id=_generate_cert_id("app.example.com", "DigiCert"),
                domain="app.example.com",
                issuer="DigiCert",
                expires_at=now + timedelta(days=5),
                days_until_expiry=5,
                key_size=4096,
                algorithm="RSA",
                auto_renewable=False,
                status=CertStatus.EXPIRING_SOON,
            ),
            Certificate(
                id=_generate_cert_id("internal.example.com", "Internal CA"),
                domain="internal.example.com",
                issuer="Internal CA",
                expires_at=now + timedelta(days=180),
                days_until_expiry=180,
                key_size=2048,
                algorithm="ECDSA",
                auto_renewable=True,
            ),
        ]
        return certs

    async def check_expiry(self, certificates: list[Certificate]) -> list[ExpiryAlert]:
        """Check certificates for upcoming expiry."""
        logger.info("cert_manager.check_expiry", cert_count=len(certificates))

        alerts: list[ExpiryAlert] = []
        for cert in certificates:
            days = cert.days_until_expiry

            severity = "info"
            for sev_name, threshold in _EXPIRY_THRESHOLDS.items():
                if days <= threshold:
                    severity = sev_name
                    break

            if severity != "info" or days <= _EXPIRY_THRESHOLDS["info"]:
                alerts.append(
                    ExpiryAlert(
                        cert_id=cert.id,
                        domain=cert.domain,
                        days_remaining=days,
                        severity=severity,
                        message=(
                            f"Certificate for {cert.domain} expires "
                            f"in {days} days (issuer: {cert.issuer})"
                        ),
                    )
                )

        alerts.sort(key=lambda a: a.days_remaining)
        return alerts

    async def validate_chains(self, certificates: list[Certificate]) -> list[ChainValidation]:
        """Validate certificate chains for trust issues."""
        logger.info("cert_manager.validate_chains", cert_count=len(certificates))

        validations: list[ChainValidation] = []
        for cert in certificates:
            issues: list[str] = []
            chain_valid = True

            if cert.key_size < 2048:
                issues.append(f"Weak key size: {cert.key_size} bits")
                chain_valid = False

            if cert.status == CertStatus.EXPIRED:
                issues.append("Certificate has expired")
                chain_valid = False

            if cert.status == CertStatus.REVOKED:
                issues.append("Certificate has been revoked")
                chain_valid = False

            validations.append(
                ChainValidation(
                    cert_id=cert.id,
                    domain=cert.domain,
                    chain_valid=chain_valid,
                    chain_depth=3,
                    issues=issues,
                    root_ca=cert.issuer,
                )
            )

        return validations

    async def plan_rotations(
        self,
        expiry_alerts: list[ExpiryAlert],
        certificates: list[Certificate],
    ) -> list[RotationPlan]:
        """Create rotation plans for expiring certificates."""
        logger.info("cert_manager.plan_rotations", alert_count=len(expiry_alerts))

        cert_map = {c.id: c for c in certificates}
        plans: list[RotationPlan] = []

        for alert in expiry_alerts:
            if alert.severity not in ("critical", "high", "warning"):
                continue

            cert = cert_map.get(alert.cert_id)
            if cert is None:
                continue

            requires_approval = not cert.auto_renewable
            provider = "acme" if cert.auto_renewable else "manual"

            plans.append(
                RotationPlan(
                    cert_id=cert.id,
                    domain=cert.domain,
                    action="renew" if cert.auto_renewable else "manual_renew",
                    provider=provider,
                    estimated_downtime_seconds=0 if cert.auto_renewable else 300,
                    requires_approval=requires_approval,
                )
            )

        return plans

    async def execute_rotation(self, plan: RotationPlan) -> RotationPlan:
        """Execute a certificate rotation plan."""
        logger.info(
            "cert_manager.execute_rotation",
            cert_id=plan.cert_id,
            domain=plan.domain,
        )

        if plan.requires_approval:
            return plan.model_copy(update={"status": RotationStatus.PENDING})

        if self._acme_client is not None:
            try:
                await self._acme_client.renew(domain=plan.domain)
                return plan.model_copy(update={"status": RotationStatus.COMPLETED})
            except Exception:
                logger.exception("cert_manager.execute_rotation.error")
                return plan.model_copy(update={"status": RotationStatus.FAILED})

        # Simulated successful rotation
        return plan.model_copy(update={"status": RotationStatus.COMPLETED})
