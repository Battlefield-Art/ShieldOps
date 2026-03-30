"""Certificate Lifecycle Manager Agent — Tool functions for certificate lifecycle."""

from __future__ import annotations

import hashlib
import random  # noqa: S311
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from .models import (
    Certificate,
    CertStatus,
    CertType,
    ConfigValidation,
    ExpiryCheck,
    RenewalExecution,
    RenewalPlan,
)

logger = structlog.get_logger()

# Expiry thresholds in days
_EXPIRY_CRITICAL = 7
_EXPIRY_WARNING = 30
_EXPIRY_NOTICE = 90

# Weak algorithms
_WEAK_KEY_ALGORITHMS = {"RSA-1024", "DSA-1024", "RC4"}
_WEAK_SIGNATURES = {"SHA1withRSA", "MD5withRSA"}
_INSECURE_PROTOCOLS = {"SSLv3", "TLSv1.0", "TLSv1.1"}


def _generate_cert_id(cn: str, host: str) -> str:
    """Generate a deterministic certificate ID."""
    raw = f"{cn}:{host}"
    return f"CRT-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


def _generate_serial() -> str:
    """Generate a random serial number."""
    return f"{random.randint(100000, 999999):X}"  # noqa: S311


class CertificateLifecycleManagerToolkit:
    """Tools for TLS/SSL certificate lifecycle management."""

    def __init__(
        self,
        acme_client: Any | None = None,
        scanner_client: Any | None = None,
        vault_client: Any | None = None,
    ) -> None:
        self._acme_client = acme_client
        self._scanner_client = scanner_client
        self._vault_client = vault_client

    async def discover_certificates(self, tenant_id: str) -> list[Certificate]:
        """Discover TLS/SSL certificates across infrastructure."""
        logger.info("cert_lifecycle.discover", tenant_id=tenant_id)

        if self._scanner_client is not None:
            try:
                raw = await self._scanner_client.scan_certs(tenant_id=tenant_id)
                return [Certificate(**c) for c in raw]
            except Exception:
                logger.exception("cert_lifecycle.discover.error")

        # Fallback: synthetic certificate data
        now = datetime.now(UTC)
        return [
            Certificate(
                id=_generate_cert_id("api.example.com", "lb-01"),
                common_name="api.example.com",
                san_names=[
                    "api.example.com",
                    "api-v2.example.com",
                ],
                cert_type=CertType.TLS_SERVER,
                status=CertStatus.VALID,
                issuer="Let's Encrypt Authority X3",
                serial_number=_generate_serial(),  # noqa: S311
                key_algorithm="RSA-2048",
                signature_algorithm="SHA256withRSA",
                issued_at=now - timedelta(days=60),
                expires_at=now + timedelta(days=30),
                auto_renew=True,
                host="lb-01",
                port=443,
                chain_valid=True,
                protocol_version="TLSv1.3",
            ),
            Certificate(
                id=_generate_cert_id("*.internal.example.com", "ingress-01"),
                common_name="*.internal.example.com",
                san_names=["*.internal.example.com"],
                cert_type=CertType.WILDCARD,
                status=CertStatus.EXPIRING_SOON,
                issuer="DigiCert SHA2 Extended Validation",
                serial_number=_generate_serial(),  # noqa: S311
                key_algorithm="ECDSA-P256",
                signature_algorithm="SHA256withECDSA",
                issued_at=now - timedelta(days=350),
                expires_at=now + timedelta(days=15),
                auto_renew=False,
                host="ingress-01",
                port=443,
                chain_valid=True,
                protocol_version="TLSv1.3",
            ),
            Certificate(
                id=_generate_cert_id("legacy.example.com", "web-legacy"),
                common_name="legacy.example.com",
                san_names=["legacy.example.com"],
                cert_type=CertType.TLS_SERVER,
                status=CertStatus.EXPIRED,
                issuer="GeoTrust RSA CA 2018",
                serial_number=_generate_serial(),  # noqa: S311
                key_algorithm="RSA-1024",
                signature_algorithm="SHA1withRSA",
                issued_at=now - timedelta(days=400),
                expires_at=now - timedelta(days=35),
                auto_renew=False,
                host="web-legacy",
                port=443,
                chain_valid=False,
                protocol_version="TLSv1.1",
            ),
            Certificate(
                id=_generate_cert_id("dev.example.com", "dev-01"),
                common_name="dev.example.com",
                san_names=["dev.example.com"],
                cert_type=CertType.SELF_SIGNED,
                status=CertStatus.VALID,
                issuer="Self-Signed",
                serial_number=_generate_serial(),  # noqa: S311
                key_algorithm="RSA-2048",
                signature_algorithm="SHA256withRSA",
                issued_at=now - timedelta(days=30),
                expires_at=now + timedelta(days=335),
                auto_renew=False,
                host="dev-01",
                port=8443,
                chain_valid=True,
                protocol_version="TLSv1.2",
            ),
            Certificate(
                id=_generate_cert_id("signing.example.com", "ci-server"),
                common_name="signing.example.com",
                san_names=[],
                cert_type=CertType.CODE_SIGNING,
                status=CertStatus.VALID,
                issuer="DigiCert Code Signing CA",
                serial_number=_generate_serial(),  # noqa: S311
                key_algorithm="RSA-4096",
                signature_algorithm="SHA256withRSA",
                issued_at=now - timedelta(days=180),
                expires_at=now + timedelta(days=185),
                auto_renew=False,
                host="ci-server",
                port=0,
                chain_valid=True,
                protocol_version="N/A",
            ),
        ]

    async def check_expiry(self, certs: list[Certificate]) -> list[ExpiryCheck]:
        """Check expiry status for discovered certificates."""
        logger.info(
            "cert_lifecycle.check_expiry",
            cert_count=len(certs),
        )

        now = datetime.now(UTC)
        checks: list[ExpiryCheck] = []

        for cert in certs:
            if cert.expires_at is None:
                days_remaining = -1
                status = CertStatus.MISCONFIGURED
                urgency = "unknown"
            elif cert.expires_at <= now:
                days_remaining = -(now - cert.expires_at).days
                status = CertStatus.EXPIRED
                urgency = "critical"
            else:
                days_remaining = (cert.expires_at - now).days
                if days_remaining <= _EXPIRY_CRITICAL:
                    status = CertStatus.EXPIRING_SOON
                    urgency = "critical"
                elif days_remaining <= _EXPIRY_WARNING:
                    status = CertStatus.EXPIRING_SOON
                    urgency = "high"
                elif days_remaining <= _EXPIRY_NOTICE:
                    status = CertStatus.EXPIRING_SOON
                    urgency = "medium"
                else:
                    status = CertStatus.VALID
                    urgency = "low"

            checks.append(
                ExpiryCheck(
                    cert_id=cert.id,
                    common_name=cert.common_name,
                    status=status,
                    days_remaining=days_remaining,
                    expires_at=cert.expires_at,
                    urgency=urgency,
                )
            )

        return checks

    async def validate_config(self, certs: list[Certificate]) -> list[ConfigValidation]:
        """Validate certificate configurations for compliance."""
        logger.info(
            "cert_lifecycle.validate_config",
            cert_count=len(certs),
        )

        validations: list[ConfigValidation] = []

        for cert in certs:
            issues: list[str] = []

            key_ok = cert.key_algorithm not in _WEAK_KEY_ALGORITHMS
            if not key_ok:
                issues.append(f"Weak key algorithm: {cert.key_algorithm}")

            sig_ok = cert.signature_algorithm not in _WEAK_SIGNATURES
            if not sig_ok:
                issues.append(f"Weak signature: {cert.signature_algorithm}")

            proto_ok = (
                cert.protocol_version not in _INSECURE_PROTOCOLS and cert.protocol_version != "N/A"
            )
            if not proto_ok and cert.protocol_version != "N/A":
                issues.append(f"Insecure protocol: {cert.protocol_version}")

            chain_ok = cert.chain_valid
            if not chain_ok:
                issues.append("Certificate chain validation failed")

            if cert.cert_type == CertType.SELF_SIGNED and cert.port == 443:
                issues.append("Self-signed certificate on port 443")

            compliant = (
                key_ok and sig_ok and chain_ok and (proto_ok or cert.protocol_version == "N/A")
            )

            validations.append(
                ConfigValidation(
                    cert_id=cert.id,
                    common_name=cert.common_name,
                    chain_valid=chain_ok,
                    protocol_secure=proto_ok or cert.protocol_version == "N/A",
                    key_strength_ok=key_ok,
                    signature_ok=sig_ok,
                    issues=issues,
                    compliant=compliant,
                )
            )

        return validations

    async def plan_renewals(
        self,
        certs: list[Certificate],
        expiry_checks: list[ExpiryCheck],
        config_validations: list[ConfigValidation],
    ) -> list[RenewalPlan]:
        """Plan certificate renewals based on expiry and compliance."""
        logger.info(
            "cert_lifecycle.plan_renewals",
            cert_count=len(certs),
        )

        expiry_map = {e.cert_id: e for e in expiry_checks}
        config_map = {v.cert_id: v for v in config_validations}
        plans: list[RenewalPlan] = []
        priority = 0

        for cert in certs:
            check = expiry_map.get(cert.id)
            validation = config_map.get(cert.id)
            reasons: list[str] = []

            needs_renewal = False

            if check and check.status in (
                CertStatus.EXPIRED,
                CertStatus.EXPIRING_SOON,
            ):
                needs_renewal = True
                reasons.append(f"Expiry: {check.days_remaining}d remaining")

            if validation and not validation.compliant:
                needs_renewal = True
                reasons.append(f"Non-compliant: {', '.join(validation.issues)}")

            if not needs_renewal:
                continue

            priority += 1
            method = "acme"
            if cert.auto_renew:
                method = "acme-auto"
            elif cert.cert_type in (
                CertType.CODE_SIGNING,
                CertType.CA_INTERMEDIATE,
            ):
                method = "manual-ca"

            provider = cert.issuer
            if cert.cert_type == CertType.SELF_SIGNED:
                provider = "internal-ca"
                method = "internal"

            plans.append(
                RenewalPlan(
                    cert_id=cert.id,
                    common_name=cert.common_name,
                    action="renew" if check and check.status != CertStatus.EXPIRED else "replace",
                    provider=provider,
                    method=method,
                    priority=priority,
                    reason="; ".join(reasons),
                    estimated_downtime_seconds=0 if method == "acme-auto" else 30,
                )
            )

        return plans

    async def execute_renewals(self, plans: list[RenewalPlan]) -> list[RenewalExecution]:
        """Execute certificate renewal plans."""
        logger.info(
            "cert_lifecycle.execute_renewals",
            plan_count=len(plans),
        )

        if self._acme_client is not None:
            try:
                results = []
                for plan in plans:
                    raw = await self._acme_client.renew(
                        cert_id=plan.cert_id,
                        method=plan.method,
                    )
                    results.append(RenewalExecution(**raw))
                return results
            except Exception:
                logger.exception("cert_lifecycle.execute_renewals.error")

        # Fallback: simulated renewal
        now = datetime.now(UTC)
        executions: list[RenewalExecution] = []

        for plan in plans:
            success = plan.method != "manual-ca"
            executions.append(
                RenewalExecution(
                    cert_id=plan.cert_id,
                    common_name=plan.common_name,
                    success=success,
                    new_serial=_generate_serial()  # noqa: S311
                    if success
                    else "",
                    new_expires_at=now + timedelta(days=365) if success else None,
                    method_used=plan.method,
                    error_message="" if success else "Manual CA renewal requires human action",
                )
            )

        return executions
