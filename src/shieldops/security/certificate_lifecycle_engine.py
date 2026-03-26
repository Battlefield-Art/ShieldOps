"""Certificate Lifecycle Engine —
track certificate expiration, renewal status,
manage certificate inventory across services."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CertStatus(StrEnum):
    VALID = "valid"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SELF_SIGNED = "self_signed"


class CertType(StrEnum):
    TLS = "tls"
    MTLS = "mtls"
    CODE_SIGNING = "code_signing"
    CA_ROOT = "ca_root"
    INTERMEDIATE = "intermediate"


class RenewalMethod(StrEnum):
    AUTO_ACME = "auto_acme"
    MANUAL = "manual"
    VAULT_PKI = "vault_pki"
    CLOUD_MANAGED = "cloud_managed"
    SELF_MANAGED = "self_managed"


# --- Models ---


class CertificateLifecycleRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    domain: str = ""
    service_name: str = ""
    cert_status: CertStatus = CertStatus.VALID
    cert_type: CertType = CertType.TLS
    renewal_method: RenewalMethod = RenewalMethod.AUTO_ACME
    days_until_expiry: float = 0.0
    issuer: str = ""
    key_size_bits: int = 2048
    serial_number: str = ""
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CertificateLifecycleAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    domain: str = ""
    cert_status: CertStatus = CertStatus.VALID
    days_until_expiry: float = 0.0
    renewal_urgency: float = 0.0
    risk_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CertificateLifecycleReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_days_until_expiry: float = 0.0
    by_cert_status: dict[str, int] = Field(default_factory=dict)
    by_cert_type: dict[str, int] = Field(default_factory=dict)
    by_renewal_method: dict[str, int] = Field(default_factory=dict)
    expiring_soon_domains: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class CertificateLifecycleEngine:
    """Track certificate expiration, renewal status,
    manage certificate inventory across services."""

    def __init__(self, max_records: int = 200000, expiry_threshold: float = 30.0) -> None:
        self._max_records = max_records
        self._expiry_threshold = expiry_threshold
        self._records: list[CertificateLifecycleRecord] = []
        self._analyses: dict[str, CertificateLifecycleAnalysis] = {}
        logger.info(
            "certificate_lifecycle_engine.init",
            max_records=max_records,
            expiry_threshold=expiry_threshold,
        )

    def add_record(
        self,
        domain: str = "",
        service_name: str = "",
        cert_status: CertStatus = CertStatus.VALID,
        cert_type: CertType = CertType.TLS,
        renewal_method: RenewalMethod = RenewalMethod.AUTO_ACME,
        days_until_expiry: float = 0.0,
        issuer: str = "",
        key_size_bits: int = 2048,
        serial_number: str = "",
        description: str = "",
    ) -> CertificateLifecycleRecord:
        record = CertificateLifecycleRecord(
            domain=domain,
            service_name=service_name,
            cert_status=cert_status,
            cert_type=cert_type,
            renewal_method=renewal_method,
            days_until_expiry=days_until_expiry,
            issuer=issuer,
            key_size_bits=key_size_bits,
            serial_number=serial_number,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "certificate_lifecycle.record_added",
            record_id=record.id,
            domain=domain,
        )
        return record

    def process(self, key: str) -> CertificateLifecycleAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key or r.domain == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        urgency = max(0.0, round(1.0 - rec.days_until_expiry / 90.0, 3))
        risk = round(urgency * 50 + (50 if rec.cert_status != CertStatus.VALID else 0), 2)
        analysis = CertificateLifecycleAnalysis(
            domain=rec.domain,
            cert_status=rec.cert_status,
            days_until_expiry=rec.days_until_expiry,
            renewal_urgency=urgency,
            risk_score=risk,
            description=(
                f"{rec.domain} expires in {rec.days_until_expiry}d "
                f"status={rec.cert_status.value} risk={risk}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> CertificateLifecycleReport:
        by_status: dict[str, int] = {}
        by_type: dict[str, int] = {}
        by_renewal: dict[str, int] = {}
        expiry_days: list[float] = []
        for r in self._records:
            s = r.cert_status.value
            by_status[s] = by_status.get(s, 0) + 1
            t = r.cert_type.value
            by_type[t] = by_type.get(t, 0) + 1
            rm = r.renewal_method.value
            by_renewal[rm] = by_renewal.get(rm, 0) + 1
            expiry_days.append(r.days_until_expiry)
        avg_expiry = round(sum(expiry_days) / len(expiry_days), 1) if expiry_days else 0.0
        expiring = list(
            {
                r.domain
                for r in self._records
                if r.days_until_expiry <= self._expiry_threshold
                and r.cert_status != CertStatus.EXPIRED
            }
        )[:10]
        recs: list[str] = []
        if expiring:
            recs.append(f"{len(expiring)} domains expiring within {self._expiry_threshold} days")
        expired_count = by_status.get("expired", 0)
        if expired_count:
            recs.append(f"{expired_count} certificates already expired — renew immediately")
        if not recs:
            recs.append("All certificates within acceptable lifecycle bounds")
        return CertificateLifecycleReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_days_until_expiry=avg_expiry,
            by_cert_status=by_status,
            by_cert_type=by_type,
            by_renewal_method=by_renewal,
            expiring_soon_domains=expiring,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        status_dist: dict[str, int] = {}
        for r in self._records:
            k = r.cert_status.value
            status_dist[k] = status_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "status_distribution": status_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("certificate_lifecycle_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def find_expiring_certificates(self) -> list[dict[str, Any]]:
        """Find certificates expiring within threshold days."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.days_until_expiry <= self._expiry_threshold:
                results.append(
                    {
                        "domain": r.domain,
                        "service_name": r.service_name,
                        "cert_type": r.cert_type.value,
                        "days_until_expiry": r.days_until_expiry,
                        "renewal_method": r.renewal_method.value,
                        "cert_status": r.cert_status.value,
                    }
                )
        results.sort(key=lambda x: x["days_until_expiry"])
        return results

    def audit_weak_certificates(self) -> list[dict[str, Any]]:
        """Audit certificates with weak key sizes or self-signed status."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            issues: list[str] = []
            if r.key_size_bits < 2048:
                issues.append(f"weak key size ({r.key_size_bits} bits)")
            if r.cert_status == CertStatus.SELF_SIGNED:
                issues.append("self-signed certificate")
            if r.cert_status == CertStatus.REVOKED:
                issues.append("revoked certificate still in inventory")
            if issues:
                results.append(
                    {
                        "domain": r.domain,
                        "service_name": r.service_name,
                        "cert_type": r.cert_type.value,
                        "key_size_bits": r.key_size_bits,
                        "issues": issues,
                    }
                )
        return results

    def summarize_renewal_coverage(self) -> list[dict[str, Any]]:
        """Summarize renewal method coverage across certificate inventory."""
        method_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            m = r.renewal_method.value
            method_data.setdefault(m, {"total": 0, "valid": 0, "expiring": 0})
            method_data[m]["total"] += 1
            if r.cert_status == CertStatus.VALID:
                method_data[m]["valid"] += 1
            if r.days_until_expiry <= self._expiry_threshold:
                method_data[m]["expiring"] += 1
        results: list[dict[str, Any]] = []
        for method, counts in method_data.items():
            results.append(
                {
                    "renewal_method": method,
                    "total_certs": counts["total"],
                    "valid": counts["valid"],
                    "expiring_soon": counts["expiring"],
                    "valid_pct": round(counts["valid"] / counts["total"] * 100, 2)
                    if counts["total"] > 0
                    else 0.0,
                }
            )
        results.sort(key=lambda x: x["total_certs"], reverse=True)
        return results
