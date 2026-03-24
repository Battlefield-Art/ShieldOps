"""OAuth Grant Analyzer — assess OAuth grants for over-permission and risk."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class GrantType(StrEnum):
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "device_code"
    IMPLICIT = "implicit"
    REFRESH_TOKEN = "refresh_token"  # noqa: S105
    JWT_BEARER = "jwt_bearer"


class GrantRisk(StrEnum):
    SAFE = "safe"
    ELEVATED = "elevated"
    EXCESSIVE = "excessive"
    DANGEROUS = "dangerous"
    COMPROMISED = "compromised"


class GrantScope(StrEnum):
    READ_MAIL = "read_mail"
    READ_WRITE_ALL = "read_write_all"
    DIRECTORY_READ = "directory_read"
    FILES_READ_WRITE = "files_read_write"
    SITES_MANAGE = "sites_manage"
    FULL_ACCESS = "full_access"


# --- Models ---


class OAuthGrantRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    application_name: str = ""
    grant_type: GrantType = GrantType.AUTHORIZATION_CODE
    grant_risk: GrantRisk = GrantRisk.SAFE
    scopes: list[GrantScope] = Field(default_factory=list)
    principal_id: str = ""
    tenant_id: str = ""
    last_used_at: float = 0.0
    expires_at: float = 0.0
    details: str = ""
    created_at: float = Field(default_factory=time.time)


class GrantRiskAssessment(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    grant_id: str = ""
    risk_level: GrantRisk = GrantRisk.SAFE
    risk_score: float = 0.0
    excessive_scopes: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    assessed_at: float = Field(default_factory=time.time)


class OAuthGrantReport(BaseModel):
    total_grants: int = 0
    total_excessive: int = 0
    total_stale: int = 0
    risk_distribution: dict[str, int] = Field(default_factory=dict)
    by_grant_type: dict[str, int] = Field(default_factory=dict)
    top_risky_apps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---

_DANGEROUS_SCOPES = {GrantScope.READ_WRITE_ALL, GrantScope.FULL_ACCESS, GrantScope.SITES_MANAGE}
_ELEVATED_SCOPES = {GrantScope.FILES_READ_WRITE, GrantScope.DIRECTORY_READ}
_STALE_THRESHOLD_DAYS = 90


class OAuthGrantAnalyzer:
    """Analyze OAuth grants for over-permission and risk."""

    def __init__(self, max_records: int = 200000, stale_days: int = 90) -> None:
        self._max_records = max_records
        self._stale_days = stale_days
        self._records: list[OAuthGrantRecord] = []
        self._assessments: list[GrantRiskAssessment] = []
        logger.info("oauth_grant_analyzer.initialized", max_records=max_records)

    # -- record / get --------------------------------------------------------

    def register_grant(
        self,
        application_name: str,
        grant_type: GrantType = GrantType.AUTHORIZATION_CODE,
        scopes: list[GrantScope] | None = None,
        principal_id: str = "",
        tenant_id: str = "",
        last_used_at: float = 0.0,
        expires_at: float = 0.0,
        details: str = "",
    ) -> OAuthGrantRecord:
        record = OAuthGrantRecord(
            application_name=application_name,
            grant_type=grant_type,
            scopes=scopes or [],
            principal_id=principal_id,
            tenant_id=tenant_id,
            last_used_at=last_used_at,
            expires_at=expires_at,
            details=details,
        )
        # Compute initial risk
        record.grant_risk = self._compute_risk(record)
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "oauth_grant_analyzer.grant_registered",
            record_id=record.id,
            application_name=application_name,
            grant_type=grant_type.value,
            risk=record.grant_risk.value,
        )
        return record

    # -- domain operations ---------------------------------------------------

    def assess_grant_risk(self, grant_id: str) -> GrantRiskAssessment:
        """Perform a detailed risk assessment of a specific grant."""
        record = next((r for r in self._records if r.id == grant_id), None)
        if record is None:
            return GrantRiskAssessment(grant_id=grant_id, risk_level=GrantRisk.SAFE)

        excessive = [s.value for s in record.scopes if s in _DANGEROUS_SCOPES]
        risk_score = len(excessive) * 25.0
        if record.grant_type == GrantType.IMPLICIT:
            risk_score += 20.0
        if record.grant_type == GrantType.CLIENT_CREDENTIALS:
            risk_score += 10.0

        elevated = [s.value for s in record.scopes if s in _ELEVATED_SCOPES]
        risk_score += len(elevated) * 10.0
        risk_score = min(risk_score, 100.0)

        risk_level = GrantRisk.SAFE
        if risk_score >= 75:
            risk_level = GrantRisk.DANGEROUS
        elif risk_score >= 50:
            risk_level = GrantRisk.EXCESSIVE
        elif risk_score >= 25:
            risk_level = GrantRisk.ELEVATED

        recs: list[str] = []
        if excessive:
            recs.append(f"Remove dangerous scopes: {', '.join(excessive)}")
        if record.grant_type == GrantType.IMPLICIT:
            recs.append("Migrate from implicit grant to authorization_code with PKCE")
        if not record.last_used_at or (
            time.time() - record.last_used_at > self._stale_days * 86400
        ):
            recs.append("Grant appears stale — consider revoking")

        assessment = GrantRiskAssessment(
            grant_id=grant_id,
            risk_level=risk_level,
            risk_score=risk_score,
            excessive_scopes=excessive,
            recommendations=recs,
        )
        self._assessments.append(assessment)
        if len(self._assessments) > self._max_records:
            self._assessments = self._assessments[-self._max_records :]
        return assessment

    def detect_excessive_scopes(self) -> list[dict[str, Any]]:
        """Identify grants with scopes beyond what is needed."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            dangerous = [s.value for s in r.scopes if s in _DANGEROUS_SCOPES]
            if dangerous:
                results.append(
                    {
                        "grant_id": r.id,
                        "application_name": r.application_name,
                        "principal_id": r.principal_id,
                        "excessive_scopes": dangerous,
                        "total_scopes": len(r.scopes),
                        "risk": r.grant_risk.value,
                    }
                )
        results.sort(key=lambda x: len(x["excessive_scopes"]), reverse=True)
        return results

    def identify_stale_grants(self) -> list[dict[str, Any]]:
        """Find grants that have not been used within the stale threshold."""
        now = time.time()
        threshold = self._stale_days * 86400
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.last_used_at and (now - r.last_used_at) > threshold:
                days_stale = int((now - r.last_used_at) / 86400)
                results.append(
                    {
                        "grant_id": r.id,
                        "application_name": r.application_name,
                        "principal_id": r.principal_id,
                        "days_since_last_use": days_stale,
                        "scopes": [s.value for s in r.scopes],
                    }
                )
            elif not r.last_used_at and (now - r.created_at) > threshold:
                results.append(
                    {
                        "grant_id": r.id,
                        "application_name": r.application_name,
                        "principal_id": r.principal_id,
                        "days_since_last_use": int((now - r.created_at) / 86400),
                        "scopes": [s.value for s in r.scopes],
                        "never_used": True,
                    }
                )
        results.sort(key=lambda x: x["days_since_last_use"], reverse=True)
        return results

    # -- report / stats ------------------------------------------------------

    def generate_grant_report(self) -> OAuthGrantReport:
        risk_dist: dict[str, int] = {}
        by_type: dict[str, int] = {}
        for r in self._records:
            risk_dist[r.grant_risk.value] = risk_dist.get(r.grant_risk.value, 0) + 1
            by_type[r.grant_type.value] = by_type.get(r.grant_type.value, 0) + 1

        excessive = self.detect_excessive_scopes()
        stale = self.identify_stale_grants()

        # Top risky apps
        app_risk: dict[str, int] = {}
        for r in self._records:
            if r.grant_risk in (GrantRisk.DANGEROUS, GrantRisk.EXCESSIVE):
                app_risk[r.application_name] = app_risk.get(r.application_name, 0) + 1
        top_risky = sorted(app_risk.keys(), key=lambda k: app_risk[k], reverse=True)[:10]

        recs: list[str] = []
        if excessive:
            recs.append(f"{len(excessive)} grant(s) have excessive scopes — review immediately")
        if stale:
            recs.append(f"{len(stale)} grant(s) are stale — consider revoking")
        if not recs:
            recs.append("OAuth grant hygiene meets targets")

        return OAuthGrantReport(
            total_grants=len(self._records),
            total_excessive=len(excessive),
            total_stale=len(stale),
            risk_distribution=risk_dist,
            by_grant_type=by_type,
            top_risky_apps=top_risky,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        risk_dist: dict[str, int] = {}
        for r in self._records:
            risk_dist[r.grant_risk.value] = risk_dist.get(r.grant_risk.value, 0) + 1
        return {
            "total_grants": len(self._records),
            "total_assessments": len(self._assessments),
            "risk_distribution": risk_dist,
            "unique_apps": len({r.application_name for r in self._records}),
            "stale_days_threshold": self._stale_days,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._assessments.clear()
        logger.info("oauth_grant_analyzer.cleared")
        return {"status": "cleared"}

    # -- private helpers -----------------------------------------------------

    @staticmethod
    def _compute_risk(record: OAuthGrantRecord) -> GrantRisk:
        has_dangerous = any(s in _DANGEROUS_SCOPES for s in record.scopes)
        has_elevated = any(s in _ELEVATED_SCOPES for s in record.scopes)
        if has_dangerous and record.grant_type == GrantType.IMPLICIT:
            return GrantRisk.DANGEROUS
        if has_dangerous:
            return GrantRisk.EXCESSIVE
        if has_elevated:
            return GrantRisk.ELEVATED
        return GrantRisk.SAFE
