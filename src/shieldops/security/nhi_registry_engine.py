"""NHIRegistryEngine — Register, classify, and assess non-human identities."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class NHIType(StrEnum):
    SERVICE_ACCOUNT = "service_account"
    AI_AGENT = "ai_agent"
    CI_CD_TOKEN = "ci_cd_token"  # noqa: S105
    OAUTH_APP = "oauth_app"
    API_KEY = "api_key"
    MCP_CONNECTION = "mcp_connection"
    GITHUB_ACTION = "github_action"
    TERRAFORM_PRINCIPAL = "terraform_principal"
    K8S_SERVICE_ACCOUNT = "k8s_service_account"


class NHIStatus(StrEnum):
    ACTIVE = "active"
    DORMANT = "dormant"
    ORPHANED = "orphaned"
    COMPROMISED = "compromised"
    DECOMMISSIONED = "decommissioned"
    SHADOW = "shadow"


class NHIRisk(StrEnum):
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --- Models ---


class NHIRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    nhi_type: NHIType = NHIType.SERVICE_ACCOUNT
    provider: str = ""
    permissions: list[str] = Field(default_factory=list)
    last_used: float = 0.0
    owner: str = ""
    risk: NHIRisk = NHIRisk.LOW
    status: NHIStatus = NHIStatus.ACTIVE
    created_at: float = Field(default_factory=time.time)


class NHIClassification(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    nhi_id: str = ""
    classification_reason: str = ""
    confidence: float = 0.0
    classifier: str = ""
    created_at: float = Field(default_factory=time.time)


class NHIRegistryReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_classifications: int = 0
    gap_count: int = 0
    avg_risk_score: float = 0.0
    by_nhi_type: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_risk: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Risk scoring helpers ---

_TYPE_RISK_WEIGHTS: dict[NHIType, float] = {
    NHIType.SERVICE_ACCOUNT: 15.0,
    NHIType.AI_AGENT: 25.0,
    NHIType.CI_CD_TOKEN: 20.0,
    NHIType.OAUTH_APP: 12.0,
    NHIType.API_KEY: 15.0,
    NHIType.MCP_CONNECTION: 28.0,
    NHIType.GITHUB_ACTION: 12.0,
    NHIType.TERRAFORM_PRINCIPAL: 25.0,
    NHIType.K8S_SERVICE_ACCOUNT: 18.0,
}


# --- Engine ---


class NHIRegistryEngine:
    """Register, classify, and risk-assess non-human identities."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[NHIRecord] = []
        self._classifications: list[NHIClassification] = []
        logger.info(
            "nhi_registry_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- register / classify -------------------------------------------------

    def register_identity(
        self,
        name: str,
        nhi_type: NHIType = NHIType.SERVICE_ACCOUNT,
        provider: str = "",
        permissions: list[str] | None = None,
        owner: str = "",
        last_used: float = 0.0,
        status: NHIStatus = NHIStatus.ACTIVE,
    ) -> NHIRecord:
        record = NHIRecord(
            name=name,
            nhi_type=nhi_type,
            provider=provider,
            permissions=permissions or [],
            owner=owner,
            last_used=last_used or time.time(),
            status=status,
        )
        record.risk = self._risk_level(self.calculate_risk_score(record.id, record=record))
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "nhi_registry_engine.identity_registered",
            record_id=record.id,
            name=name,
            nhi_type=nhi_type.value,
            provider=provider,
        )
        return record

    def classify_identity(
        self,
        nhi_id: str,
        classification_reason: str = "",
        confidence: float = 0.0,
        classifier: str = "system",
    ) -> NHIClassification:
        classification = NHIClassification(
            nhi_id=nhi_id,
            classification_reason=classification_reason,
            confidence=confidence,
            classifier=classifier,
        )
        self._classifications.append(classification)
        if len(self._classifications) > self._max_records:
            self._classifications = self._classifications[-self._max_records :]
        logger.info(
            "nhi_registry_engine.identity_classified",
            nhi_id=nhi_id,
            reason=classification_reason,
            confidence=confidence,
        )
        return classification

    # -- domain operations ---------------------------------------------------

    def detect_orphaned(self, stale_days: int = 90) -> list[NHIRecord]:
        """Identify NHIs with no owner or no activity in N days."""
        now = time.time()
        cutoff = now - stale_days * 86400
        results: list[NHIRecord] = []
        for r in self._records:
            if r.status == NHIStatus.DECOMMISSIONED:
                continue
            no_owner = not r.owner
            no_activity = r.last_used < cutoff if r.last_used > 0 else True
            if no_owner or no_activity:
                results.append(r)
        return sorted(results, key=lambda x: x.last_used)

    def detect_over_privileged(self, max_permissions: int = 10) -> list[NHIRecord]:
        """Identify NHIs exceeding permission thresholds."""
        results: list[NHIRecord] = []
        for r in self._records:
            if r.status == NHIStatus.DECOMMISSIONED:
                continue
            has_wildcard = any("*" in p for p in r.permissions)
            if has_wildcard or len(r.permissions) > max_permissions:
                results.append(r)
        return sorted(results, key=lambda x: len(x.permissions), reverse=True)

    def calculate_risk_score(
        self,
        nhi_id: str,
        record: NHIRecord | None = None,
    ) -> float:
        """Composite risk score based on type, permissions, age, activity."""
        if record is None:
            record = self._find_record(nhi_id)
        if record is None:
            return 0.0

        now = time.time()
        score = 0.0

        # Type weight (0-28 points)
        score += _TYPE_RISK_WEIGHTS.get(record.nhi_type, 15.0)

        # Permission breadth (0-25 points)
        has_wildcard = any("*" in p for p in record.permissions)
        if has_wildcard:
            score += 25.0
        elif len(record.permissions) > 10:
            score += 18.0
        elif len(record.permissions) > 5:
            score += 10.0
        else:
            score += max(0.0, len(record.permissions) * 1.5)

        # Credential age (0-20 points)
        age_days = (now - record.created_at) / 86400 if record.created_at > 0 else 0
        if age_days > 365:
            score += 20.0
        elif age_days > 180:
            score += 14.0
        elif age_days > 90:
            score += 8.0

        # Activity recency (0-17 points)
        idle_days = (now - record.last_used) / 86400 if record.last_used > 0 else 999
        if idle_days > 180:
            score += 17.0
        elif idle_days > 90:
            score += 11.0
        elif idle_days > 30:
            score += 5.0

        # Owner status (0-10 points)
        if not record.owner:
            score += 10.0

        return round(min(100.0, max(0.0, score)), 1)

    def search(
        self,
        query: str = "",
        nhi_type: NHIType | None = None,
        status: NHIStatus | None = None,
        provider: str | None = None,
        limit: int = 50,
    ) -> list[NHIRecord]:
        """Search the registry with optional filters."""
        results = list(self._records)
        if query:
            q = query.lower()
            results = [r for r in results if q in r.name.lower() or q in r.provider.lower()]
        if nhi_type is not None:
            results = [r for r in results if r.nhi_type == nhi_type]
        if status is not None:
            results = [r for r in results if r.status == status]
        if provider is not None:
            results = [r for r in results if r.provider == provider]
        return results[-limit:]

    # -- standard methods ----------------------------------------------------

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.provider == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [self.calculate_risk_score(r.id, record=r) for r in matched]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_risk_score": avg,
            "above_threshold": sum(1 for s in scores if s >= self._threshold),
        }

    def generate_report(self) -> NHIRegistryReport:
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        for r in self._records:
            by_type[r.nhi_type.value] = by_type.get(r.nhi_type.value, 0) + 1
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
            by_risk[r.risk.value] = by_risk.get(r.risk.value, 0) + 1

        scores = [self.calculate_risk_score(r.id, record=r) for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for s in scores if s >= self._threshold)

        orphaned = self.detect_orphaned()
        over_priv = self.detect_over_privileged()
        top_gaps = [r.name for r in orphaned[:3]] + [r.name for r in over_priv[:2]]

        recs: list[str] = []
        if orphaned:
            recs.append(f"{len(orphaned)} orphaned identities need owner assignment or removal")
        if over_priv:
            recs.append(f"{len(over_priv)} over-privileged identities need permission scoping")
        if not recs:
            recs.append("NHI Registry posture is healthy")

        return NHIRegistryReport(
            total_records=len(self._records),
            total_classifications=len(self._classifications),
            gap_count=gap_count,
            avg_risk_score=avg_score,
            by_nhi_type=by_type,
            by_status=by_status,
            by_risk=by_risk,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._classifications.clear()
        logger.info("nhi_registry_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            type_dist[r.nhi_type.value] = type_dist.get(r.nhi_type.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_classifications": len(self._classifications),
            "threshold": self._threshold,
            "nhi_type_distribution": type_dist,
            "unique_providers": len({r.provider for r in self._records}),
            "unique_owners": len({r.owner for r in self._records if r.owner}),
            "orphaned_count": len(self.detect_orphaned()),
            "over_privileged_count": len(self.detect_over_privileged()),
        }

    # -- internal helpers ----------------------------------------------------

    def _find_record(self, nhi_id: str) -> NHIRecord | None:
        for r in self._records:
            if r.id == nhi_id:
                return r
        return None

    @staticmethod
    def _risk_level(score: float) -> NHIRisk:
        if score >= 80:
            return NHIRisk.CRITICAL
        if score >= 60:
            return NHIRisk.HIGH
        if score >= 40:
            return NHIRisk.MEDIUM
        if score >= 20:
            return NHIRisk.LOW
        return NHIRisk.MINIMAL
