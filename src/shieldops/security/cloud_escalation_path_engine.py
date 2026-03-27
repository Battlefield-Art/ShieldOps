"""CloudEscalationPathEngine — Map privilege escalation paths."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EscalationType(StrEnum):
    IAM_ROLE_CHAIN = "iam_role_chain"
    SERVICE_ACCOUNT = "service_account"
    CROSS_ACCOUNT = "cross_account"
    METADATA_ABUSE = "metadata_abuse"
    TOKEN_THEFT = "token_theft"  # noqa: S105


class PermissionRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class PathComplexity(StrEnum):
    TRIVIAL = "trivial"
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    EXPERT = "expert"


# --- Models ---


class EscalationPathRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    escalation_type: EscalationType = EscalationType.IAM_ROLE_CHAIN
    permission_risk: PermissionRisk = PermissionRisk.MEDIUM
    complexity: PathComplexity = PathComplexity.MODERATE
    score: float = 0.0
    source_principal: str = ""
    target_principal: str = ""
    cloud_provider: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class EscalationPathAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    escalation_type: EscalationType = EscalationType.IAM_ROLE_CHAIN
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class EscalationPathReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_escalation_type: dict[str, int] = Field(default_factory=dict)
    by_permission_risk: dict[str, int] = Field(default_factory=dict)
    by_complexity: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CloudEscalationPathEngine:
    """Map and assess cloud privilege escalation."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[EscalationPathRecord] = []
        self._analyses: list[EscalationPathAnalysis] = []
        logger.info(
            "cloud_escalation_path.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def add_record(
        self,
        name: str,
        escalation_type: EscalationType = (EscalationType.IAM_ROLE_CHAIN),
        permission_risk: PermissionRisk = (PermissionRisk.MEDIUM),
        complexity: PathComplexity = (PathComplexity.MODERATE),
        score: float = 0.0,
        source_principal: str = "",
        target_principal: str = "",
        cloud_provider: str = "",
        service: str = "",
        team: str = "",
    ) -> EscalationPathRecord:
        record = EscalationPathRecord(
            name=name,
            escalation_type=escalation_type,
            permission_risk=permission_risk,
            complexity=complexity,
            score=score,
            source_principal=source_principal,
            target_principal=target_principal,
            cloud_provider=cloud_provider,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "cloud_escalation_path.record_added",
            record_id=record.id,
            name=name,
            escalation_type=escalation_type.value,
        )
        return record

    def get_record(self, record_id: str) -> EscalationPathRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        escalation_type: EscalationType | None = None,
        permission_risk: PermissionRisk | None = None,
        limit: int = 50,
    ) -> list[EscalationPathRecord]:
        results = list(self._records)
        if escalation_type is not None:
            results = [r for r in results if r.escalation_type == escalation_type]
        if permission_risk is not None:
            results = [r for r in results if r.permission_risk == permission_risk]
        return results[-limit:]

    # -- domain operations --------------------------------

    def map_escalation_path(self, source: str) -> dict[str, Any]:
        """Map escalation paths from a source."""
        matched = [r for r in self._records if r.source_principal == source]
        paths: list[dict[str, Any]] = []
        for r in matched:
            paths.append(
                {
                    "name": r.name,
                    "target": r.target_principal,
                    "type": r.escalation_type.value,
                    "risk": r.permission_risk.value,
                    "complexity": r.complexity.value,
                }
            )
        return {
            "source": source,
            "path_count": len(paths),
            "paths": paths,
        }

    def calculate_path_risk(
        self,
    ) -> list[dict[str, Any]]:
        """Calculate risk for all escalation paths."""
        risk_weights = {
            PermissionRisk.CRITICAL: 100,
            PermissionRisk.HIGH: 75,
            PermissionRisk.MEDIUM: 50,
            PermissionRisk.LOW: 25,
            PermissionRisk.NONE: 0,
        }
        complexity_mult = {
            PathComplexity.TRIVIAL: 1.5,
            PathComplexity.SIMPLE: 1.3,
            PathComplexity.MODERATE: 1.0,
            PathComplexity.COMPLEX: 0.7,
            PathComplexity.EXPERT: 0.5,
        }
        results: list[dict[str, Any]] = []
        for r in self._records:
            base = risk_weights.get(r.permission_risk, 50)
            mult = complexity_mult.get(r.complexity, 1.0)
            calc_risk = round(base * mult, 2)
            results.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "risk_score": calc_risk,
                    "permission_risk": (r.permission_risk.value),
                    "complexity": r.complexity.value,
                    "cloud_provider": r.cloud_provider,
                }
            )
        return sorted(
            results,
            key=lambda x: x["risk_score"],
            reverse=True,
        )

    def recommend_mitigation(
        self,
    ) -> list[dict[str, Any]]:
        """Recommend mitigations for high-risk paths."""
        high_risk = [
            r
            for r in self._records
            if r.permission_risk
            in (
                PermissionRisk.CRITICAL,
                PermissionRisk.HIGH,
            )
        ]
        recs: list[dict[str, Any]] = []
        for r in high_risk:
            recs.append(
                {
                    "name": r.name,
                    "escalation_type": (r.escalation_type.value),
                    "source": r.source_principal,
                    "target": r.target_principal,
                    "recommendation": (
                        f"Restrict {r.escalation_type.value} from {r.source_principal}"
                    ),
                    "priority": r.permission_risk.value,
                }
            )
        return recs

    # -- standard methods ---------------------------------

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
        }

    def generate_report(
        self,
    ) -> EscalationPathReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.escalation_type.value] = by_e1.get(r.escalation_type.value, 0) + 1
            by_e2[r.permission_risk.value] = by_e2.get(r.permission_risk.value, 0) + 1
            by_e3[r.complexity.value] = by_e3.get(r.complexity.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_ct = sum(1 for r in self._records if r.score < self._threshold)
        recs: list[str] = []
        if gap_ct > 0:
            recs.append(f"{gap_ct} path(s) below threshold")
        if not recs:
            recs.append("Cloud escalation path engine healthy")
        return EscalationPathReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_ct,
            avg_score=avg,
            by_escalation_type=by_e1,
            by_permission_risk=by_e2,
            by_complexity=by_e3,
            top_gaps=[],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.escalation_type.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "escalation_type_dist": dist,
            "unique_providers": len({r.cloud_provider for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("cloud_escalation_path.cleared")
        return {"status": "cleared"}
