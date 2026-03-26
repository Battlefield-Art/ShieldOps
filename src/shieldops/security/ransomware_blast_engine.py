"""Ransomware Blast Engine — propagation modeling and containment analysis."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RadiusScope(StrEnum):
    SINGLE_HOST = "single_host"
    SUBNET = "subnet"
    SITE = "site"
    MULTI_SITE = "multi_site"
    ENTERPRISE_WIDE = "enterprise_wide"


class PropagationVector(StrEnum):
    SMB_LATERAL = "smb_lateral"
    RDP_EXPLOIT = "rdp_exploit"
    EMAIL_PHISH = "email_phish"
    SUPPLY_CHAIN = "supply_chain"
    UNKNOWN = "unknown"


class ContainmentFeasibility(StrEnum):
    TRIVIAL = "trivial"
    MODERATE = "moderate"
    DIFFICULT = "difficult"
    CRITICAL = "critical"
    INFEASIBLE = "infeasible"


# --- Models ---


class BlastRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    blast_name: str = ""
    radius_scope: RadiusScope = RadiusScope.SINGLE_HOST
    propagation_vector: PropagationVector = PropagationVector.UNKNOWN
    containment_feasibility: ContainmentFeasibility = ContainmentFeasibility.MODERATE
    blast_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class BlastAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    blast_name: str = ""
    radius_scope: RadiusScope = RadiusScope.SINGLE_HOST
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class BlastReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    critical_count: int = 0
    avg_blast_score: float = 0.0
    by_scope: dict[str, int] = Field(default_factory=dict)
    by_vector: dict[str, int] = Field(default_factory=dict)
    by_feasibility: dict[str, int] = Field(default_factory=dict)
    top_critical: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class RansomwareBlastEngine:
    """Ransomware blast radius modeling and containment analysis."""

    def __init__(
        self,
        max_records: int = 200000,
        blast_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._blast_threshold = blast_threshold
        self._records: list[BlastRecord] = []
        self._analyses: list[BlastAnalysis] = []
        logger.info(
            "ransomware_blast.initialized",
            max_records=max_records,
            blast_threshold=blast_threshold,
        )

    # -- record / get / list ----------------------------

    def add_record(
        self,
        blast_name: str,
        radius_scope: RadiusScope = (RadiusScope.SINGLE_HOST),
        propagation_vector: PropagationVector = (PropagationVector.UNKNOWN),
        containment_feasibility: ContainmentFeasibility = (ContainmentFeasibility.MODERATE),
        blast_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> BlastRecord:
        record = BlastRecord(
            blast_name=blast_name,
            radius_scope=radius_scope,
            propagation_vector=propagation_vector,
            containment_feasibility=containment_feasibility,
            blast_score=blast_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ransomware_blast.record_added",
            record_id=record.id,
            blast_name=blast_name,
            radius_scope=radius_scope.value,
        )
        return record

    def get_record(self, record_id: str) -> BlastRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        radius_scope: RadiusScope | None = None,
        propagation_vector: PropagationVector | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[BlastRecord]:
        results = list(self._records)
        if radius_scope is not None:
            results = [r for r in results if r.radius_scope == radius_scope]
        if propagation_vector is not None:
            results = [r for r in results if r.propagation_vector == propagation_vector]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        blast_name: str,
        radius_scope: RadiusScope = (RadiusScope.SINGLE_HOST),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> BlastAnalysis:
        analysis = BlastAnalysis(
            blast_name=blast_name,
            radius_scope=radius_scope,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "ransomware_blast.analysis_added",
            blast_name=blast_name,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ------------------------------

    def model_propagation(self) -> dict[str, Any]:
        """Group by propagation_vector; return count and avg blast_score."""
        vec_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.propagation_vector.value
            vec_data.setdefault(key, []).append(r.blast_score)
        result: dict[str, Any] = {}
        for vec, scores in vec_data.items():
            result[vec] = {
                "count": len(scores),
                "avg_blast_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def estimate_data_at_risk(
        self,
    ) -> list[dict[str, Any]]:
        """Return records with blast_score >= threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.blast_score >= self._blast_threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "blast_name": r.blast_name,
                        "radius_scope": (r.radius_scope.value),
                        "blast_score": r.blast_score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["blast_score"],
            reverse=True,
        )

    def identify_containment_points(
        self,
    ) -> list[dict[str, Any]]:
        """Group by service, avg blast_score, sort descending."""
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.blast_score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_blast_score": round(sum(scores) / len(scores), 2),
                    "record_count": len(scores),
                }
            )
        results.sort(
            key=lambda x: x["avg_blast_score"],
            reverse=True,
        )
        return results

    # -- report / stats ---------------------------------

    def generate_report(self) -> BlastReport:
        by_scope: dict[str, int] = {}
        by_vector: dict[str, int] = {}
        by_feasibility: dict[str, int] = {}
        for r in self._records:
            by_scope[r.radius_scope.value] = by_scope.get(r.radius_scope.value, 0) + 1
            by_vector[r.propagation_vector.value] = by_vector.get(r.propagation_vector.value, 0) + 1
            by_feasibility[r.containment_feasibility.value] = (
                by_feasibility.get(r.containment_feasibility.value, 0) + 1
            )
        critical_count = sum(1 for r in self._records if r.blast_score >= self._blast_threshold)
        scores = [r.blast_score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        top = [
            r.blast_name
            for r in sorted(
                self._records,
                key=lambda x: x.blast_score,
                reverse=True,
            )[:5]
        ]
        recs: list[str] = []
        if critical_count > 0:
            recs.append(f"{critical_count} blast zone(s) above threshold ({self._blast_threshold})")
        if not recs:
            recs.append("Blast radius within limits")
        return BlastReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            critical_count=critical_count,
            avg_blast_score=avg,
            by_scope=by_scope,
            by_vector=by_vector,
            by_feasibility=by_feasibility,
            top_critical=top,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("ransomware_blast.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        scope_dist: dict[str, int] = {}
        for r in self._records:
            key = r.radius_scope.value
            scope_dist[key] = scope_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "blast_threshold": self._blast_threshold,
            "scope_distribution": scope_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
