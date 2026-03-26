"""CNAPP Risk Unifier — unify CSPM+CWPP+CIEM+code security risk scores."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CNAPPDomain(StrEnum):
    CSPM = "cspm"
    CWPP = "cwpp"
    CIEM = "ciem"
    CODE_SECURITY = "code_security"
    DATA_SECURITY = "data_security"


class RiskWeight(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class UnificationMethod(StrEnum):
    WEIGHTED_AVERAGE = "weighted_average"
    MAX_SEVERITY = "max_severity"
    MULTIPLICATIVE = "multiplicative"


# --- Models ---


class CNAPPRiskRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    cnapp_domain: CNAPPDomain = CNAPPDomain.CSPM
    risk_weight: RiskWeight = RiskWeight.MEDIUM
    unification_method: UnificationMethod = UnificationMethod.WEIGHTED_AVERAGE
    score: float = 0.0
    finding_count: int = 0
    resource_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CNAPPRiskAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    cnapp_domain: CNAPPDomain = CNAPPDomain.CSPM
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CNAPPRiskReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_cnapp_domain: dict[str, int] = Field(default_factory=dict)
    by_risk_weight: dict[str, int] = Field(default_factory=dict)
    by_unification_method: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CNAPPRiskUnifierEngine:
    """Unify CSPM+CWPP+CIEM+code security risk."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[CNAPPRiskRecord] = []
        self._analyses: list[CNAPPRiskAnalysis] = []
        logger.info(
            "cnapp_risk_unifier.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ---

    def add_record(
        self,
        name: str,
        cnapp_domain: CNAPPDomain = (CNAPPDomain.CSPM),
        risk_weight: RiskWeight = RiskWeight.MEDIUM,
        unification_method: UnificationMethod = (UnificationMethod.WEIGHTED_AVERAGE),
        score: float = 0.0,
        finding_count: int = 0,
        resource_id: str = "",
        service: str = "",
        team: str = "",
    ) -> CNAPPRiskRecord:
        record = CNAPPRiskRecord(
            name=name,
            cnapp_domain=cnapp_domain,
            risk_weight=risk_weight,
            unification_method=unification_method,
            score=score,
            finding_count=finding_count,
            resource_id=resource_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "cnapp_risk_unifier.record_added",
            record_id=record.id,
            name=name,
            cnapp_domain=cnapp_domain.value,
        )
        return record

    def get_record(self, record_id: str) -> CNAPPRiskRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        cnapp_domain: CNAPPDomain | None = None,
        risk_weight: RiskWeight | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CNAPPRiskRecord]:
        results = list(self._records)
        if cnapp_domain is not None:
            results = [r for r in results if r.cnapp_domain == cnapp_domain]
        if risk_weight is not None:
            results = [r for r in results if r.risk_weight == risk_weight]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        cnapp_domain: CNAPPDomain = (CNAPPDomain.CSPM),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CNAPPRiskAnalysis:
        analysis = CNAPPRiskAnalysis(
            name=name,
            cnapp_domain=cnapp_domain,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "cnapp_risk_unifier.analysis_added",
            name=name,
            cnapp_domain=cnapp_domain.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ---

    _WEIGHT_MAP = {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.5,
        "low": 0.2,
        "negligible": 0.05,
    }

    def unify_risk_scores(
        self,
    ) -> list[dict[str, Any]]:
        """Unify risk scores across CNAPP domains."""
        resource_data: dict[str, list[CNAPPRiskRecord]] = {}
        for r in self._records:
            if r.resource_id:
                resource_data.setdefault(r.resource_id, []).append(r)
        results: list[dict[str, Any]] = []
        for rid, records in resource_data.items():
            weighted_sum = 0.0
            weight_total = 0.0
            max_score = 0.0
            for r in records:
                w = self._WEIGHT_MAP.get(r.risk_weight.value, 0.5)
                weighted_sum += r.score * w
                weight_total += w
                if r.score > max_score:
                    max_score = r.score
            unified = round(weighted_sum / weight_total, 2) if weight_total else 0.0
            domains = {r.cnapp_domain.value for r in records}
            results.append(
                {
                    "resource_id": rid,
                    "unified_score": unified,
                    "max_score": max_score,
                    "domains": sorted(domains),
                    "domain_count": len(domains),
                    "finding_count": sum(r.finding_count for r in records),
                }
            )
        return sorted(
            results,
            key=lambda x: x["unified_score"],
            reverse=True,
        )

    def calculate_domain_coverage(
        self,
    ) -> dict[str, Any]:
        """Calculate coverage across CNAPP domains."""
        domain_ct: dict[str, int] = {}
        for r in self._records:
            d = r.cnapp_domain.value
            domain_ct[d] = domain_ct.get(d, 0) + 1
        total_domains = len(CNAPPDomain)
        covered = len(domain_ct)
        return {
            "coverage_pct": round(covered / total_domains * 100, 1),
            "covered_domains": covered,
            "total_domains": total_domains,
            "domain_counts": domain_ct,
            "missing": [d.value for d in CNAPPDomain if d.value not in domain_ct],
        }

    def identify_cross_domain_risks(
        self,
    ) -> list[dict[str, Any]]:
        """Identify risks spanning multiple domains."""
        resource_data: dict[str, list[CNAPPRiskRecord]] = {}
        for r in self._records:
            if r.resource_id:
                resource_data.setdefault(r.resource_id, []).append(r)
        cross: list[dict[str, Any]] = []
        for rid, records in resource_data.items():
            domains = {r.cnapp_domain for r in records}
            if len(domains) >= 2:
                avg_score = round(
                    sum(r.score for r in records) / len(records),
                    2,
                )
                cross.append(
                    {
                        "resource_id": rid,
                        "domains": sorted(d.value for d in domains),
                        "domain_count": len(domains),
                        "avg_score": avg_score,
                        "risk": (
                            "critical"
                            if len(domains) >= 4
                            else ("high" if len(domains) >= 3 else "medium")
                        ),
                    }
                )
        return sorted(
            cross,
            key=lambda x: x["domain_count"],
            reverse=True,
        )

    # -- standard methods ---

    def analyze_distribution(
        self,
    ) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.cnapp_domain.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "cnapp_domain": (r.cnapp_domain.value),
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc: dict[str, list[float]] = {}
        for r in self._records:
            svc.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for s, scores in svc.items():
            results.append(
                {
                    "service": s,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

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
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats ---

    def generate_report(self) -> CNAPPRiskReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            k1 = r.cnapp_domain.value
            by_e1[k1] = by_e1.get(k1, 0) + 1
            k2 = r.risk_weight.value
            by_e2[k2] = by_e2.get(k2, 0) + 1
            k3 = r.unification_method.value
            by_e3[k3] = by_e3.get(k3, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("CNAPP Risk Unifier is healthy")
        return CNAPPRiskReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_cnapp_domain=by_e1,
            by_risk_weight=by_e2,
            by_unification_method=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("cnapp_risk_unifier.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.cnapp_domain.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "cnapp_domain_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
