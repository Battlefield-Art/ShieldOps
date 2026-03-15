"""OtelSemanticValidationEngine — Validate OTel semantic conventions compliance."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SemanticScope(StrEnum):
    RESOURCE = "resource"
    SPAN = "span"
    METRIC = "metric"
    LOG = "log"


class ComplianceLevel(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"


class FixComplexity(StrEnum):
    TRIVIAL = "trivial"
    MODERATE = "moderate"
    COMPLEX = "complex"


# --- Models ---


class OtelSemanticValidationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    semantic_scope: SemanticScope = SemanticScope.RESOURCE
    compliance_level: ComplianceLevel = ComplianceLevel.FULL
    fix_complexity: FixComplexity = FixComplexity.TRIVIAL
    score: float = 0.0
    violation_count: int = 0
    attribute_name: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelSemanticValidationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    semantic_scope: SemanticScope = SemanticScope.RESOURCE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelSemanticValidationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_semantic_scope: dict[str, int] = Field(default_factory=dict)
    by_compliance_level: dict[str, int] = Field(default_factory=dict)
    by_fix_complexity: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OtelSemanticValidationEngine:
    """Validate OTel semantic conventions compliance across services."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[OtelSemanticValidationRecord] = []
        self._analyses: list[OtelSemanticValidationAnalysis] = []
        logger.info(
            "otel_semantic_validation_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        semantic_scope: SemanticScope = SemanticScope.RESOURCE,
        compliance_level: ComplianceLevel = ComplianceLevel.FULL,
        fix_complexity: FixComplexity = FixComplexity.TRIVIAL,
        score: float = 0.0,
        violation_count: int = 0,
        attribute_name: str = "",
        service: str = "",
        team: str = "",
    ) -> OtelSemanticValidationRecord:
        record = OtelSemanticValidationRecord(
            name=name,
            semantic_scope=semantic_scope,
            compliance_level=compliance_level,
            fix_complexity=fix_complexity,
            score=score,
            violation_count=violation_count,
            attribute_name=attribute_name,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel_semantic_validation_engine.record_added",
            record_id=record.id,
            name=name,
            semantic_scope=semantic_scope.value,
            compliance_level=compliance_level.value,
        )
        return record

    def get_record(self, record_id: str) -> OtelSemanticValidationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        semantic_scope: SemanticScope | None = None,
        compliance_level: ComplianceLevel | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[OtelSemanticValidationRecord]:
        results = list(self._records)
        if semantic_scope is not None:
            results = [r for r in results if r.semantic_scope == semantic_scope]
        if compliance_level is not None:
            results = [r for r in results if r.compliance_level == compliance_level]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        semantic_scope: SemanticScope = SemanticScope.RESOURCE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> OtelSemanticValidationAnalysis:
        analysis = OtelSemanticValidationAnalysis(
            name=name,
            semantic_scope=semantic_scope,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "otel_semantic_validation_engine.analysis_added",
            name=name,
            semantic_scope=semantic_scope.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_convention_compliance(self) -> list[dict[str, Any]]:
        """Compute semantic convention compliance per service."""
        svc_data: dict[str, list[OtelSemanticValidationRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            full = sum(1 for r in records if r.compliance_level == ComplianceLevel.FULL)
            total = len(records)
            compliance_pct = round(full / total * 100, 1) if total else 0.0
            results.append(
                {
                    "service": svc,
                    "total_attributes": total,
                    "fully_compliant": full,
                    "compliance_pct": compliance_pct,
                    "avg_score": round(sum(r.score for r in records) / total, 2),
                }
            )
        return sorted(results, key=lambda x: x["compliance_pct"])

    def identify_naming_violations(self) -> list[dict[str, Any]]:
        """Identify attributes that violate OTel naming conventions."""
        violations: list[dict[str, Any]] = []
        for r in self._records:
            if r.compliance_level != ComplianceLevel.FULL:
                violations.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "attribute_name": r.attribute_name,
                        "service": r.service,
                        "semantic_scope": r.semantic_scope.value,
                        "compliance_level": r.compliance_level.value,
                        "violation_count": r.violation_count,
                    }
                )
        return sorted(violations, key=lambda x: x["violation_count"], reverse=True)

    def recommend_attribute_fixes(self) -> list[dict[str, Any]]:
        """Recommend fixes for non-compliant attributes."""
        recommendations: list[dict[str, Any]] = []
        non_compliant = [r for r in self._records if r.compliance_level != ComplianceLevel.FULL]
        for r in non_compliant:
            priority = (
                "high"
                if r.fix_complexity == FixComplexity.TRIVIAL
                else ("medium" if r.fix_complexity == FixComplexity.MODERATE else "low")
            )
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "attribute_name": r.attribute_name,
                    "service": r.service,
                    "fix_complexity": r.fix_complexity.value,
                    "priority": priority,
                    "suggestion": (
                        f"Fix {r.semantic_scope.value} attribute '{r.attribute_name}' "
                        f"to match OTel conventions"
                    ),
                }
            )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else (1 if x["priority"] == "medium" else 2),
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.semantic_scope.value
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
                        "semantic_scope": r.semantic_scope.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> OtelSemanticValidationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.semantic_scope.value] = by_e1.get(r.semantic_scope.value, 0) + 1
            by_e2[r.compliance_level.value] = by_e2.get(r.compliance_level.value, 0) + 1
            by_e3[r.fix_complexity.value] = by_e3.get(r.fix_complexity.value, 0) + 1
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
            recs.append("OTel Semantic Validation Engine is healthy")
        return OtelSemanticValidationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_semantic_scope=by_e1,
            by_compliance_level=by_e2,
            by_fix_complexity=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel_semantic_validation_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.semantic_scope.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "semantic_scope_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
