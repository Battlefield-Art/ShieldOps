"""OtelExtensionManagerEngine — Manage OTel Collector extensions."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ExtensionType(StrEnum):
    HEALTH_CHECK = "health_check"
    PPROF = "pprof"
    ZPAGES = "zpages"
    BEARERTOKENAUTH = "bearertokenauth"
    OAUTH2CLIENT = "oauth2client"


class ExtensionStatus(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"


class ExtensionPriority(StrEnum):
    REQUIRED = "required"
    RECOMMENDED = "recommended"
    OPTIONAL = "optional"


# --- Models ---


class OtelExtensionManagerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    extension_type: ExtensionType = ExtensionType.HEALTH_CHECK
    extension_status: ExtensionStatus = ExtensionStatus.ENABLED
    extension_priority: ExtensionPriority = ExtensionPriority.REQUIRED
    score: float = 0.0
    config_valid: bool = True
    port: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelExtensionManagerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    extension_type: ExtensionType = ExtensionType.HEALTH_CHECK
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelExtensionManagerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_extension_type: dict[str, int] = Field(default_factory=dict)
    by_extension_status: dict[str, int] = Field(default_factory=dict)
    by_extension_priority: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OtelExtensionManagerEngine:
    """Manage OTel Collector extensions (health_check, pprof, zpages, auth)."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[OtelExtensionManagerRecord] = []
        self._analyses: list[OtelExtensionManagerAnalysis] = []
        logger.info(
            "otel_extension_manager_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        extension_type: ExtensionType = ExtensionType.HEALTH_CHECK,
        extension_status: ExtensionStatus = ExtensionStatus.ENABLED,
        extension_priority: ExtensionPriority = ExtensionPriority.REQUIRED,
        score: float = 0.0,
        config_valid: bool = True,
        port: int = 0,
        service: str = "",
        team: str = "",
    ) -> OtelExtensionManagerRecord:
        record = OtelExtensionManagerRecord(
            name=name,
            extension_type=extension_type,
            extension_status=extension_status,
            extension_priority=extension_priority,
            score=score,
            config_valid=config_valid,
            port=port,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel_extension_manager_engine.record_added",
            record_id=record.id,
            name=name,
            extension_type=extension_type.value,
            extension_status=extension_status.value,
        )
        return record

    def get_record(self, record_id: str) -> OtelExtensionManagerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        extension_type: ExtensionType | None = None,
        extension_status: ExtensionStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[OtelExtensionManagerRecord]:
        results = list(self._records)
        if extension_type is not None:
            results = [r for r in results if r.extension_type == extension_type]
        if extension_status is not None:
            results = [r for r in results if r.extension_status == extension_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        extension_type: ExtensionType = ExtensionType.HEALTH_CHECK,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> OtelExtensionManagerAnalysis:
        analysis = OtelExtensionManagerAnalysis(
            name=name,
            extension_type=extension_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "otel_extension_manager_engine.analysis_added",
            name=name,
            extension_type=extension_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def audit_extension_coverage(self) -> list[dict[str, Any]]:
        """Audit which extensions are enabled/disabled per service."""
        svc_extensions: dict[str, dict[str, str]] = {}
        for r in self._records:
            svc_extensions.setdefault(r.service, {})
            svc_extensions[r.service][r.extension_type.value] = r.extension_status.value
        results: list[dict[str, Any]] = []
        all_types = {t.value for t in ExtensionType}
        for svc, exts in svc_extensions.items():
            covered = {k for k, v in exts.items() if v == "enabled"}
            missing = all_types - set(exts.keys())
            disabled = {k for k, v in exts.items() if v == "disabled"}
            coverage_pct = round(len(covered) / len(all_types) * 100, 1)
            results.append(
                {
                    "service": svc,
                    "enabled": sorted(covered),
                    "disabled": sorted(disabled),
                    "missing": sorted(missing),
                    "coverage_pct": coverage_pct,
                }
            )
        return sorted(results, key=lambda x: x["coverage_pct"])

    def detect_missing_extensions(self) -> list[dict[str, Any]]:
        """Detect required extensions that are missing or disabled."""
        svc_required: dict[str, list[dict[str, Any]]] = {}
        for r in self._records:
            if r.extension_priority == ExtensionPriority.REQUIRED:
                if r.extension_status != ExtensionStatus.ENABLED:
                    svc_required.setdefault(r.service, []).append(
                        {
                            "extension": r.extension_type.value,
                            "status": r.extension_status.value,
                            "record_id": r.id,
                        }
                    )
        results: list[dict[str, Any]] = []
        for svc, issues in svc_required.items():
            results.append(
                {
                    "service": svc,
                    "missing_required": issues,
                    "count": len(issues),
                    "severity": "critical" if len(issues) > 1 else "high",
                }
            )
        return sorted(results, key=lambda x: x["count"], reverse=True)

    def recommend_extension_config(self) -> list[dict[str, Any]]:
        """Recommend extension configuration improvements."""
        recommendations: list[dict[str, Any]] = []
        error_exts = [r for r in self._records if r.extension_status == ExtensionStatus.ERROR]
        for r in error_exts:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "issue": "extension_error",
                    "priority": "critical",
                    "suggestion": f"Fix error in {r.extension_type.value} extension",
                }
            )
        disabled_required = [
            r
            for r in self._records
            if r.extension_status == ExtensionStatus.DISABLED
            and r.extension_priority == ExtensionPriority.REQUIRED
        ]
        for r in disabled_required:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "issue": "required_disabled",
                    "priority": "high",
                    "suggestion": f"Enable required extension {r.extension_type.value}",
                }
            )
        low_score = [
            r
            for r in self._records
            if r.score < self._threshold and r.extension_status == ExtensionStatus.ENABLED
        ]
        for r in low_score:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "issue": "low_score",
                    "priority": "medium",
                    "suggestion": f"Improve extension config (score: {r.score})",
                }
            )
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        return sorted(recommendations, key=lambda x: priority_order.get(x["priority"], 3))

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.extension_type.value
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
                        "extension_type": r.extension_type.value,
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

    def generate_report(self) -> OtelExtensionManagerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.extension_type.value] = by_e1.get(r.extension_type.value, 0) + 1
            by_e2[r.extension_status.value] = by_e2.get(r.extension_status.value, 0) + 1
            by_e3[r.extension_priority.value] = by_e3.get(r.extension_priority.value, 0) + 1
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
            recs.append("OTel Extension Manager Engine is healthy")
        return OtelExtensionManagerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_extension_type=by_e1,
            by_extension_status=by_e2,
            by_extension_priority=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel_extension_manager_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.extension_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "extension_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
