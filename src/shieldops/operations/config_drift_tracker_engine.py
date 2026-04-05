"""Config Drift Tracker Engine — track infrastructure configuration drift."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DriftSource(StrEnum):
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"
    HELM = "helm"
    CLOUD_CONSOLE = "cloud_console"
    CI_CD = "ci_cd"


class DriftCategory(StrEnum):
    SECURITY = "security"
    PERFORMANCE = "performance"
    COMPLIANCE = "compliance"
    OPERATIONAL = "operational"
    COSMETIC = "cosmetic"


class RemediationMethod(StrEnum):
    AUTO_REVERT = "auto_revert"
    MANUAL_FIX = "manual_fix"
    ACCEPT = "accept"
    BASELINE_UPDATE = "baseline_update"
    ESCALATE = "escalate"


# --- Models ---


class ConfigDriftTrackerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_id: str = ""
    service_id: str = ""
    drift_source: DriftSource = DriftSource.KUBERNETES
    drift_category: DriftCategory = DriftCategory.OPERATIONAL
    remediation_method: RemediationMethod = RemediationMethod.MANUAL_FIX
    drift_field: str = ""
    expected_value: str = ""
    actual_value: str = ""
    drift_detected_at: float = 0.0
    remediated_at: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ConfigDriftTrackerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_id: str = ""
    analysis_score: float = 0.0
    drift_source: DriftSource = DriftSource.KUBERNETES
    drift_count: int = 0
    data_points: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ConfigDriftTrackerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_remediation_time: float = 0.0
    by_source: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_remediation: dict[str, int] = Field(default_factory=dict)
    high_drift_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ConfigDriftTrackerEngine:
    """Track infrastructure configuration drift and remediation."""

    def __init__(
        self,
        max_records: int = 200000,
        drift_threshold: float = 5.0,
    ) -> None:
        self._max_records = max_records
        self._drift_threshold = drift_threshold
        self._records: list[ConfigDriftTrackerRecord] = []
        self._analyses: dict[str, ConfigDriftTrackerAnalysis] = {}
        logger.info(
            "config_drift_tracker_engine.init",
            max_records=max_records,
            drift_threshold=drift_threshold,
        )

    def add_record(
        self,
        resource_id: str = "",
        service_id: str = "",
        drift_source: DriftSource = DriftSource.KUBERNETES,
        drift_category: DriftCategory = DriftCategory.OPERATIONAL,
        remediation_method: RemediationMethod = RemediationMethod.MANUAL_FIX,
        drift_field: str = "",
        expected_value: str = "",
        actual_value: str = "",
        drift_detected_at: float = 0.0,
        remediated_at: float = 0.0,
        description: str = "",
    ) -> ConfigDriftTrackerRecord:
        record = ConfigDriftTrackerRecord(
            resource_id=resource_id,
            service_id=service_id,
            drift_source=drift_source,
            drift_category=drift_category,
            remediation_method=remediation_method,
            drift_field=drift_field,
            expected_value=expected_value,
            actual_value=actual_value,
            drift_detected_at=drift_detected_at,
            remediated_at=remediated_at,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "config_drift_tracker_engine.record_added",
            record_id=record.id,
            resource_id=resource_id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> ConfigDriftTrackerAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        res_recs = [r for r in self._records if r.resource_id == rec.resource_id]
        drift_count = len(res_recs)
        score = round(max(0.0, 100.0 - drift_count * 10), 2)
        analysis = ConfigDriftTrackerAnalysis(
            resource_id=rec.resource_id,
            analysis_score=score,
            drift_source=rec.drift_source,
            drift_count=drift_count,
            data_points=drift_count,
            description=(
                f"Config drift score {score} for {rec.resource_id} ({drift_count} drifts)"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ConfigDriftTrackerReport:
        by_s: dict[str, int] = {}
        by_c: dict[str, int] = {}
        by_r: dict[str, int] = {}
        rem_times: list[float] = []
        for r in self._records:
            by_s[r.drift_source.value] = by_s.get(r.drift_source.value, 0) + 1
            by_c[r.drift_category.value] = by_c.get(r.drift_category.value, 0) + 1
            by_r[r.remediation_method.value] = by_r.get(r.remediation_method.value, 0) + 1
            if r.remediated_at > 0 and r.drift_detected_at > 0:
                rem_times.append(r.remediated_at - r.drift_detected_at)
        avg_rem = round(sum(rem_times) / len(rem_times), 2) if rem_times else 0.0
        svc_counts: dict[str, int] = {}
        for r in self._records:
            svc_counts[r.service_id] = svc_counts.get(r.service_id, 0) + 1
        high_drift = [sid for sid, cnt in svc_counts.items() if cnt > self._drift_threshold][:10]
        recs: list[str] = []
        security_drifts = by_c.get(DriftCategory.SECURITY.value, 0)
        if security_drifts:
            recs.append(f"{security_drifts} security-related drifts — remediate")
        if high_drift:
            recs.append(f"{len(high_drift)} services exceeding drift threshold")
        if not recs:
            recs.append("Config drift within acceptable limits")
        return ConfigDriftTrackerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_remediation_time=avg_rem,
            by_source=by_s,
            by_category=by_c,
            by_remediation=by_r,
            high_drift_services=high_drift,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        source_dist: dict[str, int] = {}
        for r in self._records:
            k = r.drift_source.value
            source_dist[k] = source_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "drift_threshold": self._drift_threshold,
            "source_distribution": source_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("config_drift_tracker_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def identify_frequent_drift_fields(self) -> list[dict[str, Any]]:
        """Identify config fields that drift most frequently."""
        field_counts: dict[str, int] = {}
        field_services: dict[str, set[str]] = {}
        for r in self._records:
            if r.drift_field:
                field_counts[r.drift_field] = field_counts.get(r.drift_field, 0) + 1
                field_services.setdefault(r.drift_field, set()).add(r.service_id)
        results: list[dict[str, Any]] = []
        for field, count in field_counts.items():
            results.append(
                {
                    "drift_field": field,
                    "occurrence_count": count,
                    "affected_services": len(field_services[field]),
                }
            )
        results.sort(key=lambda x: x["occurrence_count"], reverse=True)
        return results

    def compute_mttr_by_source(self) -> list[dict[str, Any]]:
        """Compute mean time to remediate per drift source."""
        source_times: dict[str, list[float]] = {}
        for r in self._records:
            if r.remediated_at > 0 and r.drift_detected_at > 0:
                dt = r.remediated_at - r.drift_detected_at
                source_times.setdefault(r.drift_source.value, []).append(dt)
        results: list[dict[str, Any]] = []
        for source, times in source_times.items():
            avg = round(sum(times) / len(times), 2)
            results.append(
                {
                    "drift_source": source,
                    "mttr_seconds": avg,
                    "sample_count": len(times),
                }
            )
        results.sort(key=lambda x: x["mttr_seconds"], reverse=True)
        return results

    def summarize_drift_by_category(self) -> list[dict[str, Any]]:
        """Summarize drift counts and remediation by category."""
        cat_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            k = r.drift_category.value
            cat_data.setdefault(k, {"total": 0, "remediated": 0})
            cat_data[k]["total"] += 1
            if r.remediated_at > 0:
                cat_data[k]["remediated"] += 1
        results: list[dict[str, Any]] = []
        for cat, data in cat_data.items():
            rate = round(data["remediated"] / data["total"] * 100, 2) if data["total"] else 0.0
            results.append(
                {
                    "drift_category": cat,
                    "total_drifts": data["total"],
                    "remediated_count": data["remediated"],
                    "remediation_rate_pct": rate,
                }
            )
        results.sort(key=lambda x: x["total_drifts"], reverse=True)
        return results
