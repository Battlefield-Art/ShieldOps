"""Collector Config Drift Engine —
detect fleet config drift, classify drift impact,
generate remediation patches."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DriftType(StrEnum):
    RECEIVER_MISMATCH = "receiver_mismatch"
    PROCESSOR_MISMATCH = "processor_mismatch"
    EXPORTER_MISMATCH = "exporter_mismatch"
    RESOURCE_LIMIT_DRIFT = "resource_limit_drift"


class DriftSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ConfigSource(StrEnum):
    HELM_VALUES = "helm_values"
    CONFIGMAP = "configmap"
    ENV_OVERRIDE = "env_override"
    DEFAULT = "default"


# --- Models ---


class CollectorConfigDriftRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    collector_id: str = ""
    drift_type: DriftType = DriftType.RECEIVER_MISMATCH
    drift_severity: DriftSeverity = DriftSeverity.LOW
    config_source: ConfigSource = ConfigSource.CONFIGMAP
    drift_field: str = ""
    expected_value: str = ""
    actual_value: str = ""
    drift_age_hours: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CollectorConfigDriftAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    collector_id: str = ""
    drift_type: DriftType = DriftType.RECEIVER_MISMATCH
    drift_severity: DriftSeverity = DriftSeverity.LOW
    impact_score: float = 0.0
    patch_required: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CollectorConfigDriftReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    by_drift_type: dict[str, int] = Field(default_factory=dict)
    by_drift_severity: dict[str, int] = Field(default_factory=dict)
    by_config_source: dict[str, int] = Field(default_factory=dict)
    drifted_collectors: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class CollectorConfigDriftEngine:
    """Detect fleet config drift, classify drift impact,
    generate remediation patches."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[CollectorConfigDriftRecord] = []
        self._analyses: dict[str, CollectorConfigDriftAnalysis] = {}
        logger.info("collector_config_drift_engine.init", max_records=max_records)

    def add_record(
        self,
        collector_id: str = "",
        drift_type: DriftType = DriftType.RECEIVER_MISMATCH,
        drift_severity: DriftSeverity = DriftSeverity.LOW,
        config_source: ConfigSource = ConfigSource.CONFIGMAP,
        drift_field: str = "",
        expected_value: str = "",
        actual_value: str = "",
        drift_age_hours: float = 0.0,
        description: str = "",
    ) -> CollectorConfigDriftRecord:
        record = CollectorConfigDriftRecord(
            collector_id=collector_id,
            drift_type=drift_type,
            drift_severity=drift_severity,
            config_source=config_source,
            drift_field=drift_field,
            expected_value=expected_value,
            actual_value=actual_value,
            drift_age_hours=drift_age_hours,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "collector_config_drift.record_added",
            record_id=record.id,
            collector_id=collector_id,
        )
        return record

    def process(self, key: str) -> CollectorConfigDriftAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        severity_weights = {
            DriftSeverity.CRITICAL: 4.0,
            DriftSeverity.HIGH: 3.0,
            DriftSeverity.MEDIUM: 2.0,
            DriftSeverity.LOW: 1.0,
        }
        age_factor = min(rec.drift_age_hours / 24.0, 5.0)
        impact_score = round(
            severity_weights.get(rec.drift_severity, 1.0) * 20.0 + age_factor * 4.0,
            2,
        )
        patch_required = rec.drift_severity in (DriftSeverity.CRITICAL, DriftSeverity.HIGH)
        analysis = CollectorConfigDriftAnalysis(
            collector_id=rec.collector_id,
            drift_type=rec.drift_type,
            drift_severity=rec.drift_severity,
            impact_score=impact_score,
            patch_required=patch_required,
            description=(f"Collector {rec.collector_id} drift impact {impact_score:.1f}"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> CollectorConfigDriftReport:
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_source: dict[str, int] = {}
        drifted: list[str] = []
        for r in self._records:
            kt = r.drift_type.value
            by_type[kt] = by_type.get(kt, 0) + 1
            ks = r.drift_severity.value
            by_severity[ks] = by_severity.get(ks, 0) + 1
            kc = r.config_source.value
            by_source[kc] = by_source.get(kc, 0) + 1
            if (
                r.drift_severity in (DriftSeverity.CRITICAL, DriftSeverity.HIGH)
                and r.collector_id not in drifted
            ):
                drifted.append(r.collector_id)
        recs: list[str] = []
        critical_count = by_severity.get("critical", 0)
        if critical_count > 0:
            recs.append(
                f"{critical_count} critical config drift records — immediate patching required"
            )
        if drifted:
            recs.append(f"{len(drifted)} collectors require config remediation")
        if not recs:
            recs.append("Collector fleet configuration is consistent")
        return CollectorConfigDriftReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            by_drift_type=by_type,
            by_drift_severity=by_severity,
            by_config_source=by_source,
            drifted_collectors=drifted[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        severity_dist: dict[str, int] = {}
        for r in self._records:
            k = r.drift_severity.value
            severity_dist[k] = severity_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "severity_distribution": severity_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("collector_config_drift_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def detect_fleet_config_drift(self) -> list[dict[str, Any]]:
        """Summarize drift across the entire collector fleet."""
        collector_data: dict[str, list[CollectorConfigDriftRecord]] = {}
        for r in self._records:
            collector_data.setdefault(r.collector_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, recs in collector_data.items():
            drift_count = len(recs)
            critical_drifts = sum(1 for r in recs if r.drift_severity == DriftSeverity.CRITICAL)
            avg_age = sum(r.drift_age_hours for r in recs) / len(recs)
            results.append(
                {
                    "collector_id": cid,
                    "drift_count": drift_count,
                    "critical_drifts": critical_drifts,
                    "avg_drift_age_hours": round(avg_age, 2),
                    "drift_types": list({r.drift_type.value for r in recs}),
                }
            )
        results.sort(key=lambda x: x["critical_drifts"], reverse=True)
        return results

    def classify_drift_impact(self) -> list[dict[str, Any]]:
        """Classify each drift record by operational impact."""
        results: list[dict[str, Any]] = []
        severity_weights = {
            DriftSeverity.CRITICAL: 4.0,
            DriftSeverity.HIGH: 3.0,
            DriftSeverity.MEDIUM: 2.0,
            DriftSeverity.LOW: 1.0,
        }
        for r in self._records:
            age_factor = min(r.drift_age_hours / 24.0, 5.0)
            impact = round(
                severity_weights.get(r.drift_severity, 1.0) * 20.0 + age_factor * 4.0,
                2,
            )
            results.append(
                {
                    "record_id": r.id,
                    "collector_id": r.collector_id,
                    "drift_type": r.drift_type.value,
                    "drift_severity": r.drift_severity.value,
                    "drift_field": r.drift_field,
                    "impact_score": impact,
                    "patch_required": r.drift_severity
                    in (DriftSeverity.CRITICAL, DriftSeverity.HIGH),
                }
            )
        results.sort(key=lambda x: x["impact_score"], reverse=True)
        return results

    def generate_remediation_patches(self) -> list[dict[str, Any]]:
        """Generate remediation patch instructions per collector."""
        collector_data: dict[str, list[CollectorConfigDriftRecord]] = {}
        for r in self._records:
            if r.drift_severity in (DriftSeverity.CRITICAL, DriftSeverity.HIGH):
                collector_data.setdefault(r.collector_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, recs in collector_data.items():
            patches = [
                {
                    "field": r.drift_field,
                    "drift_type": r.drift_type.value,
                    "expected": r.expected_value,
                    "actual": r.actual_value,
                    "config_source": r.config_source.value,
                }
                for r in recs
            ]
            results.append(
                {
                    "collector_id": cid,
                    "patch_count": len(patches),
                    "patches": patches,
                    "priority": "immediate"
                    if any(r.drift_severity == DriftSeverity.CRITICAL for r in recs)
                    else "high",
                }
            )
        results.sort(key=lambda x: x["patch_count"], reverse=True)
        return results
