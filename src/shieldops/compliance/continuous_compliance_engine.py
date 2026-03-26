"""Continuous Compliance Engine —
track real-time compliance posture,
monitor control effectiveness, detect regressions."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ScanFrequency(StrEnum):
    REAL_TIME = "real_time"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    ON_CHANGE = "on_change"


class ControlCategory(StrEnum):
    ACCESS = "access"
    ENCRYPTION = "encryption"
    LOGGING = "logging"
    NETWORK = "network"
    DATA_PROTECTION = "data_protection"


class FindingTrend(StrEnum):
    NEW = "new"
    RECURRING = "recurring"
    RESOLVED = "resolved"
    REGRESSED = "regressed"
    STABLE = "stable"


# --- Models ---


class ContinuousComplianceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    control_id: str = ""
    framework: str = ""
    scan_frequency: ScanFrequency = ScanFrequency.DAILY
    control_category: ControlCategory = ControlCategory.ACCESS
    finding_trend: FindingTrend = FindingTrend.STABLE
    is_compliant: bool = True
    severity: str = "low"
    resource_id: str = ""
    remediation_time_hours: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ContinuousComplianceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    control_id: str = ""
    framework: str = ""
    compliance_rate: float = 0.0
    regression_count: int = 0
    avg_remediation_hours: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ContinuousComplianceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    overall_compliance_pct: float = 0.0
    by_scan_frequency: dict[str, int] = Field(default_factory=dict)
    by_control_category: dict[str, int] = Field(default_factory=dict)
    by_finding_trend: dict[str, int] = Field(default_factory=dict)
    regressed_controls: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ContinuousComplianceEngine:
    """Track real-time compliance posture,
    monitor control effectiveness, detect regressions."""

    def __init__(self, max_records: int = 200000, compliance_threshold: float = 95.0) -> None:
        self._max_records = max_records
        self._compliance_threshold = compliance_threshold
        self._records: list[ContinuousComplianceRecord] = []
        self._analyses: dict[str, ContinuousComplianceAnalysis] = {}
        logger.info(
            "continuous_compliance_engine.init",
            max_records=max_records,
            compliance_threshold=compliance_threshold,
        )

    def add_record(
        self,
        control_id: str = "",
        framework: str = "",
        scan_frequency: ScanFrequency = ScanFrequency.DAILY,
        control_category: ControlCategory = ControlCategory.ACCESS,
        finding_trend: FindingTrend = FindingTrend.STABLE,
        is_compliant: bool = True,
        severity: str = "low",
        resource_id: str = "",
        remediation_time_hours: float = 0.0,
        description: str = "",
    ) -> ContinuousComplianceRecord:
        record = ContinuousComplianceRecord(
            control_id=control_id,
            framework=framework,
            scan_frequency=scan_frequency,
            control_category=control_category,
            finding_trend=finding_trend,
            is_compliant=is_compliant,
            severity=severity,
            resource_id=resource_id,
            remediation_time_hours=remediation_time_hours,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "continuous_compliance.record_added",
            record_id=record.id,
            control_id=control_id,
        )
        return record

    def process(self, key: str) -> ContinuousComplianceAnalysis | dict[str, Any]:
        recs = [r for r in self._records if r.control_id == key or r.id == key]
        if not recs:
            return {"status": "not_found", "key": key}
        compliant = sum(1 for r in recs if r.is_compliant)
        compliance_rate = round(compliant / len(recs) * 100, 2)
        regressions = sum(1 for r in recs if r.finding_trend == FindingTrend.REGRESSED)
        rem_hours = [r.remediation_time_hours for r in recs if r.remediation_time_hours > 0]
        avg_rem = round(sum(rem_hours) / len(rem_hours), 2) if rem_hours else 0.0
        analysis = ContinuousComplianceAnalysis(
            control_id=recs[0].control_id,
            framework=recs[0].framework,
            compliance_rate=compliance_rate,
            regression_count=regressions,
            avg_remediation_hours=avg_rem,
            description=(
                f"{recs[0].control_id} compliance={compliance_rate}% regressions={regressions}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ContinuousComplianceReport:
        by_freq: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        by_trend: dict[str, int] = {}
        for r in self._records:
            sf = r.scan_frequency.value
            by_freq[sf] = by_freq.get(sf, 0) + 1
            cc = r.control_category.value
            by_cat[cc] = by_cat.get(cc, 0) + 1
            ft = r.finding_trend.value
            by_trend[ft] = by_trend.get(ft, 0) + 1
        compliant = sum(1 for r in self._records if r.is_compliant)
        total = len(self._records)
        overall = round(compliant / total * 100, 2) if total else 0.0
        regressed = list(
            {r.control_id for r in self._records if r.finding_trend == FindingTrend.REGRESSED}
        )[:10]
        recs: list[str] = []
        if overall < self._compliance_threshold:
            recs.append(
                f"Overall compliance {overall}% below {self._compliance_threshold}% threshold"
            )
        if regressed:
            recs.append(f"{len(regressed)} controls have regressed — investigate root cause")
        if not recs:
            recs.append("Continuous compliance posture within acceptable range")
        return ContinuousComplianceReport(
            total_records=total,
            total_analyses=len(self._analyses),
            overall_compliance_pct=overall,
            by_scan_frequency=by_freq,
            by_control_category=by_cat,
            by_finding_trend=by_trend,
            regressed_controls=regressed,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        trend_dist: dict[str, int] = {}
        for r in self._records:
            k = r.finding_trend.value
            trend_dist[k] = trend_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "trend_distribution": trend_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("continuous_compliance_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def detect_compliance_regressions(self) -> list[dict[str, Any]]:
        """Detect controls that have regressed from compliant to non-compliant."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.finding_trend == FindingTrend.REGRESSED:
                results.append(
                    {
                        "control_id": r.control_id,
                        "framework": r.framework,
                        "control_category": r.control_category.value,
                        "severity": r.severity,
                        "resource_id": r.resource_id,
                        "remediation_time_hours": r.remediation_time_hours,
                    }
                )
        results.sort(key=lambda x: x["severity"])
        return results

    def analyze_framework_coverage(self) -> list[dict[str, Any]]:
        """Analyze compliance coverage per framework."""
        fw_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            fw = r.framework or "unspecified"
            fw_data.setdefault(fw, {"total": 0, "compliant": 0})
            fw_data[fw]["total"] += 1
            if r.is_compliant:
                fw_data[fw]["compliant"] += 1
        results: list[dict[str, Any]] = []
        for fw, data in fw_data.items():
            pct = round(data["compliant"] / data["total"] * 100, 2) if data["total"] > 0 else 0.0
            results.append(
                {
                    "framework": fw,
                    "total_controls": data["total"],
                    "compliant": data["compliant"],
                    "compliance_pct": pct,
                    "below_threshold": pct < self._compliance_threshold,
                }
            )
        results.sort(key=lambda x: x["compliance_pct"])
        return results

    def rank_categories_by_risk(self) -> list[dict[str, Any]]:
        """Rank control categories by non-compliance risk."""
        cat_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            c = r.control_category.value
            cat_data.setdefault(c, {"total": 0, "non_compliant": 0, "regressed": 0})
            cat_data[c]["total"] += 1
            if not r.is_compliant:
                cat_data[c]["non_compliant"] += 1
            if r.finding_trend == FindingTrend.REGRESSED:
                cat_data[c]["regressed"] += 1
        results: list[dict[str, Any]] = []
        for cat, data in cat_data.items():
            risk = (
                round(data["non_compliant"] / data["total"] * 100 + data["regressed"] * 5, 2)
                if data["total"] > 0
                else 0.0
            )
            results.append(
                {
                    "control_category": cat,
                    "total_checks": data["total"],
                    "non_compliant": data["non_compliant"],
                    "regressed": data["regressed"],
                    "risk_score": risk,
                    "rank": 0,
                }
            )
        results.sort(key=lambda x: x["risk_score"], reverse=True)
        for idx, entry in enumerate(results, 1):
            entry["rank"] = idx
        return results
