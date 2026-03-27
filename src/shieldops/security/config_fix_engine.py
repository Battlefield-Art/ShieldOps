"""Config Fix Engine — generate and track fixes."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class FixCategory(StrEnum):
    NETWORK = "network"
    IAM = "iam"
    ENCRYPTION = "encryption"
    LOGGING = "logging"
    STORAGE = "storage"


class FixOutcome(StrEnum):
    APPLIED = "applied"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"
    PENDING = "pending"


class ComplianceMapping(StrEnum):
    CIS = "cis"
    NIST = "nist"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"


# --- Models ---


class ConfigFixRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_id: str = ""
    category: FixCategory = FixCategory.NETWORK
    outcome: FixOutcome = FixOutcome.PENDING
    compliance: ComplianceMapping = ComplianceMapping.CIS
    fix_description: str = ""
    risk_score: float = 0.0
    safe: bool = True
    created_at: float = Field(default_factory=time.time)


class ConfigFixAnalysis(BaseModel):
    resource_id: str = ""
    total_fixes: int = 0
    applied_count: int = 0
    failed_count: int = 0
    compliance_coverage: dict[str, int] = Field(default_factory=dict)
    avg_risk: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class ConfigFixReport(BaseModel):
    total_fixes: int = 0
    applied_rate_pct: float = 0.0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    unsafe_fixes: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ConfigFixEngine:
    """Generate, validate, and track config fixes."""

    def __init__(self, max_records: int = 10000) -> None:
        self._max = max_records
        self._records: list[ConfigFixRecord] = []
        logger.info(
            "config_fix_engine.init",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> ConfigFixRecord:
        rec = ConfigFixRecord(**kwargs)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "config_fix_engine.recorded",
            record_id=rec.id,
        )
        return rec

    def process(self, resource_id: str) -> ConfigFixAnalysis:
        recs = [r for r in self._records if r.resource_id == resource_id]
        if not recs:
            return ConfigFixAnalysis(resource_id=resource_id)
        applied = sum(1 for r in recs if r.outcome == FixOutcome.APPLIED)
        failed = sum(1 for r in recs if r.outcome == FixOutcome.FAILED)
        comp: dict[str, int] = {}
        for r in recs:
            c = r.compliance.value
            comp[c] = comp.get(c, 0) + 1
        risks = [r.risk_score for r in recs]
        avg_r = round(sum(risks) / len(risks), 2) if risks else 0.0
        return ConfigFixAnalysis(
            resource_id=resource_id,
            total_fixes=len(recs),
            applied_count=applied,
            failed_count=failed,
            compliance_coverage=comp,
            avg_risk=avg_r,
        )

    def generate_report(self) -> ConfigFixReport:
        by_cat: dict[str, int] = {}
        by_out: dict[str, int] = {}
        for r in self._records:
            c = r.category.value
            by_cat[c] = by_cat.get(c, 0) + 1
            o = r.outcome.value
            by_out[o] = by_out.get(o, 0) + 1
        total = len(self._records)
        applied = sum(1 for r in self._records if r.outcome == FixOutcome.APPLIED)
        unsafe = sum(1 for r in self._records if not r.safe)
        rate = round(applied / total * 100, 2) if total else 0.0
        recs: list[str] = []
        if unsafe > 0:
            recs.append(f"{unsafe} unsafe fix(es) detected")
        if rate < 80:
            recs.append("Applied rate below 80% target")
        if not recs:
            recs.append("Config fixes on track")
        return ConfigFixReport(
            total_fixes=total,
            applied_rate_pct=rate,
            by_category=by_cat,
            by_outcome=by_out,
            unsafe_fixes=unsafe,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max,
            "unique_resources": len({r.resource_id for r in self._records}),
        }

    def clear_data(self) -> None:
        self._records.clear()
        logger.info("config_fix_engine.cleared")

    # -- domain methods --

    def generate_fix(
        self,
        resource_id: str,
        category: FixCategory,
        compliance: ComplianceMapping,
        fix_description: str = "",
        risk_score: float = 0.0,
    ) -> ConfigFixRecord:
        """Generate a config fix recommendation."""
        safe = risk_score < 0.7
        return self.add_record(
            resource_id=resource_id,
            category=category,
            compliance=compliance,
            fix_description=fix_description,
            risk_score=risk_score,
            safe=safe,
        )

    def validate_fix_safety(self, record_id: str) -> dict[str, Any]:
        """Validate whether a fix is safe."""
        for r in self._records:
            if r.id == record_id:
                return {
                    "found": True,
                    "record_id": record_id,
                    "safe": r.safe,
                    "risk_score": r.risk_score,
                    "category": r.category.value,
                }
        return {
            "found": False,
            "record_id": record_id,
        }

    def track_fix_effectiveness(
        self,
    ) -> dict[str, Any]:
        """Measure fix effectiveness by category."""
        cats: dict[str, dict[str, int]] = {}
        for r in self._records:
            c = r.category.value
            cats.setdefault(c, {"applied": 0, "total": 0})
            cats[c]["total"] += 1
            if r.outcome == FixOutcome.APPLIED:
                cats[c]["applied"] += 1
        result: dict[str, Any] = {}
        for cat, counts in cats.items():
            t = counts["total"]
            a = counts["applied"]
            result[cat] = {
                "total": t,
                "applied": a,
                "rate_pct": (round(a / t * 100, 2) if t else 0.0),
            }
        return result
