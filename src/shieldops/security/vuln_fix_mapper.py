"""Vuln Fix Mapper — map vulns to fixes."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class VulnType(StrEnum):
    CVE = "cve"
    MISCONFIGURATION = "misconfiguration"
    DEPENDENCY = "dependency"
    CODE_FLAW = "code_flaw"
    ZERO_DAY = "zero_day"


class FixMethod(StrEnum):
    PATCH = "patch"
    CONFIG_CHANGE = "config_change"
    UPGRADE = "upgrade"
    WORKAROUND = "workaround"
    COMPENSATING_CONTROL = "compensating_control"


class FixAvailability(StrEnum):
    AVAILABLE = "available"
    IN_PROGRESS = "in_progress"
    NOT_AVAILABLE = "not_available"
    VENDOR_PENDING = "vendor_pending"
    END_OF_LIFE = "end_of_life"


# --- Models ---


class VulnFixRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vuln_id: str = ""
    vuln_type: VulnType = VulnType.CVE
    fix_method: FixMethod = FixMethod.PATCH
    availability: FixAvailability = FixAvailability.AVAILABLE
    complexity_score: float = 0.0
    affected_assets: int = 0
    fix_applied: bool = False
    created_at: float = Field(default_factory=time.time)


class VulnFixAnalysis(BaseModel):
    vuln_id: str = ""
    fix_options: int = 0
    best_method: str = ""
    lowest_complexity: float = 0.0
    coverage_pct: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class VulnFixReport(BaseModel):
    total_mappings: int = 0
    coverage_rate_pct: float = 0.0
    by_vuln_type: dict[str, int] = Field(default_factory=dict)
    by_fix_method: dict[str, int] = Field(default_factory=dict)
    unfixed_count: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class VulnFixMapper:
    """Map vulnerabilities to remediation fixes."""

    def __init__(self, max_records: int = 10000) -> None:
        self._max = max_records
        self._records: list[VulnFixRecord] = []
        logger.info(
            "vuln_fix_mapper.init",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> VulnFixRecord:
        rec = VulnFixRecord(**kwargs)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "vuln_fix_mapper.recorded",
            record_id=rec.id,
        )
        return rec

    def process(self, vuln_id: str) -> VulnFixAnalysis:
        recs = [r for r in self._records if r.vuln_id == vuln_id]
        if not recs:
            return VulnFixAnalysis(vuln_id=vuln_id)
        complexities = [r.complexity_score for r in recs]
        lowest = min(complexities)
        best = min(recs, key=lambda r: r.complexity_score)
        applied = sum(1 for r in recs if r.fix_applied)
        cov = round(applied / len(recs) * 100, 2) if recs else 0.0
        return VulnFixAnalysis(
            vuln_id=vuln_id,
            fix_options=len(recs),
            best_method=best.fix_method.value,
            lowest_complexity=lowest,
            coverage_pct=cov,
        )

    def generate_report(self) -> VulnFixReport:
        by_vt: dict[str, int] = {}
        by_fm: dict[str, int] = {}
        for r in self._records:
            v = r.vuln_type.value
            by_vt[v] = by_vt.get(v, 0) + 1
            f = r.fix_method.value
            by_fm[f] = by_fm.get(f, 0) + 1
        total = len(self._records)
        applied = sum(1 for r in self._records if r.fix_applied)
        unfixed = total - applied
        rate = round(applied / total * 100, 2) if total else 0.0
        recs: list[str] = []
        if unfixed > 0:
            recs.append(f"{unfixed} vuln(s) without fix")
        no_fix = sum(1 for r in self._records if r.availability == FixAvailability.NOT_AVAILABLE)
        if no_fix > 0:
            recs.append(f"{no_fix} with no fix available")
        if not recs:
            recs.append("All vulns have fixes")
        return VulnFixReport(
            total_mappings=total,
            coverage_rate_pct=rate,
            by_vuln_type=by_vt,
            by_fix_method=by_fm,
            unfixed_count=unfixed,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max,
            "unique_vulns": len({r.vuln_id for r in self._records}),
        }

    def clear_data(self) -> None:
        self._records.clear()
        logger.info("vuln_fix_mapper.cleared")

    # -- domain methods --

    def map_vuln_to_fix(
        self,
        vuln_id: str,
        vuln_type: VulnType,
        fix_method: FixMethod,
        availability: FixAvailability = (FixAvailability.AVAILABLE),
        complexity_score: float = 0.0,
        affected_assets: int = 0,
    ) -> VulnFixRecord:
        """Map a vulnerability to its fix."""
        return self.add_record(
            vuln_id=vuln_id,
            vuln_type=vuln_type,
            fix_method=fix_method,
            availability=availability,
            complexity_score=complexity_score,
            affected_assets=affected_assets,
        )

    def assess_fix_complexity(self, vuln_id: str) -> dict[str, Any]:
        """Assess complexity of fixing a vuln."""
        recs = [r for r in self._records if r.vuln_id == vuln_id]
        if not recs:
            return {
                "vuln_id": vuln_id,
                "found": False,
            }
        scores = [r.complexity_score for r in recs]
        return {
            "vuln_id": vuln_id,
            "found": True,
            "min_complexity": min(scores),
            "max_complexity": max(scores),
            "avg_complexity": round(sum(scores) / len(scores), 2),
            "fix_count": len(recs),
        }

    def track_fix_coverage(
        self,
    ) -> dict[str, Any]:
        """Track overall fix coverage by type."""
        by_type: dict[str, dict[str, int]] = {}
        for r in self._records:
            vt = r.vuln_type.value
            by_type.setdefault(vt, {"total": 0, "fixed": 0})
            by_type[vt]["total"] += 1
            if r.fix_applied:
                by_type[vt]["fixed"] += 1
        result: dict[str, Any] = {}
        for vt, counts in by_type.items():
            t = counts["total"]
            f = counts["fixed"]
            result[vt] = {
                "total": t,
                "fixed": f,
                "rate_pct": (round(f / t * 100, 2) if t else 0.0),
            }
        return result
