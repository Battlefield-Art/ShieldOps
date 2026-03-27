"""Verification Test Engine — test remediations."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TestScope(StrEnum):
    UNIT = "unit"
    FUNCTIONAL = "functional"
    INTEGRATION = "integration"
    REGRESSION = "regression"
    SMOKE = "smoke"


class ComparisonResult(StrEnum):
    IMPROVED = "improved"
    UNCHANGED = "unchanged"
    DEGRADED = "degraded"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class RegressionType(StrEnum):
    PERFORMANCE = "performance"
    FUNCTIONALITY = "functionality"
    SECURITY = "security"
    AVAILABILITY = "availability"
    COMPATIBILITY = "compatibility"


# --- Models ---


class VerificationTestRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    remediation_id: str = ""
    scope: TestScope = TestScope.SMOKE
    comparison: ComparisonResult = ComparisonResult.INCONCLUSIVE
    regression_type: str = ""
    before_value: float = 0.0
    after_value: float = 0.0
    passed: bool = False
    details: str = ""
    created_at: float = Field(default_factory=time.time)


class VerificationAnalysis(BaseModel):
    remediation_id: str = ""
    total_tests: int = 0
    passed_count: int = 0
    failed_count: int = 0
    regressions_found: int = 0
    pass_rate_pct: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class VerificationReport(BaseModel):
    total_tests: int = 0
    overall_pass_rate_pct: float = 0.0
    by_scope: dict[str, int] = Field(default_factory=dict)
    by_comparison: dict[str, int] = Field(default_factory=dict)
    regressions: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class VerificationTestEngine:
    """Design and run verification tests."""

    def __init__(self, max_records: int = 10000) -> None:
        self._max = max_records
        self._records: list[VerificationTestRecord] = []
        logger.info(
            "verification_test_engine.init",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> VerificationTestRecord:
        rec = VerificationTestRecord(**kwargs)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "verification_test_engine.recorded",
            record_id=rec.id,
        )
        return rec

    def process(self, remediation_id: str) -> VerificationAnalysis:
        recs = [r for r in self._records if r.remediation_id == remediation_id]
        if not recs:
            return VerificationAnalysis(remediation_id=remediation_id)
        passed = sum(1 for r in recs if r.passed)
        failed = len(recs) - passed
        regs = sum(1 for r in recs if r.comparison == ComparisonResult.DEGRADED)
        rate = round(passed / len(recs) * 100, 2)
        return VerificationAnalysis(
            remediation_id=remediation_id,
            total_tests=len(recs),
            passed_count=passed,
            failed_count=failed,
            regressions_found=regs,
            pass_rate_pct=rate,
        )

    def generate_report(self) -> VerificationReport:
        by_scope: dict[str, int] = {}
        by_comp: dict[str, int] = {}
        for r in self._records:
            s = r.scope.value
            by_scope[s] = by_scope.get(s, 0) + 1
            c = r.comparison.value
            by_comp[c] = by_comp.get(c, 0) + 1
        total = len(self._records)
        passed = sum(1 for r in self._records if r.passed)
        regs = sum(1 for r in self._records if r.comparison == ComparisonResult.DEGRADED)
        rate = round(passed / total * 100, 2) if total else 0.0
        recs: list[str] = []
        if regs > 0:
            recs.append(f"{regs} regression(s) detected")
        if rate < 95:
            recs.append("Pass rate below 95% threshold")
        if not recs:
            recs.append("All verifications passing")
        return VerificationReport(
            total_tests=total,
            overall_pass_rate_pct=rate,
            by_scope=by_scope,
            by_comparison=by_comp,
            regressions=regs,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max,
            "unique_remediations": len({r.remediation_id for r in self._records}),
        }

    def clear_data(self) -> None:
        self._records.clear()
        logger.info("verification_test_engine.cleared")

    # -- domain methods --

    def design_test(
        self,
        remediation_id: str,
        scope: TestScope,
        before_value: float = 0.0,
    ) -> VerificationTestRecord:
        """Design a verification test."""
        return self.add_record(
            remediation_id=remediation_id,
            scope=scope,
            before_value=before_value,
        )

    def compare_before_after(
        self,
        record_id: str,
        after_value: float,
    ) -> dict[str, Any]:
        """Compare before/after values."""
        for r in self._records:
            if r.id == record_id:
                if after_value > r.before_value:
                    comp = ComparisonResult.IMPROVED
                elif after_value < r.before_value:
                    comp = ComparisonResult.DEGRADED
                else:
                    comp = ComparisonResult.UNCHANGED
                r.after_value = after_value
                r.comparison = comp
                r.passed = comp != ComparisonResult.DEGRADED
                return {
                    "found": True,
                    "record_id": record_id,
                    "comparison": comp.value,
                    "passed": r.passed,
                    "before": r.before_value,
                    "after": after_value,
                }
        return {
            "found": False,
            "record_id": record_id,
        }

    def detect_regression(
        self,
    ) -> list[dict[str, Any]]:
        """Find regressions across tests."""
        return [
            {
                "record_id": r.id,
                "remediation_id": (r.remediation_id),
                "scope": r.scope.value,
                "before": r.before_value,
                "after": r.after_value,
                "regression_type": (r.regression_type),
            }
            for r in self._records
            if r.comparison == ComparisonResult.DEGRADED
        ]
