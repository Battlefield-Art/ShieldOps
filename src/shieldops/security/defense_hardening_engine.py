"""Defense Hardening Engine — automatic defense improvements and validation."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class HardeningCategory(StrEnum):
    ACCESS_CONTROL = "access_control"
    NETWORK_SEGMENTATION = "network_segmentation"
    ENDPOINT_PROTECTION = "endpoint_protection"
    CREDENTIAL_MANAGEMENT = "credential_management"
    MONITORING = "monitoring"
    AI_SECURITY = "ai_security"


class HardeningStatus(StrEnum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    APPLIED = "applied"
    VALIDATED = "validated"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class HardeningPriority(StrEnum):
    DEFERRED = "deferred"
    STANDARD = "standard"
    IMPORTANT = "important"
    URGENT = "urgent"
    CRITICAL = "critical"


# --- Models ---


class HardeningRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_name: str = ""
    category: HardeningCategory = HardeningCategory.ACCESS_CONTROL
    status: HardeningStatus = HardeningStatus.PROPOSED
    priority: HardeningPriority = HardeningPriority.STANDARD
    target_asset: str = ""
    source_finding: str = ""
    risk_reduction_pct: float = 0.0
    applied_at: float = 0.0
    details: str = ""
    created_at: float = Field(default_factory=time.time)


class HardeningValidation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hardening_id: str = ""
    passed: bool = False
    test_name: str = ""
    test_output: str = ""
    validated_at: float = Field(default_factory=time.time)


class HardeningReport(BaseModel):
    total_actions: int = 0
    applied_count: int = 0
    validated_count: int = 0
    failed_count: int = 0
    rolled_back_count: int = 0
    avg_risk_reduction_pct: float = 0.0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_priority: dict[str, int] = Field(default_factory=dict)
    regressions_detected: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---

_PRIORITY_WEIGHTS: dict[HardeningPriority, int] = {
    HardeningPriority.CRITICAL: 5,
    HardeningPriority.URGENT: 4,
    HardeningPriority.IMPORTANT: 3,
    HardeningPriority.STANDARD: 2,
    HardeningPriority.DEFERRED: 1,
}


class DefenseHardeningEngine:
    """Automatic defense improvements driven by red team findings."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[HardeningRecord] = []
        self._validations: list[HardeningValidation] = []
        logger.info("defense_hardening_engine.initialized", max_records=max_records)

    # -- record --------------------------------------------------------------

    def record_hardening(
        self,
        action_name: str,
        category: HardeningCategory = HardeningCategory.ACCESS_CONTROL,
        status: HardeningStatus = HardeningStatus.PROPOSED,
        priority: HardeningPriority = HardeningPriority.STANDARD,
        target_asset: str = "",
        source_finding: str = "",
        risk_reduction_pct: float = 0.0,
        details: str = "",
    ) -> HardeningRecord:
        record = HardeningRecord(
            action_name=action_name,
            category=category,
            status=status,
            priority=priority,
            target_asset=target_asset,
            source_finding=source_finding,
            risk_reduction_pct=risk_reduction_pct,
            details=details,
        )
        if status == HardeningStatus.APPLIED:
            record.applied_at = time.time()
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "defense_hardening_engine.hardening_recorded",
            record_id=record.id,
            action_name=action_name,
            category=category.value,
            priority=priority.value,
        )
        return record

    # -- domain operations ---------------------------------------------------

    def validate_hardening(
        self,
        hardening_id: str,
        test_name: str = "",
        test_output: str = "",
        passed: bool = False,
    ) -> HardeningValidation:
        """Record a validation test result for a hardening action."""
        validation = HardeningValidation(
            hardening_id=hardening_id,
            passed=passed,
            test_name=test_name,
            test_output=test_output,
        )
        self._validations.append(validation)
        if len(self._validations) > self._max_records:
            self._validations = self._validations[-self._max_records :]

        # Update record status
        for r in self._records:
            if r.id == hardening_id:
                if passed:
                    r.status = HardeningStatus.VALIDATED
                else:
                    r.status = HardeningStatus.FAILED
                break

        logger.info(
            "defense_hardening_engine.validation_recorded",
            hardening_id=hardening_id,
            test_name=test_name,
            passed=passed,
        )
        return validation

    def detect_regression(self) -> list[dict[str, Any]]:
        """Detect hardening actions that were validated but later failed or rolled back."""
        results: list[dict[str, Any]] = []
        # Find records that have both pass and fail validations, or were rolled back
        for r in self._records:
            if r.status == HardeningStatus.ROLLED_BACK:
                results.append(
                    {
                        "hardening_id": r.id,
                        "action_name": r.action_name,
                        "category": r.category.value,
                        "target_asset": r.target_asset,
                        "regression_type": "rolled_back",
                    }
                )
                continue

            validations = [v for v in self._validations if v.hardening_id == r.id]
            passed_then_failed = False
            had_pass = False
            for v in sorted(validations, key=lambda x: x.validated_at):
                if v.passed:
                    had_pass = True
                elif had_pass and not v.passed:
                    passed_then_failed = True
                    break

            if passed_then_failed:
                results.append(
                    {
                        "hardening_id": r.id,
                        "action_name": r.action_name,
                        "category": r.category.value,
                        "target_asset": r.target_asset,
                        "regression_type": "validation_regression",
                    }
                )
        return results

    def prioritize_actions(self) -> list[dict[str, Any]]:
        """Prioritize pending hardening actions by priority weight and risk reduction."""
        pending = [
            r
            for r in self._records
            if r.status in (HardeningStatus.PROPOSED, HardeningStatus.APPROVED)
        ]

        scored: list[tuple[float, HardeningRecord]] = []
        for r in pending:
            weight = _PRIORITY_WEIGHTS.get(r.priority, 2)
            score = weight * 20.0 + r.risk_reduction_pct
            scored.append((score, r))

        scored.sort(key=lambda x: x[0], reverse=True)

        return [
            {
                "hardening_id": r.id,
                "action_name": r.action_name,
                "category": r.category.value,
                "priority": r.priority.value,
                "status": r.status.value,
                "target_asset": r.target_asset,
                "risk_reduction_pct": r.risk_reduction_pct,
                "priority_score": round(score, 2),
            }
            for score, r in scored
        ]

    # -- report / stats ------------------------------------------------------

    def generate_hardening_report(self) -> HardeningReport:
        by_category: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        risk_reductions: list[float] = []

        for r in self._records:
            by_category[r.category.value] = by_category.get(r.category.value, 0) + 1
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
            by_priority[r.priority.value] = by_priority.get(r.priority.value, 0) + 1
            if r.risk_reduction_pct > 0:
                risk_reductions.append(r.risk_reduction_pct)

        applied = sum(
            1
            for r in self._records
            if r.status in (HardeningStatus.APPLIED, HardeningStatus.VALIDATED)
        )
        validated = sum(1 for r in self._records if r.status == HardeningStatus.VALIDATED)
        failed = sum(1 for r in self._records if r.status == HardeningStatus.FAILED)
        rolled_back = sum(1 for r in self._records if r.status == HardeningStatus.ROLLED_BACK)
        avg_reduction = (
            round(sum(risk_reductions) / len(risk_reductions), 2) if risk_reductions else 0.0
        )

        regressions = self.detect_regression()

        recs: list[str] = []
        pending = self.prioritize_actions()
        if pending:
            recs.append(f"{len(pending)} hardening actions pending implementation")
        if regressions:
            recs.append(f"{len(regressions)} regression(s) detected — investigate")
        if failed:
            recs.append(f"{failed} hardening actions failed — review and retry")
        if not recs:
            recs.append("Defense hardening posture meets targets")

        return HardeningReport(
            total_actions=len(self._records),
            applied_count=applied,
            validated_count=validated,
            failed_count=failed,
            rolled_back_count=rolled_back,
            avg_risk_reduction_pct=avg_reduction,
            by_category=by_category,
            by_status=by_status,
            by_priority=by_priority,
            regressions_detected=len(regressions),
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        cat_dist: dict[str, int] = {}
        for r in self._records:
            cat_dist[r.category.value] = cat_dist.get(r.category.value, 0) + 1
        return {
            "total_actions": len(self._records),
            "total_validations": len(self._validations),
            "category_distribution": cat_dist,
            "unique_assets": len({r.target_asset for r in self._records if r.target_asset}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._validations.clear()
        logger.info("defense_hardening_engine.cleared")
        return {"status": "cleared"}
