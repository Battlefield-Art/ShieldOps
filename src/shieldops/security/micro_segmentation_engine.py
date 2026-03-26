"""MicroSegmentationEngine — Track and enforce micro-segmentation policies."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SegmentScope(StrEnum):
    SERVICE = "service"
    NAMESPACE = "namespace"
    CLUSTER = "cluster"
    VPC = "vpc"
    SUBNET = "subnet"


class PolicyStatus(StrEnum):
    ENFORCED = "enforced"
    PARTIAL = "partial"
    MISSING = "missing"
    DRIFTED = "drifted"
    DISABLED = "disabled"


class EnforcementMethod(StrEnum):
    NETWORK_POLICY = "network_policy"
    SERVICE_MESH = "service_mesh"
    FIREWALL_RULE = "firewall_rule"
    SECURITY_GROUP = "security_group"
    NACL = "nacl"


# --- Models ---


class MicroSegmentationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    segment_scope: SegmentScope = SegmentScope.SERVICE
    policy_status: PolicyStatus = PolicyStatus.ENFORCED
    enforcement_method: EnforcementMethod = EnforcementMethod.NETWORK_POLICY
    score: float = 0.0
    segment_name: str = ""
    allowed_peers: int = 0
    denied_peers: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class MicroSegmentationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    segment_scope: SegmentScope = SegmentScope.SERVICE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MicroSegmentationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_segment_scope: dict[str, int] = Field(default_factory=dict)
    by_policy_status: dict[str, int] = Field(default_factory=dict)
    by_enforcement_method: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class MicroSegmentationEngine:
    """Track and enforce micro-segmentation policies across infrastructure."""

    def __init__(
        self,
        max_records: int = 200000,
        enforcement_threshold: float = 85.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = enforcement_threshold
        self._records: list[MicroSegmentationRecord] = []
        self._analyses: list[MicroSegmentationAnalysis] = []
        logger.info(
            "micro_segmentation_engine.initialized",
            max_records=max_records,
            enforcement_threshold=enforcement_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        segment_scope: SegmentScope = SegmentScope.SERVICE,
        policy_status: PolicyStatus = PolicyStatus.ENFORCED,
        enforcement_method: EnforcementMethod = EnforcementMethod.NETWORK_POLICY,
        score: float = 0.0,
        segment_name: str = "",
        allowed_peers: int = 0,
        denied_peers: int = 0,
        service: str = "",
        team: str = "",
    ) -> MicroSegmentationRecord:
        record = MicroSegmentationRecord(
            name=name,
            segment_scope=segment_scope,
            policy_status=policy_status,
            enforcement_method=enforcement_method,
            score=score,
            segment_name=segment_name,
            allowed_peers=allowed_peers,
            denied_peers=denied_peers,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "micro_segmentation_engine.record_added",
            record_id=record.id,
            name=name,
            segment_scope=segment_scope.value,
            policy_status=policy_status.value,
        )
        return record

    def get_record(self, record_id: str) -> MicroSegmentationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        segment_scope: SegmentScope | None = None,
        policy_status: PolicyStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[MicroSegmentationRecord]:
        results = list(self._records)
        if segment_scope is not None:
            results = [r for r in results if r.segment_scope == segment_scope]
        if policy_status is not None:
            results = [r for r in results if r.policy_status == policy_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        segment_scope: SegmentScope = SegmentScope.SERVICE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> MicroSegmentationAnalysis:
        analysis = MicroSegmentationAnalysis(
            name=name,
            segment_scope=segment_scope,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "micro_segmentation_engine.analysis_added",
            name=name,
            segment_scope=segment_scope.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_policy_gaps(self) -> list[dict[str, Any]]:
        """Identify segments with missing or drifted policies."""
        scope_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            s = r.segment_scope.value
            scope_data.setdefault(s, {})
            p = r.policy_status.value
            scope_data[s][p] = scope_data[s].get(p, 0) + 1
        gaps: list[dict[str, Any]] = []
        for scope, statuses in scope_data.items():
            total = sum(statuses.values())
            missing = statuses.get("missing", 0)
            drifted = statuses.get("drifted", 0)
            gap_pct = (
                round((missing + drifted) / total * 100, 1) if total else 0.0
            )
            if missing > 0 or drifted > 0:
                gaps.append(
                    {
                        "scope": scope,
                        "total_segments": total,
                        "missing": missing,
                        "drifted": drifted,
                        "gap_pct": gap_pct,
                        "severity": "critical" if missing > drifted else "warning",
                    }
                )
        return sorted(gaps, key=lambda x: x["gap_pct"], reverse=True)

    def compute_enforcement_coverage(self) -> list[dict[str, Any]]:
        """Compute enforcement coverage per scope."""
        scope_records: dict[str, list[MicroSegmentationRecord]] = {}
        for r in self._records:
            scope_records.setdefault(r.segment_scope.value, []).append(r)
        results: list[dict[str, Any]] = []
        for scope, records in scope_records.items():
            total = len(records)
            enforced = sum(
                1
                for r in records
                if r.policy_status == PolicyStatus.ENFORCED
            )
            coverage = round(enforced / total * 100, 1) if total else 0.0
            avg_score = (
                round(sum(r.score for r in records) / total, 2)
                if total
                else 0.0
            )
            results.append(
                {
                    "scope": scope,
                    "total_segments": total,
                    "enforced": enforced,
                    "coverage_pct": coverage,
                    "avg_score": avg_score,
                }
            )
        return sorted(results, key=lambda x: x["coverage_pct"])

    def recommend_segmentation_improvements(self) -> list[dict[str, Any]]:
        """Recommend segmentation improvements based on policy status."""
        recommendations: list[dict[str, Any]] = []
        missing = [
            r for r in self._records if r.policy_status == PolicyStatus.MISSING
        ]
        for r in missing:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "scope": r.segment_scope.value,
                    "issue": "missing_policy",
                    "priority": "critical",
                    "suggestion": (
                        f"Create {r.enforcement_method.value} for "
                        f"{r.segment_name or r.name}"
                    ),
                }
            )
        drifted = [
            r for r in self._records if r.policy_status == PolicyStatus.DRIFTED
        ]
        for r in drifted:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "scope": r.segment_scope.value,
                    "issue": "policy_drift",
                    "priority": "high",
                    "suggestion": (
                        f"Remediate drift in {r.enforcement_method.value} "
                        f"for {r.segment_name or r.name}"
                    ),
                }
            )
        excessive = [
            r for r in self._records if r.allowed_peers > 20
        ]
        for r in excessive:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "scope": r.segment_scope.value,
                    "issue": "excessive_peers",
                    "priority": "medium",
                    "suggestion": (
                        f"Reduce allowed peers ({r.allowed_peers}) "
                        f"for {r.segment_name or r.name}"
                    ),
                }
            )
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        return sorted(
            recommendations, key=lambda x: priority_order.get(x["priority"], 3)
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        scope_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.segment_scope.value
            scope_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in scope_data.items():
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
                        "segment_scope": r.segment_scope.value,
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
        matched = [
            r for r in self._records if r.name == key or r.service == key
        ]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(
                1 for s in scores if s < self._threshold
            ),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> MicroSegmentationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.segment_scope.value] = (
                by_e1.get(r.segment_scope.value, 0) + 1
            )
            by_e2[r.policy_status.value] = (
                by_e2.get(r.policy_status.value, 0) + 1
            )
            by_e3[r.enforcement_method.value] = (
                by_e3.get(r.enforcement_method.value, 0) + 1
            )
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(
                f"{gap_count} item(s) below threshold ({self._threshold})"
            )
        if self._records and avg_score < self._threshold:
            recs.append(
                f"Avg score {avg_score} below threshold ({self._threshold})"
            )
        if not recs:
            recs.append("Micro Segmentation Engine is healthy")
        return MicroSegmentationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_segment_scope=by_e1,
            by_policy_status=by_e2,
            by_enforcement_method=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("micro_segmentation_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.segment_scope.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "segment_scope_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
