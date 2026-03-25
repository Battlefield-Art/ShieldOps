"""K8s Admission Controller Engine — track admission control decisions and policy violations."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AdmissionAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    MUTATE = "mutate"
    AUDIT = "audit"


class PolicyCategory(StrEnum):
    IMAGE_POLICY = "image_policy"
    RESOURCE_LIMITS = "resource_limits"
    SECURITY_CONTEXT = "security_context"
    NETWORK_POLICY = "network_policy"
    LABEL_REQUIREMENT = "label_requirement"


class ViolationType(StrEnum):
    PRIVILEGED_CONTAINER = "privileged_container"
    NO_RESOURCE_LIMITS = "no_resource_limits"
    LATEST_TAG = "latest_tag"
    ROOT_USER = "root_user"
    HOST_NETWORK = "host_network"


# --- Models ---


class K8sAdmissionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    decision_id: str = ""
    admission_action: AdmissionAction = AdmissionAction.ALLOW
    policy_category: PolicyCategory = PolicyCategory.IMAGE_POLICY
    violation_type: ViolationType = ViolationType.PRIVILEGED_CONTAINER
    namespace: str = ""
    pod_name: str = ""
    image: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class K8sAdmissionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    admission_action: AdmissionAction = AdmissionAction.ALLOW
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class K8sAdmissionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_admission_action: dict[str, int] = Field(default_factory=dict)
    by_policy_category: dict[str, int] = Field(default_factory=dict)
    by_violation_type: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class K8sAdmissionControllerEngine:
    """K8s Admission Controller Engine — track admission control decisions."""

    def __init__(
        self,
        max_records: int = 200000,
        violation_threshold: float = 10.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = violation_threshold
        self._records: list[K8sAdmissionRecord] = []
        self._analyses: list[K8sAdmissionAnalysis] = []
        logger.info(
            "k8s_admission_controller_engine.initialized",
            max_records=max_records,
            violation_threshold=violation_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        decision_id: str,
        admission_action: AdmissionAction = AdmissionAction.ALLOW,
        policy_category: PolicyCategory = PolicyCategory.IMAGE_POLICY,
        violation_type: ViolationType = ViolationType.PRIVILEGED_CONTAINER,
        namespace: str = "",
        pod_name: str = "",
        image: str = "",
        service: str = "",
        team: str = "",
    ) -> K8sAdmissionRecord:
        record = K8sAdmissionRecord(
            decision_id=decision_id,
            admission_action=admission_action,
            policy_category=policy_category,
            violation_type=violation_type,
            namespace=namespace,
            pod_name=pod_name,
            image=image,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "k8s_admission_controller_engine.record_added",
            record_id=record.id,
            decision_id=decision_id,
            admission_action=admission_action.value,
            policy_category=policy_category.value,
        )
        return record

    def get_record(self, record_id: str) -> K8sAdmissionRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        admission_action: AdmissionAction | None = None,
        policy_category: PolicyCategory | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[K8sAdmissionRecord]:
        results = list(self._records)
        if admission_action is not None:
            results = [r for r in results if r.admission_action == admission_action]
        if policy_category is not None:
            results = [r for r in results if r.policy_category == policy_category]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        admission_action: AdmissionAction = AdmissionAction.ALLOW,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> K8sAdmissionAnalysis:
        analysis = K8sAdmissionAnalysis(
            name=name,
            admission_action=admission_action,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "k8s_admission_controller_engine.analysis_added",
            name=name,
            admission_action=admission_action.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_admission_patterns(self) -> dict[str, Any]:
        action_data: dict[str, int] = {}
        for r in self._records:
            key = r.admission_action.value
            action_data[key] = action_data.get(key, 0) + 1
        total = len(self._records) or 1
        result: dict[str, Any] = {}
        for k, count in action_data.items():
            result[k] = {
                "count": count,
                "pct": round(count / total * 100, 2),
            }
        return result

    def identify_frequent_violations(self) -> list[dict[str, Any]]:
        ns_violations: dict[str, list[dict[str, Any]]] = {}
        for r in self._records:
            if r.admission_action in (AdmissionAction.DENY, AdmissionAction.WARN):
                ns_violations.setdefault(r.namespace, []).append(
                    {
                        "record_id": r.id,
                        "decision_id": r.decision_id,
                        "violation_type": r.violation_type.value,
                        "policy_category": r.policy_category.value,
                        "pod_name": r.pod_name,
                        "namespace": r.namespace,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        results: list[dict[str, Any]] = []
        for ns, violations in ns_violations.items():
            if len(violations) >= self._threshold:
                results.append(
                    {
                        "namespace": ns,
                        "violation_count": len(violations),
                        "violations": violations[:10],
                    }
                )
        return sorted(results, key=lambda x: x["violation_count"], reverse=True)

    def detect_policy_trends(self) -> dict[str, Any]:
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [a.analysis_score for a in self._analyses]
        mid = len(vals) // 2
        first_half = vals[:mid]
        second_half = vals[mid:]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        delta = round(avg_second - avg_first, 2)
        if abs(delta) < 5.0:
            trend = "stable"
        elif delta > 0:
            trend = "improving"
        else:
            trend = "degrading"
        return {
            "trend": trend,
            "delta": delta,
            "avg_first_half": round(avg_first, 2),
            "avg_second_half": round(avg_second, 2),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> K8sAdmissionReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.admission_action.value] = by_e1.get(r.admission_action.value, 0) + 1
            by_e2[r.policy_category.value] = by_e2.get(r.policy_category.value, 0) + 1
            by_e3[r.violation_type.value] = by_e3.get(r.violation_type.value, 0) + 1
        gap_count = sum(
            1
            for r in self._records
            if r.admission_action in (AdmissionAction.DENY, AdmissionAction.WARN)
        )
        deny_pct = round(gap_count / len(self._records) * 100, 2) if self._records else 0.0
        gaps = self.identify_frequent_violations()
        top_gaps = [g["namespace"] for g in gaps[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} denied/warned admission(s) detected")
        if deny_pct > self._threshold:
            recs.append(f"Deny rate {deny_pct}% above threshold ({self._threshold}%)")
        if not recs:
            recs.append("K8s Admission Controller Engine is healthy")
        return K8sAdmissionReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=deny_pct,
            by_admission_action=by_e1,
            by_policy_category=by_e2,
            by_violation_type=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("k8s_admission_controller_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.admission_action.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "violation_threshold": self._threshold,
            "admission_action_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
