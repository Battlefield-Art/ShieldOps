"""WorkflowExecutionEngine — Track and analyze automated workflow executions."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class WorkflowType(StrEnum):
    INCIDENT_RESPONSE = "incident_response"
    ACCESS_REVOCATION = "access_revocation"
    COMPLIANCE_SCAN = "compliance_scan"
    THREAT_HUNT = "threat_hunt"
    CHANGE_APPROVAL = "change_approval"


class ExecutionStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class GateDecision(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"
    PENDING = "pending"
    AUTO_APPROVED = "auto_approved"
    ESCALATED = "escalated"


# --- Models ---


class WorkflowExecutionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    workflow_type: WorkflowType = WorkflowType.INCIDENT_RESPONSE
    execution_status: ExecutionStatus = ExecutionStatus.SUCCESS
    gate_decision: GateDecision = GateDecision.APPROVED
    score: float = 0.0
    duration_seconds: float = 0.0
    step_count: int = 0
    failed_step: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class WorkflowExecutionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    workflow_type: WorkflowType = WorkflowType.INCIDENT_RESPONSE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class WorkflowExecutionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_workflow_type: dict[str, int] = Field(default_factory=dict)
    by_execution_status: dict[str, int] = Field(default_factory=dict)
    by_gate_decision: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class WorkflowExecutionEngine:
    """Track and analyze automated workflow executions."""

    def __init__(
        self,
        max_records: int = 200000,
        success_threshold: float = 90.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = success_threshold
        self._records: list[WorkflowExecutionRecord] = []
        self._analyses: list[WorkflowExecutionAnalysis] = []
        logger.info(
            "workflow_execution_engine.initialized",
            max_records=max_records,
            success_threshold=success_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        workflow_type: WorkflowType = WorkflowType.INCIDENT_RESPONSE,
        execution_status: ExecutionStatus = ExecutionStatus.SUCCESS,
        gate_decision: GateDecision = GateDecision.APPROVED,
        score: float = 0.0,
        duration_seconds: float = 0.0,
        step_count: int = 0,
        failed_step: str = "",
        service: str = "",
        team: str = "",
    ) -> WorkflowExecutionRecord:
        record = WorkflowExecutionRecord(
            name=name,
            workflow_type=workflow_type,
            execution_status=execution_status,
            gate_decision=gate_decision,
            score=score,
            duration_seconds=duration_seconds,
            step_count=step_count,
            failed_step=failed_step,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "workflow_execution_engine.record_added",
            record_id=record.id,
            name=name,
            workflow_type=workflow_type.value,
            execution_status=execution_status.value,
        )
        return record

    def get_record(self, record_id: str) -> WorkflowExecutionRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        workflow_type: WorkflowType | None = None,
        execution_status: ExecutionStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[WorkflowExecutionRecord]:
        results = list(self._records)
        if workflow_type is not None:
            results = [r for r in results if r.workflow_type == workflow_type]
        if execution_status is not None:
            results = [
                r for r in results if r.execution_status == execution_status
            ]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        workflow_type: WorkflowType = WorkflowType.INCIDENT_RESPONSE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> WorkflowExecutionAnalysis:
        analysis = WorkflowExecutionAnalysis(
            name=name,
            workflow_type=workflow_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "workflow_execution_engine.analysis_added",
            name=name,
            workflow_type=workflow_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_failure_patterns(self) -> list[dict[str, Any]]:
        """Identify workflow types with high failure rates."""
        type_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            t = r.workflow_type.value
            type_data.setdefault(t, {})
            s = r.execution_status.value
            type_data[t][s] = type_data[t].get(s, 0) + 1
        patterns: list[dict[str, Any]] = []
        for wf_type, statuses in type_data.items():
            total = sum(statuses.values())
            failed = statuses.get("failed", 0)
            timeout = statuses.get("timeout", 0)
            failure_pct = (
                round((failed + timeout) / total * 100, 1) if total else 0.0
            )
            if failed > 0 or timeout > 0:
                patterns.append(
                    {
                        "workflow_type": wf_type,
                        "total_executions": total,
                        "failed": failed,
                        "timeout": timeout,
                        "failure_pct": failure_pct,
                        "severity": (
                            "critical" if failure_pct > 20 else "warning"
                        ),
                    }
                )
        return sorted(patterns, key=lambda x: x["failure_pct"], reverse=True)

    def compute_success_rates(self) -> list[dict[str, Any]]:
        """Compute success rates per workflow type."""
        type_records: dict[str, list[WorkflowExecutionRecord]] = {}
        for r in self._records:
            type_records.setdefault(r.workflow_type.value, []).append(r)
        results: list[dict[str, Any]] = []
        for wf_type, records in type_records.items():
            total = len(records)
            success = sum(
                1
                for r in records
                if r.execution_status == ExecutionStatus.SUCCESS
            )
            rate = round(success / total * 100, 1) if total else 0.0
            avg_duration = (
                round(
                    sum(r.duration_seconds for r in records) / total, 2
                )
                if total
                else 0.0
            )
            results.append(
                {
                    "workflow_type": wf_type,
                    "total_executions": total,
                    "successful": success,
                    "success_rate_pct": rate,
                    "avg_duration_seconds": avg_duration,
                }
            )
        return sorted(results, key=lambda x: x["success_rate_pct"])

    def recommend_workflow_improvements(self) -> list[dict[str, Any]]:
        """Recommend workflow improvements based on execution patterns."""
        recommendations: list[dict[str, Any]] = []
        failed = [
            r
            for r in self._records
            if r.execution_status == ExecutionStatus.FAILED
        ]
        for r in failed:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "workflow_type": r.workflow_type.value,
                    "issue": "execution_failure",
                    "priority": "critical",
                    "suggestion": (
                        f"Fix failed step '{r.failed_step}' in "
                        f"{r.workflow_type.value} workflow"
                    ),
                }
            )
        timeouts = [
            r
            for r in self._records
            if r.execution_status == ExecutionStatus.TIMEOUT
        ]
        for r in timeouts:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "workflow_type": r.workflow_type.value,
                    "issue": "timeout",
                    "priority": "high",
                    "suggestion": (
                        f"Optimize duration ({r.duration_seconds}s) "
                        f"or increase timeout"
                    ),
                }
            )
        denied = [
            r
            for r in self._records
            if r.gate_decision == GateDecision.DENIED
        ]
        for r in denied:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "workflow_type": r.workflow_type.value,
                    "issue": "gate_denied",
                    "priority": "medium",
                    "suggestion": "Review gate policy — frequent denials detected",
                }
            )
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        return sorted(
            recommendations, key=lambda x: priority_order.get(x["priority"], 3)
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.workflow_type.value
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
                        "workflow_type": r.workflow_type.value,
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

    def generate_report(self) -> WorkflowExecutionReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.workflow_type.value] = (
                by_e1.get(r.workflow_type.value, 0) + 1
            )
            by_e2[r.execution_status.value] = (
                by_e2.get(r.execution_status.value, 0) + 1
            )
            by_e3[r.gate_decision.value] = (
                by_e3.get(r.gate_decision.value, 0) + 1
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
            recs.append("Workflow Execution Engine is healthy")
        return WorkflowExecutionReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_workflow_type=by_e1,
            by_execution_status=by_e2,
            by_gate_decision=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("workflow_execution_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.workflow_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "workflow_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
