"""CI/CD Pipeline Security Engine — track CI/CD pipeline security posture."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PipelineProvider(StrEnum):
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    CIRCLECI = "circleci"
    AZURE_DEVOPS = "azure_devops"


class SecurityCheck(StrEnum):
    SECRET_SCAN = "secret_scan"  # noqa: S105
    SAST = "sast"
    DAST = "dast"
    SCA = "sca"
    IMAGE_SCAN = "image_scan"


class CheckResult(StrEnum):
    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    SKIPPED = "skipped"
    ERROR = "error"
    NOT_CONFIGURED = "not_configured"


# --- Models ---


class CICDPipelineSecurityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_id: str = ""
    pipeline_provider: PipelineProvider = PipelineProvider.GITHUB_ACTIONS
    security_check: SecurityCheck = SecurityCheck.SECRET_SCAN
    check_result: CheckResult = CheckResult.PASS
    findings_count: int = 0
    blocking: bool = False
    duration_ms: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CICDPipelineSecurityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    pipeline_provider: PipelineProvider = PipelineProvider.GITHUB_ACTIONS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CICDPipelineSecurityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_pipeline_provider: dict[str, int] = Field(default_factory=dict)
    by_security_check: dict[str, int] = Field(default_factory=dict)
    by_check_result: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CICDPipelineSecurityEngine:
    """CI/CD Pipeline Security Engine — track CI/CD pipeline security posture."""

    def __init__(
        self,
        max_records: int = 200000,
        coverage_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = coverage_threshold
        self._records: list[CICDPipelineSecurityRecord] = []
        self._analyses: list[CICDPipelineSecurityAnalysis] = []
        logger.info(
            "cicd_pipeline_security_engine.initialized",
            max_records=max_records,
            coverage_threshold=coverage_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        pipeline_id: str,
        pipeline_provider: PipelineProvider = PipelineProvider.GITHUB_ACTIONS,
        security_check: SecurityCheck = SecurityCheck.SECRET_SCAN,
        check_result: CheckResult = CheckResult.PASS,
        findings_count: int = 0,
        blocking: bool = False,
        duration_ms: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> CICDPipelineSecurityRecord:
        record = CICDPipelineSecurityRecord(
            pipeline_id=pipeline_id,
            pipeline_provider=pipeline_provider,
            security_check=security_check,
            check_result=check_result,
            findings_count=findings_count,
            blocking=blocking,
            duration_ms=duration_ms,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "cicd_pipeline_security_engine.record_added",
            record_id=record.id,
            pipeline_id=pipeline_id,
            pipeline_provider=pipeline_provider.value,
            security_check=security_check.value,
        )
        return record

    def get_record(self, record_id: str) -> CICDPipelineSecurityRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        pipeline_provider: PipelineProvider | None = None,
        security_check: SecurityCheck | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CICDPipelineSecurityRecord]:
        results = list(self._records)
        if pipeline_provider is not None:
            results = [r for r in results if r.pipeline_provider == pipeline_provider]
        if security_check is not None:
            results = [r for r in results if r.security_check == security_check]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        pipeline_provider: PipelineProvider = PipelineProvider.GITHUB_ACTIONS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CICDPipelineSecurityAnalysis:
        analysis = CICDPipelineSecurityAnalysis(
            name=name,
            pipeline_provider=pipeline_provider,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "cicd_pipeline_security_engine.analysis_added",
            name=name,
            pipeline_provider=pipeline_provider.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_pipeline_coverage(self) -> dict[str, Any]:
        provider_data: dict[str, list[str]] = {}
        for r in self._records:
            key = r.pipeline_provider.value
            provider_data.setdefault(key, []).append(r.check_result.value)
        result: dict[str, Any] = {}
        for k, results_list in provider_data.items():
            passed = sum(1 for v in results_list if v == "pass")
            result[k] = {
                "count": len(results_list),
                "pass_pct": round(passed / len(results_list) * 100, 2),
            }
        return result

    def identify_failing_checks(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.check_result in (CheckResult.FAIL, CheckResult.ERROR):
                results.append(
                    {
                        "record_id": r.id,
                        "pipeline_id": r.pipeline_id,
                        "pipeline_provider": r.pipeline_provider.value,
                        "security_check": r.security_check.value,
                        "check_result": r.check_result.value,
                        "findings_count": r.findings_count,
                        "blocking": r.blocking,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["findings_count"], reverse=True)

    def detect_security_trends(self) -> dict[str, Any]:
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

    def generate_report(self) -> CICDPipelineSecurityReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.pipeline_provider.value] = by_e1.get(r.pipeline_provider.value, 0) + 1
            by_e2[r.security_check.value] = by_e2.get(r.security_check.value, 0) + 1
            by_e3[r.check_result.value] = by_e3.get(r.check_result.value, 0) + 1
        gap_count = sum(
            1 for r in self._records if r.check_result in (CheckResult.FAIL, CheckResult.ERROR)
        )
        passed = sum(1 for r in self._records if r.check_result == CheckResult.PASS)
        pass_pct = round(passed / len(self._records) * 100, 2) if self._records else 0.0
        gap_list = self.identify_failing_checks()
        top_gaps = [g["pipeline_id"] for g in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} failing/errored security check(s)")
        if self._records and pass_pct < self._threshold:
            recs.append(f"Pass rate {pass_pct}% below threshold ({self._threshold}%)")
        if not recs:
            recs.append("CI/CD Pipeline Security Engine is healthy")
        return CICDPipelineSecurityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=pass_pct,
            by_pipeline_provider=by_e1,
            by_security_check=by_e2,
            by_check_result=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("cicd_pipeline_security_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.pipeline_provider.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "coverage_threshold": self._threshold,
            "pipeline_provider_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
