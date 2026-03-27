"""ReportGenerationEngine -- generate reports."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ReportTemplate(StrEnum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"
    INCIDENT = "incident"
    SCORECARD = "scorecard"


class GenerationStatus(StrEnum):
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class DistributionChannel(StrEnum):
    EMAIL = "email"
    SLACK = "slack"
    DASHBOARD = "dashboard"
    API = "api"
    PDF = "pdf"


# --- Models ---


class ReportGenerationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    template: ReportTemplate = ReportTemplate.EXECUTIVE
    status: GenerationStatus = GenerationStatus.PENDING
    channel: DistributionChannel = DistributionChannel.DASHBOARD
    score: float = 0.0
    recipient: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ReportGenerationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    template: ReportTemplate = ReportTemplate.EXECUTIVE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ReportGenerationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_template: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_channel: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ReportGenerationEngine:
    """Generate and distribute reports."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[ReportGenerationRecord] = []
        self._analyses: list[ReportGenerationAnalysis] = []
        logger.info(
            "report_generation_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def record_item(
        self,
        name: str,
        template: ReportTemplate = ReportTemplate.EXECUTIVE,
        status: GenerationStatus = GenerationStatus.PENDING,
        channel: DistributionChannel = DistributionChannel.DASHBOARD,
        score: float = 0.0,
        recipient: str = "",
        service: str = "",
        team: str = "",
    ) -> ReportGenerationRecord:
        record = ReportGenerationRecord(
            name=name,
            template=template,
            status=status,
            channel=channel,
            score=score,
            recipient=recipient,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "report_generation.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> ReportGenerationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        template: ReportTemplate | None = None,
        status: GenerationStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ReportGenerationRecord]:
        results = list(self._records)
        if template is not None:
            results = [r for r in results if r.template == template]
        if status is not None:
            results = [r for r in results if r.status == status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        template: ReportTemplate = ReportTemplate.EXECUTIVE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ReportGenerationAnalysis:
        analysis = ReportGenerationAnalysis(
            name=name,
            template=template,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ---

    def generate_report_item(
        self,
    ) -> list[dict[str, Any]]:
        """Generate reports by template type."""
        tmpl_data: dict[str, list[ReportGenerationRecord]] = {}
        for r in self._records:
            tmpl_data.setdefault(r.template.value, []).append(r)
        results: list[dict[str, Any]] = []
        for tmpl, records in tmpl_data.items():
            completed = sum(1 for r in records if r.status == GenerationStatus.COMPLETED)
            results.append(
                {
                    "template": tmpl,
                    "total": len(records),
                    "completed": completed,
                    "completion_pct": round(
                        completed / len(records) * 100,
                        1,
                    ),
                }
            )
        return sorted(
            results,
            key=lambda x: x["completion_pct"],
        )

    def track_distribution(
        self,
    ) -> dict[str, Any]:
        """Track distribution by channel."""
        ch_data: dict[str, int] = {}
        for r in self._records:
            key = r.channel.value
            ch_data[key] = ch_data.get(key, 0) + 1
        return ch_data

    def measure_engagement(
        self,
    ) -> list[dict[str, Any]]:
        """Measure engagement per recipient."""
        recip_data: dict[str, list[ReportGenerationRecord]] = {}
        for r in self._records:
            recip_data.setdefault(r.recipient, []).append(r)
        results: list[dict[str, Any]] = []
        for recip, records in recip_data.items():
            results.append(
                {
                    "recipient": recip,
                    "total_reports": len(records),
                    "avg_score": round(
                        sum(r.score for r in records) / len(records),
                        2,
                    ),
                }
            )
        return sorted(
            results,
            key=lambda x: x["total_reports"],
            reverse=True,
        )

    # -- standard methods ---

    def identify_gaps(
        self,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "template": r.template.value,
                        "score": r.score,
                        "service": r.service,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    def generate_report(
        self,
    ) -> ReportGenerationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            v1 = r.template.value
            by_e1[v1] = by_e1.get(v1, 0) + 1
            v2 = r.status.value
            by_e2[v2] = by_e2.get(v2, 0) + 1
            v3 = r.channel.value
            by_e3[v3] = by_e3.get(v3, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Report Generation Engine healthy")
        return ReportGenerationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_template=by_e1,
            by_status=by_e2,
            by_channel=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("report_generation_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.template.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "template_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
