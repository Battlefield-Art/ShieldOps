"""Postmortem Template Engine — generate and track postmortems."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TemplateSection(StrEnum):
    SUMMARY = "summary"
    TIMELINE = "timeline"
    ROOT_CAUSE = "root_cause"
    IMPACT = "impact"
    ACTION_ITEMS = "action_items"


class AnalysisDepth(StrEnum):
    SHALLOW = "shallow"
    STANDARD = "standard"
    DEEP = "deep"
    EXHAUSTIVE = "exhaustive"
    BLAMELESS = "blameless"


class ActionItemPriority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    OPTIONAL = "optional"


# --- Models ---


class PostmortemRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    section: TemplateSection = TemplateSection.SUMMARY
    depth: AnalysisDepth = AnalysisDepth.STANDARD
    priority: ActionItemPriority = ActionItemPriority.MEDIUM
    content: str = ""
    owner: str = ""
    completed: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class PostmortemAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    section: TemplateSection = TemplateSection.SUMMARY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PostmortemReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    completion_rate: float = 0.0
    by_section: dict[str, int] = Field(default_factory=dict)
    by_depth: dict[str, int] = Field(default_factory=dict)
    by_priority: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class PostmortemTemplateEngine:
    """Generate and track postmortem templates."""

    def __init__(
        self,
        max_records: int = 200000,
        completion_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = completion_threshold
        self._records: list[PostmortemRecord] = []
        self._analyses: list[PostmortemAnalysis] = []
        logger.info(
            "postmortem_template.initialized",
            max_records=max_records,
        )

    def record_item(
        self,
        incident_id: str,
        section: TemplateSection = (TemplateSection.SUMMARY),
        depth: AnalysisDepth = (AnalysisDepth.STANDARD),
        priority: ActionItemPriority = (ActionItemPriority.MEDIUM),
        content: str = "",
        owner: str = "",
        completed: bool = False,
        service: str = "",
        team: str = "",
    ) -> PostmortemRecord:
        record = PostmortemRecord(
            incident_id=incident_id,
            section=section,
            depth=depth,
            priority=priority,
            content=content,
            owner=owner,
            completed=completed,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "postmortem_template.record_added",
            record_id=record.id,
            incident_id=incident_id,
        )
        return record

    def get_record(self, record_id: str) -> PostmortemRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        section: TemplateSection | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[PostmortemRecord]:
        results = list(self._records)
        if section is not None:
            results = [r for r in results if r.section == section]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    # -- domain operations ---

    def generate_template(
        self,
    ) -> list[dict[str, Any]]:
        """Generate template coverage summary."""
        sec_data: dict[str, list[PostmortemRecord]] = {}
        for r in self._records:
            sec_data.setdefault(r.section.value, []).append(r)
        results: list[dict[str, Any]] = []
        for sec, records in sec_data.items():
            done = sum(1 for r in records if r.completed)
            rate = round(done / len(records) * 100, 2) if records else 0.0
            results.append(
                {
                    "section": sec,
                    "total": len(records),
                    "completed": done,
                    "completion_rate": rate,
                }
            )
        return sorted(
            results,
            key=lambda x: x["completion_rate"],
        )

    def populate_findings(
        self,
    ) -> list[dict[str, Any]]:
        """Summarize findings by depth."""
        depth_data: dict[str, list[PostmortemRecord]] = {}
        for r in self._records:
            depth_data.setdefault(r.depth.value, []).append(r)
        results: list[dict[str, Any]] = []
        for depth, records in depth_data.items():
            results.append(
                {
                    "depth": depth,
                    "count": len(records),
                    "unique_incidents": len({r.incident_id for r in records}),
                }
            )
        return sorted(
            results,
            key=lambda x: x["count"],
            reverse=True,
        )

    def track_action_items(
        self,
    ) -> list[dict[str, Any]]:
        """Track action items by priority."""
        pri_data: dict[str, list[PostmortemRecord]] = {}
        for r in self._records:
            if r.section == TemplateSection.ACTION_ITEMS:
                pri_data.setdefault(r.priority.value, []).append(r)
        results: list[dict[str, Any]] = []
        for pri, records in pri_data.items():
            done = sum(1 for r in records if r.completed)
            results.append(
                {
                    "priority": pri,
                    "total": len(records),
                    "completed": done,
                    "open": len(records) - done,
                }
            )
        return sorted(
            results,
            key=lambda x: x["open"],
            reverse=True,
        )

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.incident_id == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        done = sum(1 for r in matched if r.completed)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "completed": done,
        }

    def generate_report(self) -> PostmortemReport:
        by_sec: dict[str, int] = {}
        by_dep: dict[str, int] = {}
        by_pri: dict[str, int] = {}
        for r in self._records:
            by_sec[r.section.value] = by_sec.get(r.section.value, 0) + 1
            by_dep[r.depth.value] = by_dep.get(r.depth.value, 0) + 1
            by_pri[r.priority.value] = by_pri.get(r.priority.value, 0) + 1
        done = sum(1 for r in self._records if r.completed)
        rate = round(done / len(self._records) * 100, 2) if self._records else 0.0
        recs: list[str] = []
        if rate < self._threshold:
            recs.append(f"Completion {rate}% below {self._threshold}%")
        if not recs:
            recs.append("Postmortem Template healthy")
        return PostmortemReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            completion_rate=rate,
            by_section=by_sec,
            by_depth=by_dep,
            by_priority=by_pri,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("postmortem_template.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        sec_dist: dict[str, int] = {}
        for r in self._records:
            k = r.section.value
            sec_dist[k] = sec_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "completion_threshold": self._threshold,
            "section_distribution": sec_dist,
            "unique_incidents": len({r.incident_id for r in self._records}),
        }
