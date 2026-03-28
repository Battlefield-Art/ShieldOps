"""Incident Timeline Engine — build and analyze incident timelines."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EventCategory(StrEnum):
    DETECTION = "detection"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    COMMUNICATION = "communication"


class TimelineGranularity(StrEnum):
    SECOND = "second"
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"


class CausalLink(StrEnum):
    CAUSED_BY = "caused_by"
    LED_TO = "led_to"
    CORRELATED = "correlated"
    INDEPENDENT = "independent"
    UNKNOWN = "unknown"


# --- Models ---


class TimelineRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    event_category: EventCategory = EventCategory.DETECTION
    granularity: TimelineGranularity = TimelineGranularity.MINUTE
    causal_link: CausalLink = CausalLink.UNKNOWN
    event_description: str = ""
    event_time: float = 0.0
    source_system: str = ""
    actor: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class TimelineAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    event_category: EventCategory = EventCategory.DETECTION
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TimelineReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_gap_seconds: float = 0.0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_granularity: dict[str, int] = Field(default_factory=dict)
    by_causal: dict[str, int] = Field(default_factory=dict)
    causal_chains: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class IncidentTimelineEngine:
    """Build and analyze incident timelines."""

    def __init__(
        self,
        max_records: int = 200000,
        gap_threshold_sec: float = 300.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = gap_threshold_sec
        self._records: list[TimelineRecord] = []
        self._analyses: list[TimelineAnalysis] = []
        logger.info(
            "incident_timeline_engine.initialized",
            max_records=max_records,
        )

    # -- record / get / list ---

    def add_record(
        self,
        incident_id: str,
        event_category: EventCategory = (EventCategory.DETECTION),
        granularity: TimelineGranularity = (TimelineGranularity.MINUTE),
        causal_link: CausalLink = CausalLink.UNKNOWN,
        event_description: str = "",
        event_time: float = 0.0,
        source_system: str = "",
        actor: str = "",
        service: str = "",
        team: str = "",
    ) -> TimelineRecord:
        record = TimelineRecord(
            incident_id=incident_id,
            event_category=event_category,
            granularity=granularity,
            causal_link=causal_link,
            event_description=event_description,
            event_time=event_time or time.time(),
            source_system=source_system,
            actor=actor,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "incident_timeline_engine.record_added",
            record_id=record.id,
            incident_id=incident_id,
        )
        return record

    def get_record(self, record_id: str) -> TimelineRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        event_category: EventCategory | None = None,
        incident_id: str | None = None,
        limit: int = 50,
    ) -> list[TimelineRecord]:
        results = list(self._records)
        if event_category is not None:
            results = [r for r in results if r.event_category == event_category]
        if incident_id is not None:
            results = [r for r in results if r.incident_id == incident_id]
        return results[-limit:]

    def add_analysis(
        self,
        incident_id: str,
        event_category: EventCategory = (EventCategory.DETECTION),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> TimelineAnalysis:
        analysis = TimelineAnalysis(
            incident_id=incident_id,
            event_category=event_category,
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

    def add_event(self) -> list[dict[str, Any]]:
        """Summarize events by incident."""
        inc_data: dict[str, list[TimelineRecord]] = {}
        for r in self._records:
            inc_data.setdefault(r.incident_id, []).append(r)
        results: list[dict[str, Any]] = []
        for inc_id, records in inc_data.items():
            results.append(
                {
                    "incident_id": inc_id,
                    "event_count": len(records),
                    "categories": list({r.event_category.value for r in records}),
                }
            )
        return sorted(
            results,
            key=lambda x: x["event_count"],
            reverse=True,
        )

    def build_timeline(
        self,
    ) -> list[dict[str, Any]]:
        """Build ordered timeline per incident."""
        inc_data: dict[str, list[TimelineRecord]] = {}
        for r in self._records:
            inc_data.setdefault(r.incident_id, []).append(r)
        results: list[dict[str, Any]] = []
        for inc_id, records in inc_data.items():
            ordered = sorted(records, key=lambda x: x.event_time)
            gaps: list[float] = []
            for i in range(1, len(ordered)):
                gap = ordered[i].event_time - ordered[i - 1].event_time
                gaps.append(gap)
            avg_gap = round(sum(gaps) / len(gaps), 2) if gaps else 0.0
            large_gaps = sum(1 for g in gaps if g > self._threshold)
            results.append(
                {
                    "incident_id": inc_id,
                    "event_count": len(ordered),
                    "avg_gap_sec": avg_gap,
                    "large_gaps": large_gaps,
                    "span_sec": round(
                        ordered[-1].event_time - ordered[0].event_time,
                        2,
                    )
                    if len(ordered) > 1
                    else 0.0,
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_gap_sec"],
            reverse=True,
        )

    def identify_causal_chain(
        self,
    ) -> list[dict[str, Any]]:
        """Identify causal chains in events."""
        link_data: dict[str, list[TimelineRecord]] = {}
        for r in self._records:
            if r.causal_link != CausalLink.UNKNOWN:
                link_data.setdefault(r.causal_link.value, []).append(r)
        results: list[dict[str, Any]] = []
        for link, records in link_data.items():
            incidents = list({r.incident_id for r in records})
            results.append(
                {
                    "causal_link": link,
                    "count": len(records),
                    "incidents_affected": len(incidents),
                }
            )
        return sorted(
            results,
            key=lambda x: x["count"],
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
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
        }

    def generate_report(self) -> TimelineReport:
        by_cat: dict[str, int] = {}
        by_gran: dict[str, int] = {}
        by_causal: dict[str, int] = {}
        for r in self._records:
            by_cat[r.event_category.value] = by_cat.get(r.event_category.value, 0) + 1
            by_gran[r.granularity.value] = by_gran.get(r.granularity.value, 0) + 1
            by_causal[r.causal_link.value] = by_causal.get(r.causal_link.value, 0) + 1
        timelines = self.build_timeline()
        avg_gap = (
            round(
                sum(t["avg_gap_sec"] for t in timelines) / len(timelines),
                2,
            )
            if timelines
            else 0.0
        )
        chains = self.identify_causal_chain()
        chain_labels = [c["causal_link"] for c in chains[:5]]
        recs: list[str] = []
        if avg_gap > self._threshold:
            recs.append(f"Avg gap {avg_gap}s exceeds {self._threshold}s")
        if not recs:
            recs.append("Incident Timeline Engine healthy")
        return TimelineReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_gap_seconds=avg_gap,
            by_category=by_cat,
            by_granularity=by_gran,
            by_causal=by_causal,
            causal_chains=chain_labels,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("incident_timeline_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        cat_dist: dict[str, int] = {}
        for r in self._records:
            k = r.event_category.value
            cat_dist[k] = cat_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "gap_threshold_sec": self._threshold,
            "category_distribution": cat_dist,
            "unique_incidents": len({r.incident_id for r in self._records}),
        }
