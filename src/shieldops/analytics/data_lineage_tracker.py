"""Data Lineage Tracker — lineage and transforms."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class LineageHop(StrEnum):
    SOURCE = "source"
    TRANSFORM = "transform"
    SINK = "sink"
    CACHE = "cache"
    ARCHIVE = "archive"


class TransformationType(StrEnum):
    COPY = "copy"
    FILTER = "filter"
    AGGREGATE = "aggregate"
    JOIN = "join"
    ANONYMIZE = "anonymize"


class DataQuality(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"
    DEGRADED = "degraded"


# --- Models ---


class DataLineageRecord(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    pipeline_id: str = ""
    hop: LineageHop = LineageHop.SOURCE
    transformation: TransformationType = TransformationType.COPY
    quality: DataQuality = DataQuality.UNKNOWN
    source_dataset: str = ""
    target_dataset: str = ""
    record_count: int = 0
    owner: str = ""
    created_at: float = Field(default_factory=time.time)


class DataLineageAnalysis(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    pipeline_id: str = ""
    total_hops: int = 0
    unauthorized_transforms: int = 0
    quality_issues: int = 0
    analyzed_at: float = Field(default_factory=time.time)


class DataLineageReport(BaseModel):
    total_records: int = 0
    pipelines_tracked: int = 0
    unauthorized_count: int = 0
    quality_issues: int = 0
    by_hop: dict[str, int] = Field(
        default_factory=dict,
    )
    by_transform: dict[str, int] = Field(
        default_factory=dict,
    )
    recommendations: list[str] = Field(
        default_factory=list,
    )
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class DataLineageTracker:
    """Track data lineage and transforms."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[DataLineageRecord] = []
        logger.info(
            "data_lineage.initialized",
            max_records=max_records,
        )

    def _evict(self) -> None:
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]

    def add_record(
        self,
        **kwargs: Any,
    ) -> DataLineageRecord:
        record = DataLineageRecord(**kwargs)
        self._records.append(record)
        self._evict()
        logger.info(
            "data_lineage.record_added",
            record_id=record.id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> DataLineageAnalysis:
        matches = [r for r in self._records if r.pipeline_id == key]
        if not matches:
            return DataLineageAnalysis(
                pipeline_id=key,
            )
        unauthorized = sum(
            1
            for r in matches
            if r.transformation
            not in (
                TransformationType.COPY,
                TransformationType.FILTER,
            )
            and r.owner == ""
        )
        quality_issues = sum(
            1
            for r in matches
            if r.quality
            in (
                DataQuality.LOW,
                DataQuality.DEGRADED,
            )
        )
        return DataLineageAnalysis(
            pipeline_id=key,
            total_hops=len(matches),
            unauthorized_transforms=unauthorized,
            quality_issues=quality_issues,
        )

    def generate_report(self) -> DataLineageReport:
        by_hop: dict[str, int] = {}
        by_tx: dict[str, int] = {}
        pipelines: set[str] = set()
        unauthorized = 0
        quality_issues = 0
        for r in self._records:
            h = r.hop.value
            by_hop[h] = by_hop.get(h, 0) + 1
            t = r.transformation.value
            by_tx[t] = by_tx.get(t, 0) + 1
            pipelines.add(r.pipeline_id)
            if r.owner == "" and r.hop == LineageHop.TRANSFORM:
                unauthorized += 1
            if r.quality in (
                DataQuality.LOW,
                DataQuality.DEGRADED,
            ):
                quality_issues += 1
        recs: list[str] = []
        if unauthorized > 0:
            recs.append(f"{unauthorized} unauthorized transform(s)")
        if quality_issues > 0:
            recs.append(f"{quality_issues} quality issue(s)")
        if not recs:
            recs.append("Data lineage is healthy")
        return DataLineageReport(
            total_records=len(self._records),
            pipelines_tracked=len(pipelines),
            unauthorized_count=unauthorized,
            quality_issues=quality_issues,
            by_hop=by_hop,
            by_transform=by_tx,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "pipelines": len({r.pipeline_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("data_lineage.cleared")
        return {"status": "cleared"}

    # -- domain methods --

    def track_lineage(
        self,
        pipeline_id: str,
        source: str,
        target: str,
        hop: LineageHop = LineageHop.TRANSFORM,
    ) -> dict[str, Any]:
        """Track a lineage hop."""
        record = self.add_record(
            pipeline_id=pipeline_id,
            source_dataset=source,
            target_dataset=target,
            hop=hop,
        )
        return {
            "record_id": record.id,
            "pipeline_id": pipeline_id,
            "hop": hop.value,
        }

    def detect_unauthorized_transform(
        self,
        pipeline_id: str,
    ) -> dict[str, Any]:
        """Detect unauthorized transforms."""
        matches = [
            r
            for r in self._records
            if r.pipeline_id == pipeline_id and r.owner == "" and r.hop == LineageHop.TRANSFORM
        ]
        return {
            "pipeline_id": pipeline_id,
            "unauthorized_count": len(matches),
            "records": [r.id for r in matches],
        }

    def audit_data_flow(
        self,
        pipeline_id: str,
    ) -> dict[str, Any]:
        """Audit full data flow for a pipeline."""
        matches = [r for r in self._records if r.pipeline_id == pipeline_id]
        hops = [
            {
                "id": r.id,
                "hop": r.hop.value,
                "source": r.source_dataset,
                "target": r.target_dataset,
                "transform": r.transformation.value,
                "quality": r.quality.value,
            }
            for r in matches
        ]
        return {
            "pipeline_id": pipeline_id,
            "total_hops": len(hops),
            "flow": hops,
        }
