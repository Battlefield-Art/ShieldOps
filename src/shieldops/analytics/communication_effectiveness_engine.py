"""Communication Effectiveness Engine — measure comm channel metrics."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CommMetric(StrEnum):
    ACK_RATE = "ack_rate"
    RESPONSE_TIME = "response_time"
    ESCALATION_RATE = "escalation_rate"
    READ_RATE = "read_rate"
    ACTION_RATE = "action_rate"


class ResponseRate(StrEnum):
    IMMEDIATE = "immediate"
    FAST = "fast"
    NORMAL = "normal"
    SLOW = "slow"
    NO_RESPONSE = "no_response"


class ChannelEfficiency(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ADEQUATE = "adequate"
    POOR = "poor"
    FAILING = "failing"


# --- Models ---


class CommRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    channel: str = ""
    metric: CommMetric = CommMetric.ACK_RATE
    rate: ResponseRate = ResponseRate.NORMAL
    efficiency: ChannelEfficiency = ChannelEfficiency.GOOD
    value: float = 0.0
    target: float = 0.0
    incident_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CommAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    channel: str = ""
    metric: CommMetric = CommMetric.ACK_RATE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CommReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_ack_rate: float = 0.0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_rate: dict[str, int] = Field(default_factory=dict)
    by_efficiency: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CommunicationEffectivenessEngine:
    """Measure communication channel effectiveness."""

    def __init__(
        self,
        max_records: int = 200000,
        ack_threshold: float = 90.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = ack_threshold
        self._records: list[CommRecord] = []
        self._analyses: list[CommAnalysis] = []
        logger.info(
            "comm_effectiveness.initialized",
            max_records=max_records,
        )

    def add_record(
        self,
        channel: str,
        metric: CommMetric = CommMetric.ACK_RATE,
        rate: ResponseRate = ResponseRate.NORMAL,
        efficiency: ChannelEfficiency = (ChannelEfficiency.GOOD),
        value: float = 0.0,
        target: float = 0.0,
        incident_id: str = "",
        service: str = "",
        team: str = "",
    ) -> CommRecord:
        record = CommRecord(
            channel=channel,
            metric=metric,
            rate=rate,
            efficiency=efficiency,
            value=value,
            target=target,
            incident_id=incident_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "comm_effectiveness.record_added",
            record_id=record.id,
            channel=channel,
        )
        return record

    def get_record(self, record_id: str) -> CommRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        metric: CommMetric | None = None,
        channel: str | None = None,
        limit: int = 50,
    ) -> list[CommRecord]:
        results = list(self._records)
        if metric is not None:
            results = [r for r in results if r.metric == metric]
        if channel is not None:
            results = [r for r in results if r.channel == channel]
        return results[-limit:]

    # -- domain operations ---

    def measure_ack_rate(
        self,
    ) -> list[dict[str, Any]]:
        """Measure ack rate by channel."""
        ch_data: dict[str, list[CommRecord]] = {}
        for r in self._records:
            if r.metric == CommMetric.ACK_RATE:
                ch_data.setdefault(r.channel, []).append(r)
        results: list[dict[str, Any]] = []
        for ch, records in ch_data.items():
            vals = [r.value for r in records]
            avg = round(sum(vals) / len(vals), 2) if vals else 0.0
            results.append(
                {
                    "channel": ch,
                    "count": len(records),
                    "avg_ack_rate": avg,
                    "meets_target": avg >= self._threshold,
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_ack_rate"],
        )

    def compare_channels(
        self,
    ) -> list[dict[str, Any]]:
        """Compare channel performance."""
        ch_data: dict[str, list[CommRecord]] = {}
        for r in self._records:
            ch_data.setdefault(r.channel, []).append(r)
        results: list[dict[str, Any]] = []
        for ch, records in ch_data.items():
            vals = [r.value for r in records]
            avg = round(sum(vals) / len(vals), 2) if vals else 0.0
            eff_dist: dict[str, int] = {}
            for r in records:
                k = r.efficiency.value
                eff_dist[k] = eff_dist.get(k, 0) + 1
            results.append(
                {
                    "channel": ch,
                    "total": len(records),
                    "avg_value": avg,
                    "efficiency_dist": eff_dist,
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_value"],
            reverse=True,
        )

    def optimize_routing(
        self,
    ) -> list[dict[str, Any]]:
        """Suggest optimal routing per metric."""
        metric_data: dict[str, dict[str, list[CommRecord]]] = {}
        for r in self._records:
            md = metric_data.setdefault(r.metric.value, {})
            md.setdefault(r.channel, []).append(r)
        results: list[dict[str, Any]] = []
        for m, channels in metric_data.items():
            best_ch = ""
            best_avg = -1.0
            for ch, records in channels.items():
                vals = [r.value for r in records]
                avg = sum(vals) / len(vals) if vals else 0.0
                if avg > best_avg:
                    best_avg = avg
                    best_ch = ch
            results.append(
                {
                    "metric": m,
                    "best_channel": best_ch,
                    "best_avg": round(best_avg, 2),
                    "channels_compared": len(channels),
                }
            )
        return sorted(
            results,
            key=lambda x: x["best_avg"],
            reverse=True,
        )

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.channel == key or r.incident_id == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        vals = [r.value for r in matched]
        avg = round(sum(vals) / len(vals), 2) if vals else 0.0
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_value": avg,
        }

    def generate_report(self) -> CommReport:
        by_m: dict[str, int] = {}
        by_r: dict[str, int] = {}
        by_e: dict[str, int] = {}
        for r in self._records:
            by_m[r.metric.value] = by_m.get(r.metric.value, 0) + 1
            by_r[r.rate.value] = by_r.get(r.rate.value, 0) + 1
            by_e[r.efficiency.value] = by_e.get(r.efficiency.value, 0) + 1
        ack_recs = [r for r in self._records if r.metric == CommMetric.ACK_RATE]
        vals = [r.value for r in ack_recs]
        avg_ack = round(sum(vals) / len(vals), 2) if vals else 0.0
        recs: list[str] = []
        if avg_ack < self._threshold:
            recs.append(f"Ack rate {avg_ack}% below {self._threshold}%")
        if not recs:
            recs.append("Comm Effectiveness is healthy")
        return CommReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_ack_rate=avg_ack,
            by_metric=by_m,
            by_rate=by_r,
            by_efficiency=by_e,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("comm_effectiveness.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        m_dist: dict[str, int] = {}
        for r in self._records:
            k = r.metric.value
            m_dist[k] = m_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "ack_threshold": self._threshold,
            "metric_distribution": m_dist,
            "unique_channels": len({r.channel for r in self._records}),
        }
