"""OTelKafkaIngestionEngine — track Kafka-based OTel ingestion health."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class KafkaSignalType(StrEnum):
    OTLP_PROTO = "otlp_proto"
    OTLP_JSON = "otlp_json"
    RAW_JSON = "raw_json"
    AVRO = "avro"


class IngestionMetric(StrEnum):
    THROUGHPUT = "throughput"
    CONSUMER_LAG = "consumer_lag"
    ENCODING_ERROR = "encoding_error"
    PARTITION_SKEW = "partition_skew"


class IngestionStatus(StrEnum):
    NOMINAL = "nominal"
    LAGGING = "lagging"
    ERRORING = "erroring"
    STALLED = "stalled"


# --- Models ---


class KafkaIngestionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    topic: str = ""
    signal_type: KafkaSignalType = KafkaSignalType.OTLP_PROTO
    ingestion_metric: IngestionMetric = IngestionMetric.THROUGHPUT
    ingestion_status: IngestionStatus = IngestionStatus.NOMINAL
    value: float = 0.0
    partition_id: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class KafkaIngestionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    topic: str = ""
    avg_throughput: float = 0.0
    max_lag: float = 0.0
    error_count: int = 0
    ingestion_status: IngestionStatus = IngestionStatus.NOMINAL
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class KafkaIngestionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_throughput: float = 0.0
    by_signal_type: dict[str, int] = Field(default_factory=dict)
    by_ingestion_metric: dict[str, int] = Field(default_factory=dict)
    by_ingestion_status: dict[str, int] = Field(default_factory=dict)
    lagging_topics: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class OTelKafkaIngestionEngine:
    """Track Kafka-based OTel ingestion — topic throughput, consumer lag,
    encoding errors, partition distribution."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[KafkaIngestionRecord] = []
        self._analyses: list[KafkaIngestionAnalysis] = []
        logger.info(
            "otel.kafka.ingestion.engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        topic: str,
        signal_type: KafkaSignalType = KafkaSignalType.OTLP_PROTO,
        ingestion_metric: IngestionMetric = IngestionMetric.THROUGHPUT,
        ingestion_status: IngestionStatus = IngestionStatus.NOMINAL,
        value: float = 0.0,
        partition_id: int = 0,
        description: str = "",
    ) -> KafkaIngestionRecord:
        record = KafkaIngestionRecord(
            topic=topic,
            signal_type=signal_type,
            ingestion_metric=ingestion_metric,
            ingestion_status=ingestion_status,
            value=value,
            partition_id=partition_id,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel.kafka.ingestion.engine.record_added",
            record_id=record.id,
            topic=topic,
            signal_type=signal_type.value,
            ingestion_metric=ingestion_metric.value,
        )
        return record

    def get_record(self, record_id: str) -> KafkaIngestionRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        signal_type: KafkaSignalType | None = None,
        ingestion_metric: IngestionMetric | None = None,
        topic: str | None = None,
        limit: int = 50,
    ) -> list[KafkaIngestionRecord]:
        results = list(self._records)
        if signal_type is not None:
            results = [r for r in results if r.signal_type == signal_type]
        if ingestion_metric is not None:
            results = [r for r in results if r.ingestion_metric == ingestion_metric]
        if topic is not None:
            results = [r for r in results if r.topic == topic]
        return results[-limit:]

    # -- process ------------------------------------------------------------

    def process(self, key: str) -> KafkaIngestionAnalysis | None:
        matched = [r for r in self._records if r.topic == key]
        if not matched:
            return None
        throughput_records = [
            r for r in matched if r.ingestion_metric == IngestionMetric.THROUGHPUT
        ]
        lag_records = [r for r in matched if r.ingestion_metric == IngestionMetric.CONSUMER_LAG]
        error_records = [r for r in matched if r.ingestion_metric == IngestionMetric.ENCODING_ERROR]
        avg_throughput = (
            round(sum(r.value for r in throughput_records) / len(throughput_records), 2)
            if throughput_records
            else 0.0
        )
        max_lag = round(max(r.value for r in lag_records), 2) if lag_records else 0.0
        error_count = len(error_records)
        if error_count > len(matched) * 0.3:
            status = IngestionStatus.ERRORING
        elif max_lag > self._threshold:
            status = IngestionStatus.LAGGING
        else:
            status = IngestionStatus.NOMINAL
        analysis = KafkaIngestionAnalysis(
            topic=key,
            avg_throughput=avg_throughput,
            max_lag=max_lag,
            error_count=error_count,
            ingestion_status=status,
            description=f"Analyzed {len(matched)} records for topic {key}",
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "otel.kafka.ingestion.engine.processed",
            topic=key,
            avg_throughput=avg_throughput,
            max_lag=max_lag,
            error_count=error_count,
            ingestion_status=status.value,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def detect_consumer_lag(self) -> list[dict[str, Any]]:
        """Identify topics with high consumer lag."""
        topic_data: dict[str, list[float]] = {}
        for r in self._records:
            if r.ingestion_metric == IngestionMetric.CONSUMER_LAG:
                topic_data.setdefault(r.topic, []).append(r.value)
        results: list[dict[str, Any]] = []
        for topic, lags in topic_data.items():
            max_lag = max(lags)
            if max_lag > self._threshold:
                results.append(
                    {
                        "topic": topic,
                        "max_lag": round(max_lag, 2),
                        "avg_lag": round(sum(lags) / len(lags), 2),
                        "sample_count": len(lags),
                    }
                )
        return sorted(results, key=lambda x: x["max_lag"], reverse=True)

    def analyze_partition_distribution(self) -> list[dict[str, Any]]:
        """Check for partition skew across topics."""
        topic_partitions: dict[str, dict[int, int]] = {}
        for r in self._records:
            topic_partitions.setdefault(r.topic, {})
            pid = r.partition_id
            topic_partitions[r.topic][pid] = topic_partitions[r.topic].get(pid, 0) + 1
        results: list[dict[str, Any]] = []
        for topic, partitions in topic_partitions.items():
            counts = list(partitions.values())
            if not counts:
                continue
            avg_count = sum(counts) / len(counts)
            max_count = max(counts)
            skew_ratio = round(max_count / avg_count, 2) if avg_count > 0 else 0.0
            results.append(
                {
                    "topic": topic,
                    "partition_count": len(partitions),
                    "skew_ratio": skew_ratio,
                    "skewed": skew_ratio > 1.5,
                }
            )
        return results

    def estimate_ingestion_capacity(self) -> list[dict[str, Any]]:
        """Project capacity based on current throughput."""
        topic_throughput: dict[str, list[float]] = {}
        for r in self._records:
            if r.ingestion_metric == IngestionMetric.THROUGHPUT:
                topic_throughput.setdefault(r.topic, []).append(r.value)
        results: list[dict[str, Any]] = []
        for topic, values in topic_throughput.items():
            avg_tp = round(sum(values) / len(values), 2)
            max_tp = round(max(values), 2)
            headroom = round((1.0 - avg_tp / max_tp) * 100 if max_tp > 0 else 100.0, 2)
            results.append(
                {
                    "topic": topic,
                    "avg_throughput": avg_tp,
                    "max_throughput": max_tp,
                    "headroom_pct": headroom,
                    "at_capacity": headroom < 10.0,
                }
            )
        return results

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> KafkaIngestionReport:
        by_signal: dict[str, int] = {}
        by_metric: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for r in self._records:
            by_signal[r.signal_type.value] = by_signal.get(r.signal_type.value, 0) + 1
            by_metric[r.ingestion_metric.value] = by_metric.get(r.ingestion_metric.value, 0) + 1
            by_status[r.ingestion_status.value] = by_status.get(r.ingestion_status.value, 0) + 1
        throughput_records = [
            r for r in self._records if r.ingestion_metric == IngestionMetric.THROUGHPUT
        ]
        avg_throughput = (
            round(sum(r.value for r in throughput_records) / len(throughput_records), 2)
            if throughput_records
            else 0.0
        )
        lagging = list(
            {
                r.topic
                for r in self._records
                if r.ingestion_status in (IngestionStatus.LAGGING, IngestionStatus.STALLED)
            }
        )
        recs: list[str] = []
        if lagging:
            recs.append(f"{len(lagging)} topic(s) experiencing lag or stall")
        if avg_throughput < self._threshold and throughput_records:
            recs.append(f"Avg throughput {avg_throughput} below threshold ({self._threshold})")
        if not recs:
            recs.append("OTel Kafka Ingestion Engine is healthy")
        return KafkaIngestionReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_throughput=avg_throughput,
            by_signal_type=by_signal,
            by_ingestion_metric=by_metric,
            by_ingestion_status=by_status,
            lagging_topics=lagging,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel.kafka.ingestion.engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        signal_dist: dict[str, int] = {}
        for r in self._records:
            key = r.signal_type.value
            signal_dist[key] = signal_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "signal_type_distribution": signal_dist,
            "unique_topics": len({r.topic for r in self._records}),
        }
