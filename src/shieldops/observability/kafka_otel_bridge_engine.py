"""Kafka OTel Bridge Engine —
evaluate bridge throughput, detect mapping drift,
rank topics by signal value."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BridgeMode(StrEnum):
    PASSTHROUGH = "passthrough"
    TRANSFORM = "transform"
    ENRICH = "enrich"
    AGGREGATE = "aggregate"


class SignalMapping(StrEnum):
    MESSAGE_TO_SPAN = "message_to_span"
    MESSAGE_TO_METRIC = "message_to_metric"
    MESSAGE_TO_LOG = "message_to_log"
    MESSAGE_TO_EVENT = "message_to_event"


class BridgeFidelity(StrEnum):
    EXACT = "exact"
    LOSSY = "lossy"
    SAMPLED = "sampled"
    COMPRESSED = "compressed"


# --- Models ---


class KafkaOtelBridgeRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    topic: str = ""
    bridge_mode: BridgeMode = BridgeMode.PASSTHROUGH
    signal_mapping: SignalMapping = SignalMapping.MESSAGE_TO_SPAN
    bridge_fidelity: BridgeFidelity = BridgeFidelity.EXACT
    messages_per_sec: float = 0.0
    signal_value_score: float = 0.0
    mapping_drift_pct: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class KafkaOtelBridgeAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    topic: str = ""
    bridge_mode: BridgeMode = BridgeMode.PASSTHROUGH
    throughput_ok: bool = True
    drift_detected: bool = False
    fidelity_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class KafkaOtelBridgeReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_messages_per_sec: float = 0.0
    by_bridge_mode: dict[str, int] = Field(default_factory=dict)
    by_signal_mapping: dict[str, int] = Field(default_factory=dict)
    by_fidelity: dict[str, int] = Field(default_factory=dict)
    drifted_topics: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class KafkaOtelBridgeEngine:
    """Evaluate bridge throughput, detect mapping drift,
    rank topics by signal value."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[KafkaOtelBridgeRecord] = []
        self._analyses: dict[str, KafkaOtelBridgeAnalysis] = {}
        logger.info("kafka_otel_bridge_engine.init", max_records=max_records)

    def add_record(
        self,
        topic: str = "",
        bridge_mode: BridgeMode = BridgeMode.PASSTHROUGH,
        signal_mapping: SignalMapping = SignalMapping.MESSAGE_TO_SPAN,
        bridge_fidelity: BridgeFidelity = BridgeFidelity.EXACT,
        messages_per_sec: float = 0.0,
        signal_value_score: float = 0.0,
        mapping_drift_pct: float = 0.0,
        description: str = "",
    ) -> KafkaOtelBridgeRecord:
        record = KafkaOtelBridgeRecord(
            topic=topic,
            bridge_mode=bridge_mode,
            signal_mapping=signal_mapping,
            bridge_fidelity=bridge_fidelity,
            messages_per_sec=messages_per_sec,
            signal_value_score=signal_value_score,
            mapping_drift_pct=mapping_drift_pct,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "kafka_otel_bridge.record_added",
            record_id=record.id,
            topic=topic,
        )
        return record

    def process(self, key: str) -> KafkaOtelBridgeAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        fidelity_weights = {
            BridgeFidelity.EXACT: 1.0,
            BridgeFidelity.LOSSY: 0.6,
            BridgeFidelity.SAMPLED: 0.75,
            BridgeFidelity.COMPRESSED: 0.85,
        }
        fidelity_score = round(
            fidelity_weights.get(rec.bridge_fidelity, 0.5) * rec.signal_value_score,
            2,
        )
        throughput_ok = rec.messages_per_sec > 0.0
        drift_detected = rec.mapping_drift_pct > 5.0
        analysis = KafkaOtelBridgeAnalysis(
            topic=rec.topic,
            bridge_mode=rec.bridge_mode,
            throughput_ok=throughput_ok,
            drift_detected=drift_detected,
            fidelity_score=fidelity_score,
            description=f"Topic {rec.topic} bridge fidelity {fidelity_score:.2f}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> KafkaOtelBridgeReport:
        by_mode: dict[str, int] = {}
        by_mapping: dict[str, int] = {}
        by_fidelity: dict[str, int] = {}
        mps_vals: list[float] = []
        drifted: list[str] = []
        for r in self._records:
            km = r.bridge_mode.value
            by_mode[km] = by_mode.get(km, 0) + 1
            ksm = r.signal_mapping.value
            by_mapping[ksm] = by_mapping.get(ksm, 0) + 1
            kf = r.bridge_fidelity.value
            by_fidelity[kf] = by_fidelity.get(kf, 0) + 1
            mps_vals.append(r.messages_per_sec)
            if r.mapping_drift_pct > 5.0 and r.topic not in drifted:
                drifted.append(r.topic)
        avg_mps = round(sum(mps_vals) / len(mps_vals), 2) if mps_vals else 0.0
        recs: list[str] = []
        if drifted:
            recs.append(f"{len(drifted)} topics with mapping drift detected")
        lossy_count = by_fidelity.get("lossy", 0)
        if lossy_count > 0:
            recs.append(f"{lossy_count} lossy bridge records — review transforms")
        if not recs:
            recs.append("Kafka OTel bridge operating within normal parameters")
        return KafkaOtelBridgeReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_messages_per_sec=avg_mps,
            by_bridge_mode=by_mode,
            by_signal_mapping=by_mapping,
            by_fidelity=by_fidelity,
            drifted_topics=drifted[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        mode_dist: dict[str, int] = {}
        for r in self._records:
            k = r.bridge_mode.value
            mode_dist[k] = mode_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "mode_distribution": mode_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("kafka_otel_bridge_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def evaluate_bridge_throughput(self) -> list[dict[str, Any]]:
        """Evaluate bridge throughput per topic."""
        topic_data: dict[str, list[float]] = {}
        for r in self._records:
            topic_data.setdefault(r.topic, []).append(r.messages_per_sec)
        results: list[dict[str, Any]] = []
        for topic, vals in topic_data.items():
            avg_mps = sum(vals) / len(vals)
            results.append(
                {
                    "topic": topic,
                    "avg_messages_per_sec": round(avg_mps, 2),
                    "max_messages_per_sec": round(max(vals), 2),
                    "min_messages_per_sec": round(min(vals), 2),
                    "samples": len(vals),
                    "throughput_healthy": avg_mps > 0.0,
                }
            )
        results.sort(key=lambda x: x["avg_messages_per_sec"], reverse=True)
        return results

    def detect_mapping_drift(self) -> list[dict[str, Any]]:
        """Detect topics with significant mapping drift."""
        results: list[dict[str, Any]] = []
        seen: set[str] = set()
        for r in self._records:
            if r.mapping_drift_pct > 5.0 and r.topic not in seen:
                seen.add(r.topic)
                results.append(
                    {
                        "topic": r.topic,
                        "mapping_drift_pct": r.mapping_drift_pct,
                        "signal_mapping": r.signal_mapping.value,
                        "bridge_mode": r.bridge_mode.value,
                        "bridge_fidelity": r.bridge_fidelity.value,
                    }
                )
        results.sort(key=lambda x: x["mapping_drift_pct"], reverse=True)
        return results

    def rank_topics_by_signal_value(self) -> list[dict[str, Any]]:
        """Rank topics by aggregated signal value score."""
        topic_scores: dict[str, float] = {}
        topic_samples: dict[str, int] = {}
        for r in self._records:
            topic_scores[r.topic] = topic_scores.get(r.topic, 0.0) + r.signal_value_score
            topic_samples[r.topic] = topic_samples.get(r.topic, 0) + 1
        results: list[dict[str, Any]] = []
        for topic, total_score in topic_scores.items():
            samples = topic_samples[topic]
            results.append(
                {
                    "topic": topic,
                    "total_signal_value": round(total_score, 2),
                    "avg_signal_value": round(total_score / samples, 2),
                    "samples": samples,
                    "rank": 0,
                }
            )
        results.sort(key=lambda x: x["total_signal_value"], reverse=True)
        for idx, entry in enumerate(results, 1):
            entry["rank"] = idx
        return results
