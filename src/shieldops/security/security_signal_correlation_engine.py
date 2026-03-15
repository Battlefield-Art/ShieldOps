"""Security Signal Correlation Engine — correlate security signals across
multiple sources to produce high-fidelity alerts and reduce alert fatigue."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SignalSource(StrEnum):
    FIREWALL = "firewall"
    ENDPOINT = "endpoint"
    NETWORK = "network"
    IDENTITY = "identity"
    CLOUD = "cloud"
    APPLICATION = "application"


class CorrelationType(StrEnum):
    TEMPORAL = "temporal"
    ENTITY_BASED = "entity_based"
    TACTIC_CHAIN = "tactic_chain"
    STATISTICAL = "statistical"


class AlertFidelity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


# --- Models ---


class SecuritySignalRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    signal_id: str = ""
    signal_source: SignalSource = SignalSource.NETWORK
    correlation_type: CorrelationType = CorrelationType.TEMPORAL
    alert_fidelity: AlertFidelity = AlertFidelity.LOW
    raw_confidence: float = 0.0
    correlated_confidence: float = 0.0
    entity: str = ""
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SecuritySignalAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    signal_id: str = ""
    correlation_count: int = 0
    fidelity_upgrade: bool = False
    original_fidelity: AlertFidelity = AlertFidelity.LOW
    final_fidelity: AlertFidelity = AlertFidelity.LOW
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SecuritySignalReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_correlated_confidence: float = 0.0
    by_signal_source: dict[str, int] = Field(default_factory=dict)
    by_correlation_type: dict[str, int] = Field(default_factory=dict)
    by_alert_fidelity: dict[str, int] = Field(default_factory=dict)
    high_fidelity_alerts: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---

_FIDELITY_ORDER = [
    AlertFidelity.LOW,
    AlertFidelity.MEDIUM,
    AlertFidelity.HIGH,
    AlertFidelity.CONFIRMED,
]


class SecuritySignalCorrelationEngine:
    """Correlate security signals across multiple sources to produce
    high-fidelity alerts and reduce alert fatigue."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[SecuritySignalRecord] = []
        self._analyses: dict[str, SecuritySignalAnalysis] = {}
        logger.info(
            "security_signal_correlation_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        signal_id: str = "",
        signal_source: SignalSource = SignalSource.NETWORK,
        correlation_type: CorrelationType = CorrelationType.TEMPORAL,
        alert_fidelity: AlertFidelity = AlertFidelity.LOW,
        raw_confidence: float = 0.0,
        correlated_confidence: float = 0.0,
        entity: str = "",
        description: str = "",
    ) -> SecuritySignalRecord:
        record = SecuritySignalRecord(
            signal_id=signal_id,
            signal_source=signal_source,
            correlation_type=correlation_type,
            alert_fidelity=alert_fidelity,
            raw_confidence=raw_confidence,
            correlated_confidence=correlated_confidence,
            entity=entity,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "security_signal_correlation_engine.record_added",
            record_id=record.id,
            signal_id=signal_id,
            signal_source=signal_source.value,
        )
        return record

    def process(self, key: str) -> SecuritySignalAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        correlated = [r for r in self._records if r.entity == rec.entity]
        correlation_count = len(correlated)
        original_fidelity = rec.alert_fidelity
        final_fidelity = self._compute_fidelity(correlated)
        upgraded = _FIDELITY_ORDER.index(final_fidelity) > _FIDELITY_ORDER.index(original_fidelity)
        analysis = SecuritySignalAnalysis(
            signal_id=rec.signal_id,
            correlation_count=correlation_count,
            fidelity_upgrade=upgraded,
            original_fidelity=original_fidelity,
            final_fidelity=final_fidelity,
            description=(f"Signal {rec.signal_id} correlated with {correlation_count} signals"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> SecuritySignalReport:
        by_ss: dict[str, int] = {}
        by_ct: dict[str, int] = {}
        by_af: dict[str, int] = {}
        conf_vals: list[float] = []
        for r in self._records:
            by_ss[r.signal_source.value] = by_ss.get(r.signal_source.value, 0) + 1
            by_ct[r.correlation_type.value] = by_ct.get(r.correlation_type.value, 0) + 1
            by_af[r.alert_fidelity.value] = by_af.get(r.alert_fidelity.value, 0) + 1
            conf_vals.append(r.correlated_confidence)
        avg_conf = round(sum(conf_vals) / len(conf_vals), 2) if conf_vals else 0.0
        high_fidelity = list(
            {
                r.signal_id
                for r in self._records
                if r.alert_fidelity in (AlertFidelity.HIGH, AlertFidelity.CONFIRMED)
            }
        )[:10]
        recs: list[str] = []
        if high_fidelity:
            recs.append(f"{len(high_fidelity)} high-fidelity alerts identified")
        if not recs:
            recs.append("Signal correlation posture is healthy")
        return SecuritySignalReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_correlated_confidence=avg_conf,
            by_signal_source=by_ss,
            by_correlation_type=by_ct,
            by_alert_fidelity=by_af,
            high_fidelity_alerts=high_fidelity,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        source_dist: dict[str, int] = {}
        for r in self._records:
            k = r.signal_source.value
            source_dist[k] = source_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "source_distribution": source_dist,
            "unique_entities": len({r.entity for r in self._records}),
            "unique_signals": len({r.signal_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("security_signal_correlation_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def correlate_by_entity(self, entity: str) -> dict[str, Any]:
        """Find all signals for an entity and compute correlated confidence."""
        entity_records = [r for r in self._records if r.entity == entity]
        if not entity_records:
            return {
                "entity": entity,
                "signal_count": 0,
                "correlated_confidence": 0.0,
            }
        raw_vals = [r.raw_confidence for r in entity_records]
        sources = {r.signal_source.value for r in entity_records}
        # Correlated confidence boosts with more sources
        base_conf = sum(raw_vals) / len(raw_vals)
        source_boost = min(len(sources) * 0.1, 0.5)
        correlated = round(min(base_conf + source_boost * 100, 100.0), 2)
        fidelity = self._compute_fidelity(entity_records)
        return {
            "entity": entity,
            "signal_count": len(entity_records),
            "unique_sources": list(sources),
            "avg_raw_confidence": round(base_conf, 2),
            "correlated_confidence": correlated,
            "fidelity": fidelity.value,
        }

    def measure_noise_reduction(self) -> dict[str, Any]:
        """Compare raw alert volume vs. correlated alert volume."""
        total_raw = len(self._records)
        # Group by entity to count unique correlated alerts
        entity_groups: dict[str, list[SecuritySignalRecord]] = {}
        for r in self._records:
            entity_groups.setdefault(r.entity, []).append(r)
        correlated_count = len(entity_groups)
        reduction_pct = round((1 - correlated_count / total_raw) * 100, 2) if total_raw > 0 else 0.0
        high_fidelity = sum(
            1
            for records in entity_groups.values()
            if self._compute_fidelity(records) in (AlertFidelity.HIGH, AlertFidelity.CONFIRMED)
        )
        return {
            "total_raw_signals": total_raw,
            "correlated_alerts": correlated_count,
            "noise_reduction_pct": reduction_pct,
            "high_fidelity_count": high_fidelity,
        }

    def identify_correlation_patterns(self) -> list[dict[str, Any]]:
        """Find recurring signal source combinations across entities."""
        entity_sources: dict[str, set[str]] = {}
        for r in self._records:
            entity_sources.setdefault(r.entity, set()).add(r.signal_source.value)
        pattern_counts: dict[str, int] = {}
        for sources in entity_sources.values():
            key = "+".join(sorted(sources))
            pattern_counts[key] = pattern_counts.get(key, 0) + 1
        results: list[dict[str, Any]] = []
        for pattern, count in pattern_counts.items():
            results.append(
                {
                    "source_combination": pattern,
                    "occurrence_count": count,
                    "source_count": len(pattern.split("+")),
                }
            )
        results.sort(key=lambda x: x["occurrence_count"], reverse=True)
        return results

    # -- internal helpers ---

    def _compute_fidelity(self, records: list[SecuritySignalRecord]) -> AlertFidelity:
        if not records:
            return AlertFidelity.LOW
        sources = {r.signal_source for r in records}
        avg_conf = sum(r.correlated_confidence for r in records) / len(records)
        if len(sources) >= 3 and avg_conf >= 80:
            return AlertFidelity.CONFIRMED
        if len(sources) >= 2 and avg_conf >= 60:
            return AlertFidelity.HIGH
        if avg_conf >= 40:
            return AlertFidelity.MEDIUM
        return AlertFidelity.LOW
