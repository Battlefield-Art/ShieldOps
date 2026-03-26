"""Vendor Signal Correlator — correlate cross-vendor signals."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SignalType(StrEnum):
    ENDPOINT_ALERT = "endpoint_alert"
    IDENTITY_EVENT = "identity_event"
    CLOUD_FINDING = "cloud_finding"
    NETWORK_FLOW = "network_flow"


class CorrelationMethod(StrEnum):
    ENTITY_MATCH = "entity_match"
    TEMPORAL = "temporal"
    BEHAVIORAL = "behavioral"
    GRAPH = "graph"


class EntityType(StrEnum):
    IP_ADDRESS = "ip_address"
    HOSTNAME = "hostname"
    USER = "user"
    HASH = "hash"
    DOMAIN = "domain"


# --- Models ---


class SignalRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor: str = ""
    signal_type: SignalType = SignalType.ENDPOINT_ALERT
    entity_type: EntityType = EntityType.IP_ADDRESS
    entity_value: str = ""
    severity: float = 0.0
    raw_data: dict[str, Any] = Field(default_factory=dict)
    correlated: bool = False
    correlation_id: str = ""
    created_at: float = Field(default_factory=time.time)


class CorrelationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_value: str = ""
    entity_type: str = ""
    total_signals: int = 0
    vendor_count: int = 0
    vendors: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    time_span_seconds: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class CorrelationReport(BaseModel):
    total_signals: int = 0
    total_correlations: int = 0
    by_signal_type: dict[str, int] = Field(default_factory=dict)
    by_entity_type: dict[str, int] = Field(default_factory=dict)
    by_vendor: dict[str, int] = Field(default_factory=dict)
    avg_confidence: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class VendorSignalCorrelatorEngine:
    """Correlate security signals across vendors."""

    def __init__(
        self,
        max_records: int = 200000,
        time_window_seconds: float = 3600.0,
    ) -> None:
        self._max_records = max_records
        self._time_window = time_window_seconds
        self._records: list[SignalRecord] = []
        self._correlations: dict[str, list[str]] = {}
        logger.info(
            "vendor_signal_correlator.initialized",
            max_records=max_records,
            time_window=time_window_seconds,
        )

    # -- record / query --

    def add_record(
        self,
        vendor: str,
        signal_type: SignalType = (SignalType.ENDPOINT_ALERT),
        entity_type: EntityType = (EntityType.IP_ADDRESS),
        entity_value: str = "",
        severity: float = 0.0,
        raw_data: dict[str, Any] | None = None,
    ) -> SignalRecord:
        record = SignalRecord(
            vendor=vendor,
            signal_type=signal_type,
            entity_type=entity_type,
            entity_value=entity_value,
            severity=severity,
            raw_data=raw_data or {},
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "vendor_signal_correlator.record_added",
            record_id=record.id,
            vendor=vendor,
            entity=entity_value,
        )
        return record

    def process(self, entity_value: str) -> CorrelationAnalysis:
        signals = [r for r in self._records if r.entity_value == entity_value]
        if not signals:
            return CorrelationAnalysis(entity_value=entity_value)
        vendors = list({s.vendor for s in signals})
        entity_type = signals[0].entity_type.value
        timestamps = [s.created_at for s in signals]
        time_span = max(timestamps) - min(timestamps)
        # Confidence increases with more vendors
        confidence = min(
            1.0,
            len(vendors) * 0.25 + len(signals) * 0.05,
        )
        return CorrelationAnalysis(
            entity_value=entity_value,
            entity_type=entity_type,
            total_signals=len(signals),
            vendor_count=len(vendors),
            vendors=vendors,
            confidence=round(confidence, 4),
            time_span_seconds=round(time_span, 2),
        )

    def generate_report(self) -> CorrelationReport:
        by_signal: dict[str, int] = {}
        by_entity: dict[str, int] = {}
        by_vendor: dict[str, int] = {}
        for r in self._records:
            by_signal[r.signal_type.value] = by_signal.get(r.signal_type.value, 0) + 1
            by_entity[r.entity_type.value] = by_entity.get(r.entity_type.value, 0) + 1
            by_vendor[r.vendor] = by_vendor.get(r.vendor, 0) + 1
        correlated = sum(1 for r in self._records if r.correlated)
        total = len(self._records)
        recs: list[str] = []
        if len(by_vendor) < 2 and total > 0:
            recs.append("Limited vendor diversity — add more signal sources")
        uncorrelated = total - correlated
        if uncorrelated > 0:
            recs.append(f"{uncorrelated} signal(s) uncorrelated")
        if not recs:
            recs.append("Signal correlation coverage is good")
        return CorrelationReport(
            total_signals=total,
            total_correlations=correlated,
            by_signal_type=by_signal,
            by_entity_type=by_entity,
            by_vendor=by_vendor,
            avg_confidence=0.0,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        vendor_dist: dict[str, int] = {}
        for r in self._records:
            vendor_dist[r.vendor] = vendor_dist.get(r.vendor, 0) + 1
        return {
            "total_signals": len(self._records),
            "max_records": self._max_records,
            "time_window": self._time_window,
            "vendor_distribution": vendor_dist,
            "correlated": sum(1 for r in self._records if r.correlated),
            "unique_entities": len({r.entity_value for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._correlations.clear()
        logger.info("vendor_signal_correlator.cleared")
        return {"status": "cleared"}

    # -- domain operations --

    def correlate_by_entity(
        self,
        entity_value: str,
        entity_type: EntityType = (EntityType.IP_ADDRESS),
        method: CorrelationMethod = (CorrelationMethod.ENTITY_MATCH),
    ) -> dict[str, Any]:
        """Correlate signals sharing an entity."""
        signals = [
            r
            for r in self._records
            if r.entity_value == entity_value and r.entity_type == entity_type
        ]
        if len(signals) < 2:
            return {
                "entity": entity_value,
                "correlated": False,
                "reason": "insufficient signals",
                "signal_count": len(signals),
            }
        corr_id = str(uuid.uuid4())
        for s in signals:
            s.correlated = True
            s.correlation_id = corr_id
        self._correlations[corr_id] = [s.id for s in signals]
        vendors = list({s.vendor for s in signals})
        max_sev = max(s.severity for s in signals)
        logger.info(
            "vendor_signal_correlator.entity_correlated",
            entity=entity_value,
            signals=len(signals),
            vendors=len(vendors),
        )
        return {
            "correlation_id": corr_id,
            "entity": entity_value,
            "entity_type": entity_type.value,
            "method": method.value,
            "correlated": True,
            "signal_count": len(signals),
            "vendors": vendors,
            "max_severity": max_sev,
        }

    def build_timeline(
        self,
        entity_value: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Build chronological timeline for entity."""
        signals = [r for r in self._records if r.entity_value == entity_value]
        signals.sort(key=lambda s: s.created_at)
        timeline: list[dict[str, Any]] = []
        for s in signals[-limit:]:
            timeline.append(
                {
                    "signal_id": s.id,
                    "vendor": s.vendor,
                    "signal_type": s.signal_type.value,
                    "severity": s.severity,
                    "timestamp": s.created_at,
                    "correlated": s.correlated,
                }
            )
        logger.info(
            "vendor_signal_correlator.timeline_built",
            entity=entity_value,
            events=len(timeline),
        )
        return timeline

    def calculate_confidence(
        self,
        correlation_id: str,
    ) -> dict[str, Any]:
        """Calculate confidence for a correlation."""
        signal_ids = self._correlations.get(correlation_id, [])
        signals = [r for r in self._records if r.id in signal_ids]
        if not signals:
            return {
                "correlation_id": correlation_id,
                "found": False,
                "confidence": 0.0,
            }
        vendors = list({s.vendor for s in signals})
        types = list({s.signal_type.value for s in signals})
        timestamps = [s.created_at for s in signals]
        time_span = max(timestamps) - min(timestamps)
        # Confidence factors
        vendor_factor = min(len(vendors) * 0.25, 1.0)
        type_factor = min(len(types) * 0.2, 0.8)
        time_factor = 0.3 if time_span <= self._time_window else 0.1
        confidence = round(
            min(
                1.0,
                vendor_factor + type_factor + time_factor,
            ),
            4,
        )
        return {
            "correlation_id": correlation_id,
            "found": True,
            "confidence": confidence,
            "vendor_count": len(vendors),
            "signal_type_count": len(types),
            "time_span_seconds": round(time_span, 2),
            "signal_count": len(signals),
        }
