"""Vendor Telemetry Normalizer — normalize events from multiple security vendors."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class VendorSource(StrEnum):
    CROWDSTRIKE = "crowdstrike"
    MICROSOFT_DEFENDER = "microsoft_defender"
    WIZ = "wiz"
    SENTINEL = "sentinel"
    SPLUNK = "splunk"
    DATADOG = "datadog"
    PALO_ALTO = "palo_alto"


class EventCategory(StrEnum):
    DETECTION = "detection"
    ALERT = "alert"
    INCIDENT = "incident"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    IDENTITY = "identity"
    NETWORK = "network"


class NormalizationStatus(StrEnum):
    RAW = "raw"
    NORMALIZED = "normalized"
    ENRICHED = "enriched"
    CORRELATED = "correlated"
    FAILED = "failed"


# --- Models ---


class TelemetryRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor: VendorSource = VendorSource.CROWDSTRIKE
    category: EventCategory = EventCategory.DETECTION
    status: NormalizationStatus = NormalizationStatus.RAW
    original_severity: str = ""
    normalized_severity: str = ""
    title: str = ""
    description: str = ""
    entity_id: str = ""
    entity_type: str = ""
    raw_event: dict[str, Any] = Field(default_factory=dict)
    normalized_fields: dict[str, Any] = Field(default_factory=dict)
    enrichment_context: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)


class NormalizationMapping(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor: VendorSource = VendorSource.CROWDSTRIKE
    vendor_field: str = ""
    normalized_field: str = ""
    transform_rule: str = ""
    created_at: float = Field(default_factory=time.time)


class TelemetryReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_events: int = 0
    normalized_count: int = 0
    enriched_count: int = 0
    failed_count: int = 0
    by_vendor: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    avg_normalization_rate: float = 0.0
    cross_vendor_entities: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Severity mapping per vendor ---

_SEVERITY_MAP: dict[str, dict[str, str]] = {
    VendorSource.CROWDSTRIKE: {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "info",
    },
    VendorSource.MICROSOFT_DEFENDER: {
        "high": "critical",
        "medium": "high",
        "low": "medium",
        "informational": "low",
        "unspecified": "info",
    },
    VendorSource.WIZ: {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFORMATIONAL": "info",
    },
    VendorSource.SENTINEL: {
        "high": "critical",
        "medium": "high",
        "low": "medium",
        "informational": "info",
    },
    VendorSource.SPLUNK: {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    },
    VendorSource.DATADOG: {
        "critical": "critical",
        "error": "high",
        "warning": "medium",
        "info": "low",
        "ok": "info",
    },
    VendorSource.PALO_ALTO: {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "info",
    },
}

# --- Field extraction per vendor ---

_FIELD_EXTRACTORS: dict[str, dict[str, str]] = {
    VendorSource.CROWDSTRIKE: {
        "title": "behaviors[0].tactic",
        "entity_id": "device.device_id",
        "entity_type": "device",
        "severity": "max_severity_displayname",
    },
    VendorSource.MICROSOFT_DEFENDER: {
        "title": "title",
        "entity_id": "machineId",
        "entity_type": "machine",
        "severity": "severity",
    },
    VendorSource.WIZ: {
        "title": "title",
        "entity_id": "entitySnapshot.id",
        "entity_type": "cloud_resource",
        "severity": "severity",
    },
}


# --- Engine ---


class VendorTelemetryNormalizer:
    """Normalize security telemetry from multiple vendors into a unified schema."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[TelemetryRecord] = []
        self._mappings: list[NormalizationMapping] = []
        logger.info("vendor_telemetry_normalizer.initialized", max_records=max_records)

    # -- ingest / normalize ------------------------------------------------

    def ingest_event(
        self,
        vendor: VendorSource,
        raw_event: dict[str, Any],
        category: EventCategory = EventCategory.DETECTION,
    ) -> TelemetryRecord:
        """Ingest a raw event from a vendor and normalize to common schema."""
        extractor = _FIELD_EXTRACTORS.get(vendor, {})
        title = self._extract_nested(raw_event, extractor.get("title", "title"))
        entity_id = self._extract_nested(raw_event, extractor.get("entity_id", "id"))
        entity_type = extractor.get("entity_type", "unknown")
        vendor_severity = str(
            self._extract_nested(raw_event, extractor.get("severity", "severity"))
        )
        normalized_severity = self.map_severity(vendor, vendor_severity)

        mitre: list[str] = []
        behaviors = raw_event.get("behaviors", [])
        if isinstance(behaviors, list):
            for b in behaviors:
                tech = b.get("technique_id") or b.get("technique")
                if tech:
                    mitre.append(str(tech))

        record = TelemetryRecord(
            vendor=vendor,
            category=category,
            status=NormalizationStatus.NORMALIZED,
            original_severity=vendor_severity,
            normalized_severity=normalized_severity,
            title=str(title) if title else "",
            entity_id=str(entity_id) if entity_id else "",
            entity_type=entity_type,
            raw_event=raw_event,
            normalized_fields={
                "severity": normalized_severity,
                "title": title,
                "entity_id": entity_id,
                "entity_type": entity_type,
                "vendor": vendor.value,
                "category": category.value,
            },
            mitre_techniques=mitre,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "vendor_telemetry_normalizer.event_ingested",
            record_id=record.id,
            vendor=vendor.value,
            category=category.value,
            normalized_severity=normalized_severity,
        )
        return record

    def map_severity(self, vendor: VendorSource, vendor_severity: str) -> str:
        """Map vendor-specific severity to unified severity (critical/high/medium/low/info)."""
        vendor_map = _SEVERITY_MAP.get(vendor, {})
        return vendor_map.get(vendor_severity.lower(), vendor_map.get(vendor_severity, "medium"))

    def enrich_with_context(self, event_id: str, context: dict[str, Any]) -> TelemetryRecord | None:
        """Add cross-vendor enrichment context to an event."""
        for r in self._records:
            if r.id == event_id:
                r.enrichment_context.update(context)
                r.status = NormalizationStatus.ENRICHED
                logger.info(
                    "vendor_telemetry_normalizer.event_enriched",
                    event_id=event_id,
                    context_keys=list(context.keys()),
                )
                return r
        return None

    # -- cross-vendor correlation ------------------------------------------

    def correlate_across_vendors(self, time_window_seconds: float = 300.0) -> list[dict[str, Any]]:
        """Find related events across vendors within a time window by entity overlap."""
        entity_groups: dict[str, list[TelemetryRecord]] = {}
        for r in self._records:
            if r.entity_id:
                entity_groups.setdefault(r.entity_id, []).append(r)

        correlations: list[dict[str, Any]] = []
        for entity_id, records in entity_groups.items():
            vendors_involved = {r.vendor.value for r in records}
            if len(vendors_involved) < 2:
                continue
            # Check time proximity
            sorted_recs = sorted(records, key=lambda x: x.created_at)
            for i, base in enumerate(sorted_recs):
                cluster = [base]
                for candidate in sorted_recs[i + 1 :]:
                    if candidate.created_at - base.created_at <= time_window_seconds:
                        cluster.append(candidate)
                if len({c.vendor.value for c in cluster}) >= 2:
                    for c in cluster:
                        c.status = NormalizationStatus.CORRELATED
                    correlations.append(
                        {
                            "entity_id": entity_id,
                            "vendors": list({c.vendor.value for c in cluster}),
                            "event_count": len(cluster),
                            "event_ids": [c.id for c in cluster],
                            "severities": list({c.normalized_severity for c in cluster}),
                            "time_span_seconds": round(
                                cluster[-1].created_at - cluster[0].created_at, 2
                            ),
                        }
                    )
                    break  # One correlation group per entity
        correlations.sort(key=lambda x: x["event_count"], reverse=True)
        logger.info(
            "vendor_telemetry_normalizer.correlation_complete",
            correlation_count=len(correlations),
        )
        return correlations

    # -- domain methods ----------------------------------------------------

    def get_vendor_breakdown(self) -> list[dict[str, Any]]:
        """Breakdown of events per vendor with severity distribution."""
        vendor_map: dict[str, dict[str, int]] = {}
        for r in self._records:
            bucket = vendor_map.setdefault(r.vendor.value, {})
            bucket[r.normalized_severity] = bucket.get(r.normalized_severity, 0) + 1
        return [
            {"vendor": v, "severity_distribution": s, "total": sum(s.values())}
            for v, s in sorted(vendor_map.items())
        ]

    def get_entity_risk_summary(self) -> list[dict[str, Any]]:
        """Summarize risk per entity across all vendors."""
        severity_weight = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
        entity_scores: dict[str, dict[str, Any]] = {}
        for r in self._records:
            if not r.entity_id:
                continue
            entry = entity_scores.setdefault(
                r.entity_id,
                {"entity_type": r.entity_type, "score": 0, "vendors": set(), "event_count": 0},
            )
            entry["score"] += severity_weight.get(r.normalized_severity, 1)
            entry["vendors"].add(r.vendor.value)
            entry["event_count"] += 1
        results = [
            {
                "entity_id": eid,
                "entity_type": data["entity_type"],
                "risk_score": data["score"],
                "vendors": sorted(data["vendors"]),
                "event_count": data["event_count"],
            }
            for eid, data in entity_scores.items()
        ]
        results.sort(key=lambda x: x["risk_score"], reverse=True)
        return results

    def detect_normalization_gaps(self) -> list[dict[str, Any]]:
        """Identify events that failed normalization or have missing fields."""
        gaps: list[dict[str, Any]] = []
        for r in self._records:
            missing: list[str] = []
            if not r.title:
                missing.append("title")
            if not r.entity_id:
                missing.append("entity_id")
            if not r.normalized_severity:
                missing.append("normalized_severity")
            if r.status == NormalizationStatus.FAILED or missing:
                gaps.append(
                    {
                        "event_id": r.id,
                        "vendor": r.vendor.value,
                        "status": r.status.value,
                        "missing_fields": missing,
                    }
                )
        return gaps

    # -- report / stats / clear --------------------------------------------

    def generate_report(self) -> TelemetryReport:
        by_vendor: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        normalized = enriched = failed = 0

        for r in self._records:
            by_vendor[r.vendor.value] = by_vendor.get(r.vendor.value, 0) + 1
            by_category[r.category.value] = by_category.get(r.category.value, 0) + 1
            by_severity[r.normalized_severity] = by_severity.get(r.normalized_severity, 0) + 1
            if r.status == NormalizationStatus.NORMALIZED:
                normalized += 1
            elif r.status == NormalizationStatus.ENRICHED:
                enriched += 1
            elif r.status == NormalizationStatus.FAILED:
                failed += 1

        total = len(self._records)
        norm_rate = round((normalized + enriched) / total, 4) if total else 0.0

        # Count entities seen across multiple vendors
        entity_vendors: dict[str, set[str]] = {}
        for r in self._records:
            if r.entity_id:
                entity_vendors.setdefault(r.entity_id, set()).add(r.vendor.value)
        cross_vendor = sum(1 for v in entity_vendors.values() if len(v) >= 2)

        recs: list[str] = []
        if failed > 0:
            recs.append(f"{failed} event(s) failed normalization — review field extractors")
        if cross_vendor > 0:
            recs.append(f"{cross_vendor} entit(ies) seen across multiple vendors — run correlation")
        if not recs:
            recs.append("All events normalized successfully; telemetry pipeline healthy")

        return TelemetryReport(
            total_events=total,
            normalized_count=normalized,
            enriched_count=enriched,
            failed_count=failed,
            by_vendor=by_vendor,
            by_category=by_category,
            by_severity=by_severity,
            avg_normalization_rate=norm_rate,
            cross_vendor_entities=cross_vendor,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        status_dist: dict[str, int] = {}
        for r in self._records:
            status_dist[r.status.value] = status_dist.get(r.status.value, 0) + 1
        return {
            "total_events": len(self._records),
            "total_mappings": len(self._mappings),
            "status_distribution": status_dist,
            "unique_vendors": len({r.vendor.value for r in self._records}),
            "unique_entities": len({r.entity_id for r in self._records if r.entity_id}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._mappings.clear()
        logger.info("vendor_telemetry_normalizer.cleared")
        return {"status": "cleared"}

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _extract_nested(data: dict[str, Any], path: str) -> Any:
        """Extract a value from a nested dict using dot/bracket notation."""
        parts = path.replace("[", ".").replace("]", "").split(".")
        current: Any = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except (IndexError, ValueError):
                    return None
            else:
                return None
        return current
