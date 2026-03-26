"""IOC Extraction Engine — extract and manage Indicators of Compromise."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class IOCType(StrEnum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    MUTEX = "mutex"
    REGISTRY_KEY = "registry_key"
    URL = "url"
    EMAIL = "email"


class IOCConfidence(StrEnum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    UNLIKELY = "unlikely"


class IOCSource(StrEnum):
    SANDBOX = "sandbox"
    STATIC = "static"
    NETWORK = "network"
    INTELLIGENCE = "intelligence"


# --- Models ---


class IOCExtractionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    ioc_type: IOCType = IOCType.IP_ADDRESS
    ioc_confidence: IOCConfidence = IOCConfidence.POSSIBLE
    ioc_source: IOCSource = IOCSource.SANDBOX
    score: float = 0.0
    ioc_value: str = ""
    sample_hash: str = ""
    campaign_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class IOCExtractionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    ioc_type: IOCType = IOCType.IP_ADDRESS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class IOCExtractionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_ioc_type: dict[str, int] = Field(default_factory=dict)
    by_ioc_confidence: dict[str, int] = Field(default_factory=dict)
    by_ioc_source: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class IOCExtractionEngine:
    """Extract and manage Indicators of Compromise."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[IOCExtractionRecord] = []
        self._analyses: list[IOCExtractionAnalysis] = []
        logger.info(
            "ioc_extraction_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ---

    def add_record(
        self,
        name: str,
        ioc_type: IOCType = IOCType.IP_ADDRESS,
        ioc_confidence: IOCConfidence = (IOCConfidence.POSSIBLE),
        ioc_source: IOCSource = IOCSource.SANDBOX,
        score: float = 0.0,
        ioc_value: str = "",
        sample_hash: str = "",
        campaign_id: str = "",
        service: str = "",
        team: str = "",
    ) -> IOCExtractionRecord:
        record = IOCExtractionRecord(
            name=name,
            ioc_type=ioc_type,
            ioc_confidence=ioc_confidence,
            ioc_source=ioc_source,
            score=score,
            ioc_value=ioc_value,
            sample_hash=sample_hash,
            campaign_id=campaign_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ioc_extraction_engine.record_added",
            record_id=record.id,
            name=name,
            ioc_type=ioc_type.value,
        )
        return record

    def get_record(self, record_id: str) -> IOCExtractionRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        ioc_type: IOCType | None = None,
        ioc_confidence: (IOCConfidence | None) = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[IOCExtractionRecord]:
        results = list(self._records)
        if ioc_type is not None:
            results = [r for r in results if r.ioc_type == ioc_type]
        if ioc_confidence is not None:
            results = [r for r in results if r.ioc_confidence == ioc_confidence]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        ioc_type: IOCType = IOCType.IP_ADDRESS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> IOCExtractionAnalysis:
        analysis = IOCExtractionAnalysis(
            name=name,
            ioc_type=ioc_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "ioc_extraction_engine.analysis",
            name=name,
            ioc_type=ioc_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ---

    def extract_iocs(
        self,
    ) -> list[dict[str, Any]]:
        """Extract and summarize IOCs per sample."""
        sample_data: dict[str, list[IOCExtractionRecord]] = {}
        for r in self._records:
            if r.sample_hash:
                sample_data.setdefault(r.sample_hash, []).append(r)
        results: list[dict[str, Any]] = []
        for shash, records in sample_data.items():
            type_ct: dict[str, int] = {}
            for r in records:
                t = r.ioc_type.value
                type_ct[t] = type_ct.get(t, 0) + 1
            confirmed = sum(1 for r in records if r.ioc_confidence == IOCConfidence.CONFIRMED)
            results.append(
                {
                    "sample_hash": shash,
                    "ioc_count": len(records),
                    "type_distribution": type_ct,
                    "confirmed_count": confirmed,
                    "unique_values": len({r.ioc_value for r in records}),
                    "sources": sorted({r.ioc_source.value for r in records}),
                }
            )
        return sorted(
            results,
            key=lambda x: x["ioc_count"],
            reverse=True,
        )

    def deduplicate_iocs(
        self,
    ) -> dict[str, Any]:
        """Deduplicate IOCs across all records."""
        seen: dict[str, IOCExtractionRecord] = {}
        duplicates = 0
        for r in self._records:
            key = f"{r.ioc_type.value}:{r.ioc_value}"
            if key in seen:
                duplicates += 1
            else:
                seen[key] = r
        unique_by_type: dict[str, int] = {}
        for r in seen.values():
            t = r.ioc_type.value
            unique_by_type[t] = unique_by_type.get(t, 0) + 1
        return {
            "total_records": len(self._records),
            "unique_iocs": len(seen),
            "duplicates": duplicates,
            "dedup_pct": round(
                duplicates / len(self._records) * 100,
                1,
            )
            if self._records
            else 0.0,
            "unique_by_type": unique_by_type,
        }

    def correlate_with_threat_intel(
        self,
    ) -> list[dict[str, Any]]:
        """Correlate IOCs with campaign intelligence."""
        campaign_data: dict[str, list[IOCExtractionRecord]] = {}
        for r in self._records:
            if r.campaign_id:
                campaign_data.setdefault(r.campaign_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, records in campaign_data.items():
            type_ct: dict[str, int] = {}
            for r in records:
                t = r.ioc_type.value
                type_ct[t] = type_ct.get(t, 0) + 1
            conf_ct: dict[str, int] = {}
            for r in records:
                c = r.ioc_confidence.value
                conf_ct[c] = conf_ct.get(c, 0) + 1
            confirmed = conf_ct.get("confirmed", 0)
            total = len(records)
            intel_score = round(confirmed / total * 100, 1)
            results.append(
                {
                    "campaign_id": cid,
                    "ioc_count": total,
                    "type_distribution": type_ct,
                    "confidence_dist": conf_ct,
                    "intel_score": intel_score,
                    "samples": sorted({r.sample_hash for r in records if r.sample_hash})[:10],
                }
            )
        return sorted(
            results,
            key=lambda x: x["intel_score"],
            reverse=True,
        )

    # -- standard methods ---

    def analyze_distribution(
        self,
    ) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.ioc_type.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "ioc_type": (r.ioc_type.value),
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc: dict[str, list[float]] = {}
        for r in self._records:
            svc.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for s, scores in svc.items():
            results.append(
                {
                    "service": s,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

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

    # -- report / stats ---

    def generate_report(
        self,
    ) -> IOCExtractionReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            k1 = r.ioc_type.value
            by_e1[k1] = by_e1.get(k1, 0) + 1
            k2 = r.ioc_confidence.value
            by_e2[k2] = by_e2.get(k2, 0) + 1
            k3 = r.ioc_source.value
            by_e3[k3] = by_e3.get(k3, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("IOC Extraction Engine is healthy")
        return IOCExtractionReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_ioc_type=by_e1,
            by_ioc_confidence=by_e2,
            by_ioc_source=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("ioc_extraction_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.ioc_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "ioc_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
