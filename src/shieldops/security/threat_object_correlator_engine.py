"""Threat Object Correlator Engine —
correlate threat objects, detect campaign indicators,
score object threat relevance."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ThreatObjectType(StrEnum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    URL = "url"


class CorrelationStrength(StrEnum):
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    COINCIDENTAL = "coincidental"


class CampaignConfidence(StrEnum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    SPECULATIVE = "speculative"


# --- Models ---


class ThreatObjectRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    object_value: str = ""
    object_type: ThreatObjectType = ThreatObjectType.IP_ADDRESS
    correlation_strength: CorrelationStrength = CorrelationStrength.WEAK
    campaign_confidence: CampaignConfidence = CampaignConfidence.SPECULATIVE
    campaign_id: str = ""
    threat_score: float = 0.0
    seen_count: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ThreatObjectAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    object_value: str = ""
    object_type: ThreatObjectType = ThreatObjectType.IP_ADDRESS
    correlation_strength: CorrelationStrength = CorrelationStrength.WEAK
    relevance_score: float = 0.0
    campaign_linked: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ThreatObjectReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_threat_score: float = 0.0
    by_object_type: dict[str, int] = Field(default_factory=dict)
    by_correlation_strength: dict[str, int] = Field(default_factory=dict)
    by_campaign_confidence: dict[str, int] = Field(default_factory=dict)
    top_threat_objects: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ThreatObjectCorrelatorEngine:
    """Correlate threat objects, detect campaign indicators,
    score object threat relevance."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ThreatObjectRecord] = []
        self._analyses: dict[str, ThreatObjectAnalysis] = {}
        logger.info("threat_object_correlator_engine.init", max_records=max_records)

    def add_record(
        self,
        object_value: str = "",
        object_type: ThreatObjectType = ThreatObjectType.IP_ADDRESS,
        correlation_strength: CorrelationStrength = CorrelationStrength.WEAK,
        campaign_confidence: CampaignConfidence = CampaignConfidence.SPECULATIVE,
        campaign_id: str = "",
        threat_score: float = 0.0,
        seen_count: int = 0,
        description: str = "",
    ) -> ThreatObjectRecord:
        record = ThreatObjectRecord(
            object_value=object_value,
            object_type=object_type,
            correlation_strength=correlation_strength,
            campaign_confidence=campaign_confidence,
            campaign_id=campaign_id,
            threat_score=threat_score,
            seen_count=seen_count,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "threat_object.record_added",
            record_id=record.id,
            object_value=object_value,
        )
        return record

    def process(self, key: str) -> ThreatObjectAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        strength_weights = {
            CorrelationStrength.STRONG: 1.0,
            CorrelationStrength.MODERATE: 0.75,
            CorrelationStrength.WEAK: 0.4,
            CorrelationStrength.COINCIDENTAL: 0.1,
        }
        relevance = round(rec.threat_score * strength_weights.get(rec.correlation_strength, 0.4), 4)
        campaign_linked = rec.campaign_confidence in (
            CampaignConfidence.CONFIRMED,
            CampaignConfidence.PROBABLE,
        )
        analysis = ThreatObjectAnalysis(
            object_value=rec.object_value,
            object_type=rec.object_type,
            correlation_strength=rec.correlation_strength,
            relevance_score=relevance,
            campaign_linked=campaign_linked,
            description=f"Object {rec.object_value} relevance={relevance}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ThreatObjectReport:
        by_ot: dict[str, int] = {}
        by_cs: dict[str, int] = {}
        by_cc: dict[str, int] = {}
        scores: list[float] = []
        for r in self._records:
            by_ot[r.object_type.value] = by_ot.get(r.object_type.value, 0) + 1
            by_cs[r.correlation_strength.value] = by_cs.get(r.correlation_strength.value, 0) + 1
            by_cc[r.campaign_confidence.value] = by_cc.get(r.campaign_confidence.value, 0) + 1
            scores.append(r.threat_score)
        avg_s = round(sum(scores) / len(scores), 4) if scores else 0.0
        top = list(
            {
                r.object_value
                for r in self._records
                if r.correlation_strength == CorrelationStrength.STRONG
            }
        )[:10]
        recs: list[str] = []
        if top:
            recs.append(f"{len(top)} strongly correlated threat objects found")
        if not recs:
            recs.append("No strongly correlated threat objects detected")
        return ThreatObjectReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_threat_score=avg_s,
            by_object_type=by_ot,
            by_correlation_strength=by_cs,
            by_campaign_confidence=by_cc,
            top_threat_objects=top,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        ot_dist: dict[str, int] = {}
        for r in self._records:
            ot_dist[r.object_type.value] = ot_dist.get(r.object_type.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "object_type_distribution": ot_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("threat_object_correlator_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def correlate_threat_objects(self) -> list[dict[str, Any]]:
        """Correlate threat objects by campaign and strength."""
        campaign_objects: dict[str, list[ThreatObjectRecord]] = {}
        for r in self._records:
            if r.campaign_id:
                campaign_objects.setdefault(r.campaign_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, recs in campaign_objects.items():
            strong_count = sum(
                1 for r in recs if r.correlation_strength == CorrelationStrength.STRONG
            )
            types = list({r.object_type.value for r in recs})
            avg_score = round(sum(r.threat_score for r in recs) / len(recs), 4)
            results.append(
                {
                    "campaign_id": cid,
                    "object_count": len(recs),
                    "strong_correlations": strong_count,
                    "object_types": types,
                    "avg_threat_score": avg_score,
                }
            )
        results.sort(key=lambda x: x["strong_correlations"], reverse=True)
        return results

    def detect_campaign_indicators(self) -> list[dict[str, Any]]:
        """Detect objects indicative of active campaigns."""
        obj_campaign: dict[str, set[str]] = {}
        obj_scores: dict[str, list[float]] = {}
        for r in self._records:
            if r.campaign_id:
                obj_campaign.setdefault(r.object_value, set()).add(r.campaign_id)
            obj_scores.setdefault(r.object_value, []).append(r.threat_score)
        results: list[dict[str, Any]] = []
        for obj_val, campaigns in obj_campaign.items():
            scores = obj_scores.get(obj_val, [])
            avg_s = round(sum(scores) / len(scores), 4) if scores else 0.0
            results.append(
                {
                    "object_value": obj_val,
                    "campaign_count": len(campaigns),
                    "campaign_ids": list(campaigns),
                    "avg_threat_score": avg_s,
                    "multi_campaign": len(campaigns) > 1,
                }
            )
        results.sort(key=lambda x: x["campaign_count"], reverse=True)
        return results

    def score_object_threat_relevance(self) -> list[dict[str, Any]]:
        """Score each threat object by combined threat and correlation signals."""
        strength_mult = {
            CorrelationStrength.STRONG: 1.0,
            CorrelationStrength.MODERATE: 0.75,
            CorrelationStrength.WEAK: 0.4,
            CorrelationStrength.COINCIDENTAL: 0.1,
        }
        conf_mult = {
            CampaignConfidence.CONFIRMED: 1.0,
            CampaignConfidence.PROBABLE: 0.8,
            CampaignConfidence.POSSIBLE: 0.5,
            CampaignConfidence.SPECULATIVE: 0.2,
        }
        obj_latest: dict[str, ThreatObjectRecord] = {}
        for r in self._records:
            obj_latest[r.object_value] = r
        results: list[dict[str, Any]] = []
        for obj_val, rec in obj_latest.items():
            sm = strength_mult.get(rec.correlation_strength, 0.4)
            cm = conf_mult.get(rec.campaign_confidence, 0.2)
            relevance = round(rec.threat_score * sm * cm, 4)
            results.append(
                {
                    "object_value": obj_val,
                    "object_type": rec.object_type.value,
                    "threat_score": rec.threat_score,
                    "relevance_score": relevance,
                    "correlation_strength": rec.correlation_strength.value,
                    "campaign_confidence": rec.campaign_confidence.value,
                }
            )
        results.sort(key=lambda x: x["relevance_score"], reverse=True)
        return results
