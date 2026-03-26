"""XDR Signal Correlator — correlate XDR signals across domains."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SignalDomain(StrEnum):
    ENDPOINT = "endpoint"
    NETWORK = "network"
    CLOUD = "cloud"
    IDENTITY = "identity"
    EMAIL = "email"
    IOT = "iot"


class CorrelationStrength(StrEnum):
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    NONE = "none"


class CampaignStatus(StrEnum):
    ACTIVE = "active"
    CONTAINED = "contained"
    RESOLVED = "resolved"


# --- Models ---


class XDRSignalRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    signal_domain: SignalDomain = SignalDomain.ENDPOINT
    correlation_strength: CorrelationStrength = CorrelationStrength.NONE
    campaign_status: CampaignStatus = CampaignStatus.ACTIVE
    score: float = 0.0
    event_count: int = 0
    campaign_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class XDRSignalAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    signal_domain: SignalDomain = SignalDomain.ENDPOINT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class XDRSignalReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_signal_domain: dict[str, int] = Field(default_factory=dict)
    by_correlation_strength: dict[str, int] = Field(default_factory=dict)
    by_campaign_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class XDRSignalCorrelatorEngine:
    """Correlate XDR signals across domains."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[XDRSignalRecord] = []
        self._analyses: list[XDRSignalAnalysis] = []
        logger.info(
            "xdr_signal_correlator.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ---

    def add_record(
        self,
        name: str,
        signal_domain: SignalDomain = (SignalDomain.ENDPOINT),
        correlation_strength: CorrelationStrength = (CorrelationStrength.NONE),
        campaign_status: CampaignStatus = (CampaignStatus.ACTIVE),
        score: float = 0.0,
        event_count: int = 0,
        campaign_id: str = "",
        service: str = "",
        team: str = "",
    ) -> XDRSignalRecord:
        record = XDRSignalRecord(
            name=name,
            signal_domain=signal_domain,
            correlation_strength=correlation_strength,
            campaign_status=campaign_status,
            score=score,
            event_count=event_count,
            campaign_id=campaign_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "xdr_signal_correlator.record_added",
            record_id=record.id,
            name=name,
            signal_domain=signal_domain.value,
        )
        return record

    def get_record(self, record_id: str) -> XDRSignalRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        signal_domain: SignalDomain | None = None,
        correlation_strength: (CorrelationStrength | None) = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[XDRSignalRecord]:
        results = list(self._records)
        if signal_domain is not None:
            results = [r for r in results if r.signal_domain == signal_domain]
        if correlation_strength is not None:
            results = [r for r in results if r.correlation_strength == correlation_strength]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        signal_domain: SignalDomain = (SignalDomain.ENDPOINT),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> XDRSignalAnalysis:
        analysis = XDRSignalAnalysis(
            name=name,
            signal_domain=signal_domain,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "xdr_signal_correlator.analysis_added",
            name=name,
            signal_domain=signal_domain.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ---

    def correlate_signals(
        self,
    ) -> list[dict[str, Any]]:
        """Correlate signals across domains per campaign."""
        campaign_data: dict[str, list[XDRSignalRecord]] = {}
        for r in self._records:
            if r.campaign_id:
                campaign_data.setdefault(r.campaign_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, records in campaign_data.items():
            domains = {r.signal_domain.value for r in records}
            strengths = [r.correlation_strength for r in records]
            strong_ct = sum(1 for s in strengths if s == CorrelationStrength.STRONG)
            total = len(strengths)
            confidence = round(strong_ct / total, 2) if total else 0.0
            results.append(
                {
                    "campaign_id": cid,
                    "domains": sorted(domains),
                    "domain_count": len(domains),
                    "signal_count": total,
                    "correlation_confidence": confidence,
                    "total_events": sum(r.event_count for r in records),
                }
            )
        return sorted(
            results,
            key=lambda x: x["domain_count"],
            reverse=True,
        )

    def detect_campaign_pattern(
        self,
    ) -> list[dict[str, Any]]:
        """Detect multi-domain attack campaign patterns."""
        campaign_data: dict[str, list[XDRSignalRecord]] = {}
        for r in self._records:
            if r.campaign_id:
                campaign_data.setdefault(r.campaign_id, []).append(r)
        patterns: list[dict[str, Any]] = []
        for cid, records in campaign_data.items():
            domains = {r.signal_domain for r in records}
            is_multi = len(domains) >= 3
            avg_score = round(
                sum(r.score for r in records) / len(records),
                2,
            )
            patterns.append(
                {
                    "campaign_id": cid,
                    "is_multi_domain": is_multi,
                    "domains": sorted(d.value for d in domains),
                    "avg_score": avg_score,
                    "status": records[-1].campaign_status.value,
                    "risk": (
                        "critical"
                        if is_multi and avg_score > 70
                        else ("high" if is_multi else "medium")
                    ),
                }
            )
        return sorted(
            patterns,
            key=lambda x: x["avg_score"],
            reverse=True,
        )

    def calculate_correlation_confidence(
        self,
    ) -> dict[str, Any]:
        """Calculate overall correlation confidence."""
        if not self._records:
            return {
                "confidence": 0.0,
                "total": 0,
            }
        strength_ct: dict[str, int] = {}
        for r in self._records:
            k = r.correlation_strength.value
            strength_ct[k] = strength_ct.get(k, 0) + 1
        total = len(self._records)
        strong = strength_ct.get("strong", 0)
        moderate = strength_ct.get("moderate", 0)
        weighted = strong * 1.0 + moderate * 0.5
        confidence = round(weighted / total, 3)
        return {
            "confidence": confidence,
            "total": total,
            "strength_distribution": strength_ct,
            "strong_pct": round(strong / total * 100, 1),
        }

    # -- standard methods ---

    def analyze_distribution(
        self,
    ) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.signal_domain.value
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
                        "signal_domain": (r.signal_domain.value),
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

    def generate_report(self) -> XDRSignalReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            k1 = r.signal_domain.value
            by_e1[k1] = by_e1.get(k1, 0) + 1
            k2 = r.correlation_strength.value
            by_e2[k2] = by_e2.get(k2, 0) + 1
            k3 = r.campaign_status.value
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
            recs.append("XDR Signal Correlator is healthy")
        return XDRSignalReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_signal_domain=by_e1,
            by_correlation_strength=by_e2,
            by_campaign_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("xdr_signal_correlator.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.signal_domain.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "signal_domain_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
