"""ThreatFeedQualityEngine — measure quality of threat intelligence feeds including
false positive rates, timeliness, coverage, and overlap."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class FeedQualityMetric(StrEnum):
    FALSE_POSITIVE_RATE = "false_positive_rate"
    TIMELINESS = "timeliness"
    COVERAGE = "coverage"
    UNIQUENESS = "uniqueness"


class FeedTier(StrEnum):
    PREMIUM = "premium"
    STANDARD = "standard"
    COMMUNITY = "community"
    INTERNAL = "internal"


class QualityTrend(StrEnum):
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    UNRELIABLE = "unreliable"


# --- Models ---


class ThreatFeedRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    feed_name: str = ""
    quality_metric: FeedQualityMetric = FeedQualityMetric.FALSE_POSITIVE_RATE
    feed_tier: FeedTier = FeedTier.STANDARD
    quality_trend: QualityTrend = QualityTrend.STABLE
    quality_score: float = 0.0
    false_positives: int = 0
    true_detections: int = 0
    total_iocs: int = 0
    cost_per_month: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ThreatFeedAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    feed_name: str = ""
    feed_tier: FeedTier = FeedTier.STANDARD
    recommended_action: str = ""
    risk_assessment: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ThreatFeedReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_quality_score: float = 0.0
    by_quality_metric: dict[str, int] = Field(default_factory=dict)
    by_feed_tier: dict[str, int] = Field(default_factory=dict)
    by_quality_trend: dict[str, int] = Field(default_factory=dict)
    low_quality_feeds: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ThreatFeedQualityEngine:
    """Measure quality of threat intelligence feeds — false positive rates,
    timeliness, coverage, and overlap."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ThreatFeedRecord] = []
        self._analyses: dict[str, ThreatFeedAnalysis] = {}
        logger.info("threat_feed_quality_engine.init", max_records=max_records)

    def add_record(
        self,
        feed_name: str = "",
        quality_metric: FeedQualityMetric = FeedQualityMetric.FALSE_POSITIVE_RATE,
        feed_tier: FeedTier = FeedTier.STANDARD,
        quality_trend: QualityTrend = QualityTrend.STABLE,
        quality_score: float = 0.0,
        false_positives: int = 0,
        true_detections: int = 0,
        total_iocs: int = 0,
        cost_per_month: float = 0.0,
        description: str = "",
    ) -> ThreatFeedRecord:
        record = ThreatFeedRecord(
            feed_name=feed_name,
            quality_metric=quality_metric,
            feed_tier=feed_tier,
            quality_trend=quality_trend,
            quality_score=quality_score,
            false_positives=false_positives,
            true_detections=true_detections,
            total_iocs=total_iocs,
            cost_per_month=cost_per_month,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "threat_feed_quality.record_added",
            record_id=record.id,
            feed_name=feed_name,
            feed_tier=feed_tier.value,
        )
        return record

    def process(self, key: str) -> ThreatFeedAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        risk = round((1.0 - rec.quality_score) * 100, 2) if rec.quality_score <= 1.0 else 0.0
        if rec.quality_score >= 0.8:
            action = "Feed performing well — maintain subscription"
        elif rec.quality_score >= 0.5:
            action = "Feed quality moderate — review for optimization"
        else:
            action = "Feed quality poor — consider replacement"
        analysis = ThreatFeedAnalysis(
            feed_name=rec.feed_name,
            feed_tier=rec.feed_tier,
            recommended_action=action,
            risk_assessment=risk,
            description=f"Feed {rec.feed_name} quality_score={rec.quality_score}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ThreatFeedReport:
        by_metric: dict[str, int] = {}
        by_tier: dict[str, int] = {}
        by_trend: dict[str, int] = {}
        for r in self._records:
            by_metric[r.quality_metric.value] = by_metric.get(r.quality_metric.value, 0) + 1
            by_tier[r.feed_tier.value] = by_tier.get(r.feed_tier.value, 0) + 1
            by_trend[r.quality_trend.value] = by_trend.get(r.quality_trend.value, 0) + 1
        scores = [r.quality_score for r in self._records]
        avg_quality = round(sum(scores) / len(scores), 2) if scores else 0.0
        low_quality = list(
            {r.feed_name for r in self._records if r.quality_score < 0.5 and r.feed_name}
        )[:10]
        recs: list[str] = []
        if low_quality:
            recs.append(f"{len(low_quality)} feed(s) below quality threshold")
        degrading = sum(
            1
            for r in self._records
            if r.quality_trend in (QualityTrend.DEGRADING, QualityTrend.UNRELIABLE)
        )
        if degrading > 0:
            recs.append(f"{degrading} record(s) showing degrading/unreliable trends")
        if not recs:
            recs.append("Threat feed quality engine is healthy")
        return ThreatFeedReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_quality_score=avg_quality,
            by_quality_metric=by_metric,
            by_feed_tier=by_tier,
            by_quality_trend=by_trend,
            low_quality_feeds=low_quality,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        tier_dist: dict[str, int] = {}
        for r in self._records:
            tier_dist[r.feed_tier.value] = tier_dist.get(r.feed_tier.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "feed_tier_distribution": tier_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("threat_feed_quality_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def rank_feeds_by_quality(self) -> list[dict[str, Any]]:
        """Rank threat feeds by composite quality score."""
        feed_data: dict[str, list[ThreatFeedRecord]] = {}
        for r in self._records:
            feed_data.setdefault(r.feed_name, []).append(r)
        results: list[dict[str, Any]] = []
        for name, recs in feed_data.items():
            avg_quality = round(sum(r.quality_score for r in recs) / len(recs), 4)
            total_fp = sum(r.false_positives for r in recs)
            total_td = sum(r.true_detections for r in recs)
            fp_rate = (
                round(total_fp / (total_fp + total_td) * 100, 2)
                if (total_fp + total_td) > 0
                else 0.0
            )
            tier = recs[0].feed_tier.value
            results.append(
                {
                    "feed_name": name,
                    "avg_quality_score": avg_quality,
                    "false_positive_rate": fp_rate,
                    "true_detections": total_td,
                    "feed_tier": tier,
                    "sample_count": len(recs),
                }
            )
        results.sort(key=lambda x: x["avg_quality_score"], reverse=True)
        return results

    def detect_feed_overlap(self) -> list[dict[str, Any]]:
        """Identify redundant feeds providing the same IOCs (same total_iocs count
        as a proxy for overlap)."""
        feed_iocs: dict[str, list[int]] = {}
        for r in self._records:
            feed_iocs.setdefault(r.feed_name, []).append(r.total_iocs)
        feed_names = list(feed_iocs.keys())
        results: list[dict[str, Any]] = []
        for i in range(len(feed_names)):
            for j in range(i + 1, len(feed_names)):
                a_avg = sum(feed_iocs[feed_names[i]]) / len(feed_iocs[feed_names[i]])
                b_avg = sum(feed_iocs[feed_names[j]]) / len(feed_iocs[feed_names[j]])
                if a_avg == 0 and b_avg == 0:
                    continue
                max_val = max(a_avg, b_avg)
                min_val = min(a_avg, b_avg)
                overlap_ratio = round(min_val / max_val * 100, 2) if max_val > 0 else 0.0
                if overlap_ratio > 70:
                    results.append(
                        {
                            "feed_a": feed_names[i],
                            "feed_b": feed_names[j],
                            "avg_iocs_a": round(a_avg, 2),
                            "avg_iocs_b": round(b_avg, 2),
                            "overlap_ratio_pct": overlap_ratio,
                        }
                    )
        results.sort(key=lambda x: x["overlap_ratio_pct"], reverse=True)
        return results

    def compute_feed_roi(self) -> list[dict[str, Any]]:
        """Compute ROI per feed based on true detections vs. cost."""
        feed_data: dict[str, list[ThreatFeedRecord]] = {}
        for r in self._records:
            feed_data.setdefault(r.feed_name, []).append(r)
        results: list[dict[str, Any]] = []
        for name, recs in feed_data.items():
            total_detections = sum(r.true_detections for r in recs)
            total_cost = sum(r.cost_per_month for r in recs)
            avg_cost = round(total_cost / len(recs), 2)
            cost_per_detection = (
                round(avg_cost / total_detections, 2) if total_detections > 0 else 0.0
            )
            roi_score = round(total_detections / avg_cost, 4) if avg_cost > 0 else 0.0
            results.append(
                {
                    "feed_name": name,
                    "total_detections": total_detections,
                    "avg_cost_per_month": avg_cost,
                    "cost_per_detection": cost_per_detection,
                    "roi_score": roi_score,
                    "feed_tier": recs[0].feed_tier.value,
                }
            )
        results.sort(key=lambda x: x["roi_score"], reverse=True)
        return results
