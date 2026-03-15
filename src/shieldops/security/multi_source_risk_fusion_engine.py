"""Multi-Source Risk Fusion Engine —
fuse multi-source risk signals, detect source disagreement,
evaluate source contribution."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SourceCategory(StrEnum):
    SIEM = "siem"
    EDR = "edr"
    NDR = "ndr"
    CASB = "casb"


class FusionMethod(StrEnum):
    DEMPSTER_SHAFER = "dempster_shafer"
    WEIGHTED_AVERAGE = "weighted_average"
    VOTING = "voting"
    HIERARCHICAL = "hierarchical"


class SourceAgreement(StrEnum):
    CONSENSUS = "consensus"
    MAJORITY = "majority"
    SPLIT = "split"
    CONTRADICTORY = "contradictory"


# --- Models ---


class MultiSourceRiskRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = ""
    source_category: SourceCategory = SourceCategory.SIEM
    fusion_method: FusionMethod = FusionMethod.WEIGHTED_AVERAGE
    source_agreement: SourceAgreement = SourceAgreement.CONSENSUS
    source_id: str = ""
    risk_score: float = 0.0
    source_weight: float = 1.0
    confidence: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MultiSourceRiskAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = ""
    fusion_method: FusionMethod = FusionMethod.WEIGHTED_AVERAGE
    fused_risk_score: float = 0.0
    source_agreement: SourceAgreement = SourceAgreement.CONSENSUS
    disagreement_detected: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MultiSourceRiskReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_fused_risk: float = 0.0
    by_source_category: dict[str, int] = Field(default_factory=dict)
    by_fusion_method: dict[str, int] = Field(default_factory=dict)
    by_source_agreement: dict[str, int] = Field(default_factory=dict)
    contradictory_entity_ids: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class MultiSourceRiskFusionEngine:
    """Fuse multi-source risk signals, detect source disagreement,
    evaluate source contribution."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[MultiSourceRiskRecord] = []
        self._analyses: dict[str, MultiSourceRiskAnalysis] = {}
        logger.info("multi_source_risk_fusion_engine.init", max_records=max_records)

    def add_record(
        self,
        entity_id: str = "",
        source_category: SourceCategory = SourceCategory.SIEM,
        fusion_method: FusionMethod = FusionMethod.WEIGHTED_AVERAGE,
        source_agreement: SourceAgreement = SourceAgreement.CONSENSUS,
        source_id: str = "",
        risk_score: float = 0.0,
        source_weight: float = 1.0,
        confidence: float = 0.0,
        description: str = "",
    ) -> MultiSourceRiskRecord:
        record = MultiSourceRiskRecord(
            entity_id=entity_id,
            source_category=source_category,
            fusion_method=fusion_method,
            source_agreement=source_agreement,
            source_id=source_id,
            risk_score=risk_score,
            source_weight=source_weight,
            confidence=confidence,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "multi_source_risk.record_added",
            record_id=record.id,
            entity_id=entity_id,
        )
        return record

    def process(self, key: str) -> MultiSourceRiskAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        entity_recs = [r for r in self._records if r.entity_id == rec.entity_id]
        fused = self._fuse_scores(entity_recs, rec.fusion_method)
        scores = [r.risk_score for r in entity_recs]
        disagreement = (max(scores) - min(scores)) > 40 if len(scores) > 1 else False
        agreement = SourceAgreement.CONTRADICTORY if disagreement else SourceAgreement.CONSENSUS
        analysis = MultiSourceRiskAnalysis(
            entity_id=rec.entity_id,
            fusion_method=rec.fusion_method,
            fused_risk_score=round(fused, 4),
            source_agreement=agreement,
            disagreement_detected=disagreement,
            description=f"Entity {rec.entity_id} fused risk={fused:.4f}",
        )
        self._analyses[key] = analysis
        return analysis

    @staticmethod
    def _fuse_scores(
        recs: list[MultiSourceRiskRecord],
        method: FusionMethod,
    ) -> float:
        if not recs:
            return 0.0
        if method == FusionMethod.WEIGHTED_AVERAGE:
            total_w = sum(r.source_weight for r in recs)
            if total_w == 0:
                return 0.0
            return sum(r.risk_score * r.source_weight for r in recs) / total_w
        if method == FusionMethod.VOTING:
            high = sum(1 for r in recs if r.risk_score >= 50)
            return 80.0 if high > len(recs) / 2 else 20.0
        if method == FusionMethod.HIERARCHICAL:
            return max(r.risk_score for r in recs)
        return sum(r.risk_score for r in recs) / len(recs)

    def generate_report(self) -> MultiSourceRiskReport:
        by_sc: dict[str, int] = {}
        by_fm: dict[str, int] = {}
        by_sa: dict[str, int] = {}
        scores: list[float] = []
        for r in self._records:
            by_sc[r.source_category.value] = by_sc.get(r.source_category.value, 0) + 1
            by_fm[r.fusion_method.value] = by_fm.get(r.fusion_method.value, 0) + 1
            by_sa[r.source_agreement.value] = by_sa.get(r.source_agreement.value, 0) + 1
            scores.append(r.risk_score)
        avg_r = round(sum(scores) / len(scores), 4) if scores else 0.0
        contra = list(
            {
                r.entity_id
                for r in self._records
                if r.source_agreement == SourceAgreement.CONTRADICTORY and r.entity_id
            }
        )[:10]
        recs: list[str] = []
        if contra:
            recs.append(f"{len(contra)} entities with contradictory source signals")
        if not recs:
            recs.append("Source risk fusion signals in agreement")
        return MultiSourceRiskReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_fused_risk=avg_r,
            by_source_category=by_sc,
            by_fusion_method=by_fm,
            by_source_agreement=by_sa,
            contradictory_entity_ids=contra,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        sc_dist: dict[str, int] = {}
        for r in self._records:
            sc_dist[r.source_category.value] = sc_dist.get(r.source_category.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "source_category_distribution": sc_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("multi_source_risk_fusion_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def fuse_multi_source_risk(self) -> list[dict[str, Any]]:
        """Fuse risk scores from multiple sources per entity."""
        entity_recs: dict[str, list[MultiSourceRiskRecord]] = {}
        for r in self._records:
            entity_recs.setdefault(r.entity_id, []).append(r)
        results: list[dict[str, Any]] = []
        for eid, recs in entity_recs.items():
            method = recs[-1].fusion_method
            fused = self._fuse_scores(recs, method)
            sources = list({r.source_category.value for r in recs})
            results.append(
                {
                    "entity_id": eid,
                    "fused_risk_score": round(fused, 4),
                    "fusion_method": method.value,
                    "source_count": len(recs),
                    "source_categories": sources,
                }
            )
        results.sort(key=lambda x: x["fused_risk_score"], reverse=True)
        return results

    def detect_source_disagreement(
        self, disagreement_threshold: float = 40.0
    ) -> list[dict[str, Any]]:
        """Detect entities where sources disagree significantly on risk."""
        entity_recs: dict[str, list[MultiSourceRiskRecord]] = {}
        for r in self._records:
            entity_recs.setdefault(r.entity_id, []).append(r)
        results: list[dict[str, Any]] = []
        for eid, recs in entity_recs.items():
            if len(recs) < 2:
                continue
            scores = [r.risk_score for r in recs]
            score_range = max(scores) - min(scores)
            if score_range > disagreement_threshold:
                results.append(
                    {
                        "entity_id": eid,
                        "score_range": round(score_range, 4),
                        "max_score": max(scores),
                        "min_score": min(scores),
                        "source_count": len(recs),
                        "agreement_level": SourceAgreement.CONTRADICTORY.value,
                    }
                )
        results.sort(key=lambda x: x["score_range"], reverse=True)
        return results

    def evaluate_source_contribution(self) -> list[dict[str, Any]]:
        """Evaluate each source category's contribution to overall risk."""
        source_data: dict[str, list[MultiSourceRiskRecord]] = {}
        for r in self._records:
            source_data.setdefault(r.source_category.value, []).append(r)
        total_risk = sum(r.risk_score for r in self._records)
        results: list[dict[str, Any]] = []
        for src, recs in source_data.items():
            src_total = sum(r.risk_score for r in recs)
            avg_weight = round(sum(r.source_weight for r in recs) / len(recs), 4)
            share = round(src_total / total_risk * 100, 2) if total_risk else 0.0
            results.append(
                {
                    "source_category": src,
                    "total_risk_contributed": round(src_total, 4),
                    "share_pct": share,
                    "avg_source_weight": avg_weight,
                    "record_count": len(recs),
                }
            )
        results.sort(key=lambda x: x["share_pct"], reverse=True)
        return results
