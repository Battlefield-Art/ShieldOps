"""AIActComplianceEngine — EU AI Act compliance tracking and assessment."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AIActRiskTier(StrEnum):
    UNACCEPTABLE = "unacceptable"
    HIGH_RISK = "high_risk"
    LIMITED_RISK = "limited_risk"
    MINIMAL_RISK = "minimal_risk"


class ComplianceArticle(StrEnum):
    ART6_CLASSIFICATION = "art6_classification"
    ART9_RISK_MGMT = "art9_risk_mgmt"
    ART10_DATA_GOVERNANCE = "art10_data_governance"
    ART13_TRANSPARENCY = "art13_transparency"
    ART14_HUMAN_OVERSIGHT = "art14_human_oversight"
    ART15_ACCURACY = "art15_accuracy"


class AssessmentStatus(StrEnum):
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    EXEMPT = "exempt"


# --- Models ---


class ComplianceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    system_id: str = ""
    risk_tier: AIActRiskTier = AIActRiskTier.MINIMAL_RISK
    article: ComplianceArticle = ComplianceArticle.ART6_CLASSIFICATION
    assessment_status: AssessmentStatus = AssessmentStatus.PARTIAL
    score: float = 0.0
    evidence_ref: str = ""
    assessor: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ComplianceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    risk_tier: AIActRiskTier = AIActRiskTier.MINIMAL_RISK
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ComplianceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_risk_tier: dict[str, int] = Field(default_factory=dict)
    by_article: dict[str, int] = Field(default_factory=dict)
    by_assessment_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AIActComplianceEngine:
    """EU AI Act compliance tracking and assessment."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[ComplianceRecord] = []
        self._analyses: list[ComplianceAnalysis] = []
        logger.info(
            "ai_act_compliance_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        system_id: str,
        risk_tier: AIActRiskTier = AIActRiskTier.MINIMAL_RISK,
        article: ComplianceArticle = ComplianceArticle.ART6_CLASSIFICATION,
        assessment_status: AssessmentStatus = AssessmentStatus.PARTIAL,
        score: float = 0.0,
        evidence_ref: str = "",
        assessor: str = "",
        service: str = "",
        team: str = "",
    ) -> ComplianceRecord:
        record = ComplianceRecord(
            system_id=system_id,
            risk_tier=risk_tier,
            article=article,
            assessment_status=assessment_status,
            score=score,
            evidence_ref=evidence_ref,
            assessor=assessor,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ai_act_compliance_engine.record_added",
            record_id=record.id,
            system_id=system_id,
            risk_tier=risk_tier.value,
            article=article.value,
        )
        return record

    def get_record(self, record_id: str) -> ComplianceRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        risk_tier: AIActRiskTier | None = None,
        article: ComplianceArticle | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ComplianceRecord]:
        results = list(self._records)
        if risk_tier is not None:
            results = [r for r in results if r.risk_tier == risk_tier]
        if article is not None:
            results = [r for r in results if r.article == article]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        risk_tier: AIActRiskTier = AIActRiskTier.MINIMAL_RISK,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ComplianceAnalysis:
        analysis = ComplianceAnalysis(
            name=name,
            risk_tier=risk_tier,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "ai_act_compliance_engine.analysis_added",
            name=name,
            risk_tier=risk_tier.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def classify_risk_tier(self) -> list[dict[str, Any]]:
        """Classify AI systems by EU AI Act risk tier with compliance summary."""
        system_data: dict[str, list[ComplianceRecord]] = {}
        for r in self._records:
            system_data.setdefault(r.system_id, []).append(r)
        tier_order = {
            AIActRiskTier.UNACCEPTABLE: 0,
            AIActRiskTier.HIGH_RISK: 1,
            AIActRiskTier.LIMITED_RISK: 2,
            AIActRiskTier.MINIMAL_RISK: 3,
        }
        results: list[dict[str, Any]] = []
        for system_id, records in system_data.items():
            tiers = {r.risk_tier for r in records}
            highest_tier = min(tiers, key=lambda t: tier_order.get(t, 99))
            non_compliant = sum(
                1 for r in records if r.assessment_status == AssessmentStatus.NON_COMPLIANT
            )
            compliant = sum(1 for r in records if r.assessment_status == AssessmentStatus.COMPLIANT)
            results.append(
                {
                    "system_id": system_id,
                    "assigned_risk_tier": highest_tier.value,
                    "articles_assessed": len(records),
                    "compliant_count": compliant,
                    "non_compliant_count": non_compliant,
                    "compliance_rate_pct": round(compliant / len(records) * 100, 2)
                    if records
                    else 0.0,
                    "action_required": highest_tier == AIActRiskTier.UNACCEPTABLE
                    or non_compliant > 0,
                }
            )
        return sorted(results, key=lambda x: x["compliance_rate_pct"])

    def assess_article_compliance(self) -> list[dict[str, Any]]:
        """Assess compliance status per article across all systems."""
        article_data: dict[str, list[ComplianceRecord]] = {}
        for r in self._records:
            article_data.setdefault(r.article.value, []).append(r)
        results: list[dict[str, Any]] = []
        for article, records in article_data.items():
            statuses = {s.value: 0 for s in AssessmentStatus}
            for r in records:
                statuses[r.assessment_status.value] += 1
            scores = [r.score for r in records]
            avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
            results.append(
                {
                    "article": article,
                    "total_assessments": len(records),
                    "status_breakdown": statuses,
                    "avg_score": avg_score,
                    "systems_assessed": len({r.system_id for r in records}),
                    "fully_compliant": statuses.get("compliant", 0) == len(records),
                }
            )
        return sorted(results, key=lambda x: x["avg_score"])

    def generate_conformity_assessment(self) -> list[dict[str, Any]]:
        """Generate conformity assessment documents per system for EU AI Act."""
        system_data: dict[str, list[ComplianceRecord]] = {}
        for r in self._records:
            system_data.setdefault(r.system_id, []).append(r)
        assessments: list[dict[str, Any]] = []
        for system_id, records in system_data.items():
            article_results: dict[str, str] = {}
            for r in records:
                article_results[r.article.value] = r.assessment_status.value
            all_articles = set(ComplianceArticle)
            assessed_articles = {r.article for r in records}
            missing_articles = all_articles - assessed_articles
            tiers = {r.risk_tier for r in records}
            scores = [r.score for r in records]
            avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
            overall = "compliant"
            if any(v == "non_compliant" for v in article_results.values()):
                overall = "non_compliant"
            elif any(v == "partial" for v in article_results.values()) or missing_articles:
                overall = "partial"
            assessments.append(
                {
                    "system_id": system_id,
                    "risk_tiers": sorted(t.value for t in tiers),
                    "article_results": article_results,
                    "missing_articles": sorted(a.value for a in missing_articles),
                    "overall_status": overall,
                    "avg_score": avg_score,
                    "evidence_refs": sorted({r.evidence_ref for r in records if r.evidence_ref}),
                }
            )
        return sorted(assessments, key=lambda x: x["overall_status"])

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.risk_tier.value
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
                        "system_id": r.system_id,
                        "risk_tier": r.risk_tier.value,
                        "article": r.article.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, system_id: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.system_id == system_id]
        if not matched:
            return {"key": system_id, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": system_id,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> ComplianceReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.risk_tier.value] = by_e1.get(r.risk_tier.value, 0) + 1
            by_e2[r.article.value] = by_e2.get(r.article.value, 0) + 1
            by_e3[r.assessment_status.value] = by_e3.get(r.assessment_status.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["system_id"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("AI Act Compliance Engine is healthy")
        return ComplianceReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_risk_tier=by_e1,
            by_article=by_e2,
            by_assessment_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("ai_act_compliance_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.risk_tier.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "risk_tier_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
