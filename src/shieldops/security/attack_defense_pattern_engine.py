"""Attack Defense Pattern Engine — track the data flywheel of attack/defense patterns."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PatternSource(StrEnum):
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    VALIDATION = "validation"
    CUSTOMER = "customer"
    THREAT_INTEL = "threat_intel"


class PatternType(StrEnum):
    ATTACK_TTP = "attack_ttp"
    DEFENSE_RULE = "defense_rule"
    DETECTION_SIGNATURE = "detection_signature"
    REMEDIATION_PLAYBOOK = "remediation_playbook"
    EVASION_TECHNIQUE = "evasion_technique"


class PatternMaturity(StrEnum):
    EXPERIMENTAL = "experimental"
    TESTED = "tested"
    PROVEN = "proven"
    DEPRECATED = "deprecated"
    SUPERSEDED = "superseded"


# --- Models ---


class AttackDefensePatternRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pattern_id: str = ""
    pattern_source: PatternSource = PatternSource.RED_TEAM
    pattern_type: PatternType = PatternType.ATTACK_TTP
    pattern_maturity: PatternMaturity = PatternMaturity.EXPERIMENTAL
    effectiveness: float = 0.0
    usage_count: int = 0
    cross_customer_validated: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AttackDefensePatternAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pattern_id: str = ""
    pattern_type: PatternType = PatternType.ATTACK_TTP
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AttackDefensePatternReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_pattern_source: dict[str, int] = Field(default_factory=dict)
    by_pattern_type: dict[str, int] = Field(default_factory=dict)
    by_pattern_maturity: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AttackDefensePatternEngine:
    """Track the data flywheel of attack/defense patterns and maturity."""

    def __init__(
        self,
        max_records: int = 200000,
        maturity_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = maturity_threshold
        self._records: list[AttackDefensePatternRecord] = []
        self._analyses: list[AttackDefensePatternAnalysis] = []
        logger.info(
            "attack_defense_pattern_engine.initialized",
            max_records=max_records,
            maturity_threshold=maturity_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        pattern_id: str,
        pattern_source: PatternSource = PatternSource.RED_TEAM,
        pattern_type: PatternType = PatternType.ATTACK_TTP,
        pattern_maturity: PatternMaturity = PatternMaturity.EXPERIMENTAL,
        effectiveness: float = 0.0,
        usage_count: int = 0,
        cross_customer_validated: bool = False,
        service: str = "",
        team: str = "",
    ) -> AttackDefensePatternRecord:
        record = AttackDefensePatternRecord(
            pattern_id=pattern_id,
            pattern_source=pattern_source,
            pattern_type=pattern_type,
            pattern_maturity=pattern_maturity,
            effectiveness=effectiveness,
            usage_count=usage_count,
            cross_customer_validated=cross_customer_validated,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "attack_defense_pattern_engine.record_added",
            record_id=record.id,
            pattern_id=pattern_id,
            pattern_source=pattern_source.value,
            pattern_type=pattern_type.value,
        )
        return record

    def get_record(self, record_id: str) -> AttackDefensePatternRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        pattern_source: PatternSource | None = None,
        pattern_type: PatternType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AttackDefensePatternRecord]:
        results = list(self._records)
        if pattern_source is not None:
            results = [r for r in results if r.pattern_source == pattern_source]
        if pattern_type is not None:
            results = [r for r in results if r.pattern_type == pattern_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        pattern_id: str,
        pattern_type: PatternType = PatternType.ATTACK_TTP,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AttackDefensePatternAnalysis:
        analysis = AttackDefensePatternAnalysis(
            pattern_id=pattern_id,
            pattern_type=pattern_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "attack_defense_pattern_engine.analysis_added",
            pattern_id=pattern_id,
            pattern_type=pattern_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_pattern_distribution(self) -> list[dict[str, Any]]:
        """Analyze distribution of patterns by source and type."""
        src_data: dict[str, list[float]] = {}
        for r in self._records:
            src_data.setdefault(r.pattern_source.value, []).append(r.effectiveness)
        results: list[dict[str, Any]] = []
        for src, scores in src_data.items():
            avg = round(sum(scores) / len(scores), 2) if scores else 0.0
            proven = sum(
                1
                for r in self._records
                if r.pattern_source.value == src and r.pattern_maturity == PatternMaturity.PROVEN
            )
            results.append(
                {
                    "pattern_source": src,
                    "count": len(scores),
                    "avg_effectiveness": avg,
                    "proven_count": proven,
                    "cross_validated": sum(
                        1
                        for r in self._records
                        if r.pattern_source.value == src and r.cross_customer_validated
                    ),
                }
            )
        return sorted(results, key=lambda x: x["avg_effectiveness"], reverse=True)

    def identify_proven_patterns(self) -> list[dict[str, Any]]:
        """Identify proven patterns with high effectiveness."""
        proven: list[dict[str, Any]] = []
        for r in self._records:
            if r.pattern_maturity == PatternMaturity.PROVEN and r.effectiveness >= self._threshold:
                proven.append(
                    {
                        "record_id": r.id,
                        "pattern_id": r.pattern_id,
                        "pattern_type": r.pattern_type.value,
                        "pattern_source": r.pattern_source.value,
                        "effectiveness": r.effectiveness,
                        "usage_count": r.usage_count,
                        "cross_customer_validated": r.cross_customer_validated,
                        "service": r.service,
                    }
                )
        return sorted(proven, key=lambda x: x["effectiveness"], reverse=True)

    def detect_flywheel_growth(self) -> list[dict[str, Any]]:
        """Detect flywheel growth by tracking pattern maturity progression."""
        type_maturity: dict[str, dict[str, int]] = {}
        for r in self._records:
            pt = r.pattern_type.value
            type_maturity.setdefault(pt, {})
            mat = r.pattern_maturity.value
            type_maturity[pt][mat] = type_maturity[pt].get(mat, 0) + 1
        results: list[dict[str, Any]] = []
        for pt, mats in type_maturity.items():
            total = sum(mats.values())
            proven_pct = round(mats.get("proven", 0) / total * 100, 2) if total > 0 else 0.0
            results.append(
                {
                    "pattern_type": pt,
                    "total_patterns": total,
                    "maturity_distribution": mats,
                    "proven_pct": proven_pct,
                    "experimental_count": mats.get("experimental", 0),
                }
            )
        return sorted(results, key=lambda x: x["proven_pct"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def generate_report(self) -> AttackDefensePatternReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.pattern_source.value] = by_e1.get(r.pattern_source.value, 0) + 1
            by_e2[r.pattern_type.value] = by_e2.get(r.pattern_type.value, 0) + 1
            by_e3[r.pattern_maturity.value] = by_e3.get(r.pattern_maturity.value, 0) + 1
        scores = [r.effectiveness for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for s in scores if s < self._threshold)
        gaps = [r.pattern_id for r in self._records if r.effectiveness < self._threshold]
        top_gaps = gaps[:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} pattern(s) below threshold ({self._threshold})")
        if avg_score < self._threshold:
            recs.append(f"Avg effectiveness {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Attack Defense Pattern Engine is healthy")
        return AttackDefensePatternReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_pattern_source=by_e1,
            by_pattern_type=by_e2,
            by_pattern_maturity=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("attack_defense_pattern_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.pattern_source.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "maturity_threshold": self._threshold,
            "pattern_source_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
