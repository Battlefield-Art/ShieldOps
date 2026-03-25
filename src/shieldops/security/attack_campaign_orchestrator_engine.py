"""Attack Campaign Orchestrator Engine — track and analyze attack simulation campaigns."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CampaignType(StrEnum):
    RED_TEAM = "red_team"
    PURPLE_TEAM = "purple_team"
    TABLETOP = "tabletop"
    AUTOMATED = "automated"
    CONTINUOUS = "continuous"


class CampaignPhase(StrEnum):
    PLANNING = "planning"
    EXECUTION = "execution"
    ASSESSMENT = "assessment"
    REPORTING = "reporting"
    REMEDIATION = "remediation"


class CampaignOutcome(StrEnum):
    SUCCESSFUL_BREACH = "successful_breach"
    DETECTED_AND_BLOCKED = "detected_and_blocked"
    PARTIALLY_DETECTED = "partially_detected"
    UNDETECTED = "undetected"
    ABORTED = "aborted"


# --- Models ---


class CampaignRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_name: str = ""
    campaign_type: CampaignType = CampaignType.AUTOMATED
    campaign_phase: CampaignPhase = CampaignPhase.PLANNING
    campaign_outcome: CampaignOutcome = CampaignOutcome.DETECTED_AND_BLOCKED
    ttps_executed: int = 0
    ttps_blocked: int = 0
    detection_rate: float = 0.0
    mean_detection_ms: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CampaignAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_name: str = ""
    campaign_type: CampaignType = CampaignType.AUTOMATED
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CampaignReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    breach_count: int = 0
    avg_detection_rate: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_phase: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AttackCampaignOrchestratorEngine:
    """Track and analyze attack simulation campaigns."""

    def __init__(
        self,
        max_records: int = 200000,
        detection_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = detection_threshold
        self._records: list[CampaignRecord] = []
        self._analyses: list[CampaignAnalysis] = []
        logger.info(
            "attack_campaign_orchestrator_engine.initialized",
            max_records=max_records,
            detection_threshold=detection_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        campaign_name: str,
        campaign_type: CampaignType = CampaignType.AUTOMATED,
        campaign_phase: CampaignPhase = CampaignPhase.PLANNING,
        campaign_outcome: CampaignOutcome = CampaignOutcome.DETECTED_AND_BLOCKED,
        ttps_executed: int = 0,
        ttps_blocked: int = 0,
        detection_rate: float = 0.0,
        mean_detection_ms: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> CampaignRecord:
        record = CampaignRecord(
            campaign_name=campaign_name,
            campaign_type=campaign_type,
            campaign_phase=campaign_phase,
            campaign_outcome=campaign_outcome,
            ttps_executed=ttps_executed,
            ttps_blocked=ttps_blocked,
            detection_rate=detection_rate,
            mean_detection_ms=mean_detection_ms,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "attack_campaign_orchestrator_engine.record_added",
            record_id=record.id,
            campaign_name=campaign_name,
            campaign_type=campaign_type.value,
            campaign_outcome=campaign_outcome.value,
        )
        return record

    def get_record(self, record_id: str) -> CampaignRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        campaign_type: CampaignType | None = None,
        campaign_phase: CampaignPhase | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CampaignRecord]:
        results = list(self._records)
        if campaign_type is not None:
            results = [r for r in results if r.campaign_type == campaign_type]
        if campaign_phase is not None:
            results = [r for r in results if r.campaign_phase == campaign_phase]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        campaign_name: str,
        campaign_type: CampaignType = CampaignType.AUTOMATED,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CampaignAnalysis:
        analysis = CampaignAnalysis(
            campaign_name=campaign_name,
            campaign_type=campaign_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "attack_campaign_orchestrator_engine.analysis_added",
            campaign_name=campaign_name,
            campaign_type=campaign_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_campaign_effectiveness(self) -> list[dict[str, Any]]:
        """Analyze effectiveness of campaigns by type and outcome."""
        type_data: dict[str, list[CampaignRecord]] = {}
        for r in self._records:
            type_data.setdefault(r.campaign_type.value, []).append(r)
        results: list[dict[str, Any]] = []
        for ctype, records in type_data.items():
            rates = [r.detection_rate for r in records]
            avg_rate = round(sum(rates) / len(rates), 2) if rates else 0.0
            blocked = sum(
                1 for r in records if r.campaign_outcome == CampaignOutcome.DETECTED_AND_BLOCKED
            )
            undetected = sum(1 for r in records if r.campaign_outcome == CampaignOutcome.UNDETECTED)
            results.append(
                {
                    "campaign_type": ctype,
                    "total_campaigns": len(records),
                    "avg_detection_rate": avg_rate,
                    "blocked_count": blocked,
                    "undetected_count": undetected,
                    "effectiveness": "strong"
                    if avg_rate >= 90
                    else "adequate"
                    if avg_rate >= self._threshold
                    else "weak"
                    if avg_rate >= 50
                    else "critical",
                }
            )
        return sorted(results, key=lambda x: x["avg_detection_rate"])

    def identify_defense_gaps(self) -> list[dict[str, Any]]:
        """Identify gaps where TTPs were not blocked."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.detection_rate < self._threshold:
                gap_ttps = r.ttps_executed - r.ttps_blocked
                results.append(
                    {
                        "record_id": r.id,
                        "campaign_name": r.campaign_name,
                        "campaign_type": r.campaign_type.value,
                        "detection_rate": r.detection_rate,
                        "ttps_missed": gap_ttps,
                        "service": r.service,
                        "team": r.team,
                        "severity": "critical"
                        if r.detection_rate < 30
                        else "high"
                        if r.detection_rate < 50
                        else "medium"
                        if r.detection_rate < self._threshold
                        else "low",
                    }
                )
        return sorted(results, key=lambda x: x["detection_rate"])

    def detect_improvement_trends(self) -> list[dict[str, Any]]:
        """Detect improvement trends over time by team."""
        team_data: dict[str, list[CampaignRecord]] = {}
        for r in self._records:
            team_data.setdefault(r.team, []).append(r)
        results: list[dict[str, Any]] = []
        for team_name, records in team_data.items():
            sorted_recs = sorted(records, key=lambda x: x.created_at)
            if len(sorted_recs) < 2:
                continue
            mid = len(sorted_recs) // 2
            first_half = sorted_recs[:mid]
            second_half = sorted_recs[mid:]
            avg_first = round(sum(r.detection_rate for r in first_half) / len(first_half), 2)
            avg_second = round(sum(r.detection_rate for r in second_half) / len(second_half), 2)
            delta = round(avg_second - avg_first, 2)
            results.append(
                {
                    "team": team_name,
                    "campaigns_count": len(records),
                    "early_avg_detection": avg_first,
                    "recent_avg_detection": avg_second,
                    "delta": delta,
                    "trend": "improving" if delta > 5 else "stable" if delta > -5 else "declining",
                }
            )
        return sorted(results, key=lambda x: x["delta"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.campaign_name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        rates = [r.detection_rate for r in matched]
        avg = round(sum(rates) / len(rates), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_detection_rate": avg,
            "below_threshold": sum(1 for s in rates if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> CampaignReport:
        by_type: dict[str, int] = {}
        by_phase: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        for r in self._records:
            by_type[r.campaign_type.value] = by_type.get(r.campaign_type.value, 0) + 1
            by_phase[r.campaign_phase.value] = by_phase.get(r.campaign_phase.value, 0) + 1
            by_outcome[r.campaign_outcome.value] = by_outcome.get(r.campaign_outcome.value, 0) + 1
        breach_count = sum(1 for r in self._records if r.detection_rate < self._threshold)
        rates = [r.detection_rate for r in self._records]
        avg_rate = round(sum(rates) / len(rates), 2) if rates else 0.0
        gap_list = self.identify_defense_gaps()
        top_gaps = [g["campaign_name"] for g in gap_list[:5]]
        recs: list[str] = []
        if self._records and breach_count > 0:
            recs.append(
                f"{breach_count} campaign(s) below detection threshold ({self._threshold}%)"
            )
        if self._records and avg_rate < self._threshold:
            recs.append(f"Avg detection rate {avg_rate}% below threshold ({self._threshold}%)")
        if not recs:
            recs.append("Attack Campaign Orchestrator Engine is healthy")
        return CampaignReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            breach_count=breach_count,
            avg_detection_rate=avg_rate,
            by_type=by_type,
            by_phase=by_phase,
            by_outcome=by_outcome,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("attack_campaign_orchestrator_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            key = r.campaign_type.value
            type_dist[key] = type_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "detection_threshold": self._threshold,
            "type_distribution": type_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
