"""APT Campaign Engine — design and track APT campaigns."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CampaignComplexity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    ADVANCED = "advanced"
    NATION_STATE = "nation_state"


class APTGroup(StrEnum):
    APT28 = "apt28"
    APT29 = "apt29"
    APT41 = "apt41"
    LAZARUS = "lazarus"
    CUSTOM = "custom"


class EvasionLevel(StrEnum):
    NONE = "none"
    BASIC = "basic"
    MODERATE = "moderate"
    ADVANCED = "advanced"
    ELITE = "elite"


# --- Models ---


class CampaignRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_name: str = ""
    complexity: CampaignComplexity = CampaignComplexity.MEDIUM
    apt_group: APTGroup = APTGroup.CUSTOM
    evasion_level: EvasionLevel = EvasionLevel.BASIC
    score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CampaignAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_name: str = ""
    complexity: CampaignComplexity = CampaignComplexity.MEDIUM
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CampaignReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_score: float = 0.0
    by_complexity: dict[str, int] = Field(default_factory=dict)
    by_group: dict[str, int] = Field(default_factory=dict)
    by_evasion: dict[str, int] = Field(default_factory=dict)
    high_evasion: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class APTCampaignEngine:
    """Design, track, and score APT emulation campaigns."""

    def __init__(
        self,
        max_records: int = 200000,
        evasion_threshold: float = 60.0,
    ) -> None:
        self._max = max_records
        self._evasion_threshold = evasion_threshold
        self._records: list[CampaignRecord] = []
        self._analyses: list[CampaignAnalysis] = []
        logger.info(
            "apt_campaign_engine.initialized",
            max_records=max_records,
        )

    def add_record(
        self,
        campaign_name: str = "",
        complexity: CampaignComplexity = (CampaignComplexity.MEDIUM),
        apt_group: APTGroup = APTGroup.CUSTOM,
        evasion_level: EvasionLevel = (EvasionLevel.BASIC),
        score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> CampaignRecord:
        rec = CampaignRecord(
            campaign_name=campaign_name,
            complexity=complexity,
            apt_group=apt_group,
            evasion_level=evasion_level,
            score=score,
            service=service,
            team=team,
        )
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "apt_campaign_engine.record_added",
            record_id=rec.id,
        )
        return rec

    def process(self, key: str) -> CampaignAnalysis:
        matches = [r for r in self._records if r.campaign_name == key]
        total = sum(r.score for r in matches)
        avg = total / len(matches) if matches else 0.0
        analysis = CampaignAnalysis(
            campaign_name=key,
            analysis_score=round(avg, 2),
            threshold=self._evasion_threshold,
            breached=avg > self._evasion_threshold,
            description=f"Analyzed {len(matches)} records",
        )
        self._analyses.append(analysis)
        return analysis

    # -- domain methods ---

    def design_campaign(
        self,
        name: str,
        group: APTGroup = APTGroup.CUSTOM,
        complexity: CampaignComplexity = (CampaignComplexity.MEDIUM),
    ) -> dict[str, Any]:
        """Design a new APT campaign scaffold."""
        return {
            "campaign_name": name,
            "apt_group": group.value,
            "complexity": complexity.value,
            "phases": [
                "recon",
                "initial_access",
                "execution",
                "persistence",
                "lateral_movement",
                "exfiltration",
            ],
            "status": "designed",
        }

    def track_phase_results(
        self,
    ) -> list[dict[str, Any]]:
        """Group records by complexity, return counts."""
        buckets: dict[str, list[float]] = {}
        for r in self._records:
            k = r.complexity.value
            buckets.setdefault(k, []).append(r.score)
        results: list[dict[str, Any]] = []
        for comp, scores in buckets.items():
            avg = sum(scores) / len(scores)
            results.append(
                {
                    "complexity": comp,
                    "count": len(scores),
                    "avg_score": round(avg, 2),
                }
            )
        return results

    def calculate_evasion_rate(self) -> dict[str, Any]:
        """Calculate evasion success rate."""
        if not self._records:
            return {"rate": 0.0, "total": 0}
        evaded = sum(1 for r in self._records if r.score > self._evasion_threshold)
        rate = round(evaded / len(self._records), 4)
        return {
            "rate": rate,
            "evaded": evaded,
            "total": len(self._records),
        }

    # -- report / stats ---

    def generate_report(self) -> CampaignReport:
        by_complexity: dict[str, int] = {}
        by_group: dict[str, int] = {}
        by_evasion: dict[str, int] = {}
        for r in self._records:
            c = r.complexity.value
            by_complexity[c] = by_complexity.get(c, 0) + 1
            g = r.apt_group.value
            by_group[g] = by_group.get(g, 0) + 1
            e = r.evasion_level.value
            by_evasion[e] = by_evasion.get(e, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        high = [r.campaign_name for r in self._records if r.score > self._evasion_threshold][:5]
        recs: list[str] = []
        if high:
            recs.append(f"{len(high)} campaign(s) above evasion threshold")
        if not recs:
            recs.append("Campaign evasion rates normal")
        return CampaignReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_score=avg,
            by_complexity=by_complexity,
            by_group=by_group,
            by_evasion=by_evasion,
            high_evasion=high,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        grp: dict[str, int] = {}
        for r in self._records:
            k = r.apt_group.value
            grp[k] = grp.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "evasion_threshold": self._evasion_threshold,
            "group_distribution": grp,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("apt_campaign_engine.cleared")
        return {"status": "cleared"}
