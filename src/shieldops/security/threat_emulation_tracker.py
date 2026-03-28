"""Threat Emulation Tracker — track emulations and map to MITRE."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EmulationScope(StrEnum):
    SINGLE_HOST = "single_host"
    NETWORK_SEGMENT = "network_segment"
    FULL_ENVIRONMENT = "full_environment"
    CLOUD_ONLY = "cloud_only"
    HYBRID = "hybrid"


class TTPMapping(StrEnum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"


class DetectionGap(StrEnum):
    NONE = "none"
    PARTIAL = "partial"
    SIGNIFICANT = "significant"
    CRITICAL = "critical"


# --- Models ---


class EmulationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    emulation_name: str = ""
    scope: EmulationScope = EmulationScope.SINGLE_HOST
    ttp: TTPMapping = TTPMapping.INITIAL_ACCESS
    gap: DetectionGap = DetectionGap.NONE
    score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class EmulationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    emulation_name: str = ""
    scope: EmulationScope = EmulationScope.SINGLE_HOST
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class EmulationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_score: float = 0.0
    by_scope: dict[str, int] = Field(default_factory=dict)
    by_ttp: dict[str, int] = Field(default_factory=dict)
    by_gap: dict[str, int] = Field(default_factory=dict)
    critical_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ThreatEmulationTracker:
    """Track threat emulations and identify gaps."""

    def __init__(
        self,
        max_records: int = 200000,
        gap_threshold: float = 50.0,
    ) -> None:
        self._max = max_records
        self._gap_threshold = gap_threshold
        self._records: list[EmulationRecord] = []
        self._analyses: list[EmulationAnalysis] = []
        logger.info(
            "threat_emulation_tracker.initialized",
            max_records=max_records,
        )

    def add_record(
        self,
        emulation_name: str = "",
        scope: EmulationScope = (EmulationScope.SINGLE_HOST),
        ttp: TTPMapping = TTPMapping.INITIAL_ACCESS,
        gap: DetectionGap = DetectionGap.NONE,
        score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> EmulationRecord:
        rec = EmulationRecord(
            emulation_name=emulation_name,
            scope=scope,
            ttp=ttp,
            gap=gap,
            score=score,
            service=service,
            team=team,
        )
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "threat_emulation_tracker.record_added",
            record_id=rec.id,
        )
        return rec

    def process(self, key: str) -> EmulationAnalysis:
        matches = [r for r in self._records if r.emulation_name == key]
        total = sum(r.score for r in matches)
        avg = total / len(matches) if matches else 0.0
        analysis = EmulationAnalysis(
            emulation_name=key,
            analysis_score=round(avg, 2),
            threshold=self._gap_threshold,
            breached=avg < self._gap_threshold,
            description=(f"Tracked {len(matches)} emulations"),
        )
        self._analyses.append(analysis)
        return analysis

    # -- domain methods ---

    def track_emulation(
        self,
        name: str,
        scope: EmulationScope = (EmulationScope.SINGLE_HOST),
    ) -> dict[str, Any]:
        """Track a specific emulation run."""
        matches = [r for r in self._records if r.emulation_name == name]
        return {
            "emulation": name,
            "scope": scope.value,
            "run_count": len(matches),
            "status": "tracked",
        }

    def map_to_mitre(self) -> dict[str, Any]:
        """Map records to MITRE ATT&CK TTPs."""
        ttp_map: dict[str, int] = {}
        for r in self._records:
            k = r.ttp.value
            ttp_map[k] = ttp_map.get(k, 0) + 1
        return {
            "ttp_coverage": ttp_map,
            "total_mapped": len(self._records),
        }

    def identify_detection_gaps(
        self,
    ) -> list[dict[str, Any]]:
        """Find emulations with significant gaps."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.gap in (
                DetectionGap.SIGNIFICANT,
                DetectionGap.CRITICAL,
            ):
                results.append(
                    {
                        "id": r.id,
                        "emulation": r.emulation_name,
                        "gap": r.gap.value,
                        "ttp": r.ttp.value,
                        "score": r.score,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    # -- report / stats ---

    def generate_report(self) -> EmulationReport:
        by_scope: dict[str, int] = {}
        by_ttp: dict[str, int] = {}
        by_gap: dict[str, int] = {}
        for r in self._records:
            s = r.scope.value
            by_scope[s] = by_scope.get(s, 0) + 1
            t = r.ttp.value
            by_ttp[t] = by_ttp.get(t, 0) + 1
            g = r.gap.value
            by_gap[g] = by_gap.get(g, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        critical = [r.emulation_name for r in self._records if r.gap == DetectionGap.CRITICAL][:5]
        recs: list[str] = []
        if critical:
            recs.append(f"{len(critical)} emulation(s) have critical detection gaps")
        if not recs:
            recs.append("Detection coverage adequate")
        return EmulationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_score=avg,
            by_scope=by_scope,
            by_ttp=by_ttp,
            by_gap=by_gap,
            critical_gaps=critical,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.scope.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "gap_threshold": self._gap_threshold,
            "scope_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("threat_emulation_tracker.cleared")
        return {"status": "cleared"}
