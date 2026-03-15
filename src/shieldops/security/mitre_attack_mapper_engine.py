"""MITRE ATT&CK Mapper Engine — map security observations to MITRE ATT&CK
tactics and techniques, track coverage, identify gaps."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AttackPhase(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class DetectionCoverage(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"
    UNTESTED = "untested"


class MappingConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNMAPPED = "unmapped"


# --- Models ---


class MitreAttackRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detection_name: str = ""
    tactic: str = ""
    technique: str = ""
    attack_phase: AttackPhase = AttackPhase.RECONNAISSANCE
    detection_coverage: DetectionCoverage = DetectionCoverage.UNTESTED
    mapping_confidence: MappingConfidence = MappingConfidence.UNMAPPED
    score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MitreAttackAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detection_name: str = ""
    tactic: str = ""
    coverage_score: float = 0.0
    confidence_avg: float = 0.0
    gap_count: int = 0
    detection_coverage: DetectionCoverage = DetectionCoverage.UNTESTED
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MitreAttackReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_confidence: float = 0.0
    by_attack_phase: dict[str, int] = Field(default_factory=dict)
    by_detection_coverage: dict[str, int] = Field(default_factory=dict)
    by_mapping_confidence: dict[str, int] = Field(default_factory=dict)
    coverage_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---

_CONFIDENCE_SCORES: dict[MappingConfidence, float] = {
    MappingConfidence.HIGH: 1.0,
    MappingConfidence.MEDIUM: 0.6,
    MappingConfidence.LOW: 0.3,
    MappingConfidence.UNMAPPED: 0.0,
}


class MitreAttackMapperEngine:
    """Map security observations to MITRE ATT&CK tactics and techniques,
    track coverage, identify gaps."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[MitreAttackRecord] = []
        self._analyses: dict[str, MitreAttackAnalysis] = {}
        logger.info(
            "mitre_attack_mapper_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        detection_name: str = "",
        tactic: str = "",
        technique: str = "",
        attack_phase: AttackPhase = AttackPhase.RECONNAISSANCE,
        detection_coverage: DetectionCoverage = DetectionCoverage.UNTESTED,
        mapping_confidence: MappingConfidence = MappingConfidence.UNMAPPED,
        score: float = 0.0,
        description: str = "",
    ) -> MitreAttackRecord:
        record = MitreAttackRecord(
            detection_name=detection_name,
            tactic=tactic,
            technique=technique,
            attack_phase=attack_phase,
            detection_coverage=detection_coverage,
            mapping_confidence=mapping_confidence,
            score=score,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "mitre_attack_mapper_engine.record_added",
            record_id=record.id,
            detection_name=detection_name,
            tactic=tactic,
        )
        return record

    def process(self, key: str) -> MitreAttackAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        tactic_records = [r for r in self._records if r.tactic == rec.tactic]
        conf_vals = [_CONFIDENCE_SCORES.get(r.mapping_confidence, 0.0) for r in tactic_records]
        conf_avg = round(sum(conf_vals) / len(conf_vals), 2) if conf_vals else 0.0
        covered = sum(
            1
            for r in tactic_records
            if r.detection_coverage in (DetectionCoverage.FULL, DetectionCoverage.PARTIAL)
        )
        coverage_score = round(covered / len(tactic_records) * 100, 2) if tactic_records else 0.0
        gap_count = sum(
            1
            for r in tactic_records
            if r.detection_coverage in (DetectionCoverage.NONE, DetectionCoverage.UNTESTED)
        )
        analysis = MitreAttackAnalysis(
            detection_name=rec.detection_name,
            tactic=rec.tactic,
            coverage_score=coverage_score,
            confidence_avg=conf_avg,
            gap_count=gap_count,
            detection_coverage=rec.detection_coverage,
            description=f"Tactic {rec.tactic} coverage {coverage_score}%",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> MitreAttackReport:
        by_ap: dict[str, int] = {}
        by_dc: dict[str, int] = {}
        by_mc: dict[str, int] = {}
        conf_vals: list[float] = []
        for r in self._records:
            by_ap[r.attack_phase.value] = by_ap.get(r.attack_phase.value, 0) + 1
            by_dc[r.detection_coverage.value] = by_dc.get(r.detection_coverage.value, 0) + 1
            by_mc[r.mapping_confidence.value] = by_mc.get(r.mapping_confidence.value, 0) + 1
            conf_vals.append(_CONFIDENCE_SCORES.get(r.mapping_confidence, 0.0))
        avg_conf = round(sum(conf_vals) / len(conf_vals), 2) if conf_vals else 0.0
        gaps = self.identify_coverage_gaps()
        gap_names = [g["tactic"] for g in gaps[:10]]
        recs: list[str] = []
        if gap_names:
            recs.append(f"{len(gap_names)} tactic(s) have coverage gaps")
        if not recs:
            recs.append("MITRE ATT&CK coverage is healthy")
        return MitreAttackReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_confidence=avg_conf,
            by_attack_phase=by_ap,
            by_detection_coverage=by_dc,
            by_mapping_confidence=by_mc,
            coverage_gaps=gap_names,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        phase_dist: dict[str, int] = {}
        for r in self._records:
            k = r.attack_phase.value
            phase_dist[k] = phase_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "phase_distribution": phase_dist,
            "unique_tactics": len({r.tactic for r in self._records if r.tactic}),
            "unique_techniques": len({r.technique for r in self._records if r.technique}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("mitre_attack_mapper_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def identify_coverage_gaps(self) -> list[dict[str, Any]]:
        """Find MITRE tactics/techniques with no detection coverage."""
        tactic_coverage: dict[str, list[str]] = {}
        for r in self._records:
            if r.tactic:
                tactic_coverage.setdefault(r.tactic, []).append(r.detection_coverage.value)
        results: list[dict[str, Any]] = []
        for tactic, coverages in tactic_coverage.items():
            none_count = sum(1 for c in coverages if c in ("none", "untested"))
            if none_count > 0:
                results.append(
                    {
                        "tactic": tactic,
                        "total_detections": len(coverages),
                        "uncovered_count": none_count,
                        "gap_ratio": round(none_count / len(coverages), 2),
                    }
                )
        results.sort(key=lambda x: x["gap_ratio"], reverse=True)
        return results

    def compute_attack_surface_coverage(self) -> dict[str, Any]:
        """Compute percentage of ATT&CK matrix covered by detections."""
        all_phases = set(AttackPhase)
        covered_phases: set[str] = set()
        all_tactics: set[str] = set()
        covered_tactics: set[str] = set()
        for r in self._records:
            if r.tactic:
                all_tactics.add(r.tactic)
            if r.detection_coverage in (DetectionCoverage.FULL, DetectionCoverage.PARTIAL):
                covered_phases.add(r.attack_phase.value)
                if r.tactic:
                    covered_tactics.add(r.tactic)
        phase_coverage = (
            round(len(covered_phases) / len(all_phases) * 100, 2) if all_phases else 0.0
        )
        tactic_coverage = (
            round(len(covered_tactics) / len(all_tactics) * 100, 2) if all_tactics else 0.0
        )
        return {
            "phase_coverage_pct": phase_coverage,
            "tactic_coverage_pct": tactic_coverage,
            "total_phases": len(all_phases),
            "covered_phases": len(covered_phases),
            "total_tactics": len(all_tactics),
            "covered_tactics": len(covered_tactics),
        }

    def prioritize_detection_development(self) -> list[dict[str, Any]]:
        """Rank uncovered techniques by impact for detection development."""
        technique_data: dict[str, dict[str, Any]] = {}
        for r in self._records:
            if not r.technique:
                continue
            if r.technique not in technique_data:
                technique_data[r.technique] = {
                    "technique": r.technique,
                    "tactic": r.tactic,
                    "attack_phase": r.attack_phase.value,
                    "max_score": r.score,
                    "coverage": r.detection_coverage.value,
                    "confidence": r.mapping_confidence.value,
                }
            else:
                if r.score > technique_data[r.technique]["max_score"]:
                    technique_data[r.technique]["max_score"] = r.score
        results: list[dict[str, Any]] = []
        for tech, data in technique_data.items():
            if data["coverage"] in ("none", "untested"):
                results.append(
                    {
                        "technique": tech,
                        "tactic": data["tactic"],
                        "attack_phase": data["attack_phase"],
                        "impact_score": data["max_score"],
                        "priority": "high" if data["max_score"] >= 70 else "medium",
                    }
                )
        results.sort(key=lambda x: x["impact_score"], reverse=True)
        return results
