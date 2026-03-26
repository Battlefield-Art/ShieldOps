"""SIEM Migration Engine — track migration and rule translation."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MigrationPhase(StrEnum):
    DISCOVERY = "discovery"
    MAPPING = "mapping"
    TRANSLATION = "translation"
    TESTING = "testing"
    CUTOVER = "cutover"


class RuleFormat(StrEnum):
    SPLUNK_SPL = "splunk_spl"
    ELASTIC_EQL = "elastic_eql"
    SIGMA = "sigma"
    KQL = "kql"
    YARA_L = "yara_l"


class TranslationStatus(StrEnum):
    PENDING = "pending"
    TRANSLATED = "translated"
    VALIDATED = "validated"
    FAILED = "failed"
    SKIPPED = "skipped"


# --- Models ---


class MigrationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    phase: MigrationPhase = MigrationPhase.DISCOVERY
    source_format: RuleFormat = RuleFormat.SPLUNK_SPL
    target_format: RuleFormat = RuleFormat.SIGMA
    status: TranslationStatus = TranslationStatus.PENDING
    fidelity_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class MigrationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    phase: MigrationPhase = MigrationPhase.DISCOVERY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MigrationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    translation_rate: float = 0.0
    avg_fidelity: float = 0.0
    by_phase: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class SiemMigrationEngine:
    """Track SIEM migration and rule translation."""

    def __init__(
        self,
        max_records: int = 200000,
        fidelity_threshold: float = 85.0,
    ) -> None:
        self._max_records = max_records
        self._fidelity_threshold = fidelity_threshold
        self._records: list[MigrationRecord] = []
        self._analyses: list[MigrationAnalysis] = []
        logger.info(
            "siem_migration_engine.init",
            max_records=max_records,
        )

    # -- record --

    def add_record(
        self,
        rule_id: str = "",
        phase: MigrationPhase = (MigrationPhase.DISCOVERY),
        source_format: RuleFormat = (RuleFormat.SPLUNK_SPL),
        target_format: RuleFormat = (RuleFormat.SIGMA),
        status: TranslationStatus = (TranslationStatus.PENDING),
        fidelity_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> MigrationRecord:
        record = MigrationRecord(
            rule_id=rule_id,
            phase=phase,
            source_format=source_format,
            target_format=target_format,
            status=status,
            fidelity_score=fidelity_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "siem_migration.record_added",
            record_id=record.id,
        )
        return record

    # -- process --

    def process(self, rule_id: str) -> MigrationAnalysis:
        relevant = [r for r in self._records if r.rule_id == rule_id]
        if not relevant:
            analysis = MigrationAnalysis(
                rule_id=rule_id,
                description="no records found",
            )
            self._analyses.append(analysis)
            return analysis
        scores = [r.fidelity_score for r in relevant]
        avg = sum(scores) / len(scores)
        breached = avg < self._fidelity_threshold
        analysis = MigrationAnalysis(
            rule_id=rule_id,
            analysis_score=round(avg, 2),
            threshold=self._fidelity_threshold,
            breached=breached,
            description=(f"avg_fidelity={round(avg, 2)}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain methods --

    def translate_detection_rule(
        self,
    ) -> dict[str, Any]:
        """Translation stats by format pair."""
        pair_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = f"{r.source_format.value}->{r.target_format.value}"
            pair_data.setdefault(
                key,
                {"total": 0, "translated": 0},
            )
            pair_data[key]["total"] += 1
            if r.status in (
                TranslationStatus.TRANSLATED,
                TranslationStatus.VALIDATED,
            ):
                pair_data[key]["translated"] += 1
        result: dict[str, Any] = {}
        for pair, data in pair_data.items():
            rate = 0.0
            if data["total"] > 0:
                rate = data["translated"] / data["total"] * 100
            result[pair] = {
                "total": data["total"],
                "translated": data["translated"],
                "rate": round(rate, 2),
            }
        return result

    def track_migration_progress(
        self,
    ) -> dict[str, Any]:
        """Progress by phase."""
        phase_data: dict[str, int] = {}
        for r in self._records:
            key = r.phase.value
            phase_data[key] = phase_data.get(key, 0) + 1
        total = len(self._records)
        completed = sum(1 for r in self._records if r.phase == MigrationPhase.CUTOVER)
        progress = round(completed / total * 100, 2) if total > 0 else 0.0
        return {
            "by_phase": phase_data,
            "total_rules": total,
            "completed": completed,
            "progress_pct": progress,
        }

    def validate_parity(
        self,
    ) -> list[dict[str, Any]]:
        """Rules below fidelity threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if (
                r.fidelity_score < self._fidelity_threshold
                and r.status != TranslationStatus.SKIPPED
            ):
                results.append(
                    {
                        "rule_id": r.rule_id,
                        "fidelity": (r.fidelity_score),
                        "source": (r.source_format.value),
                        "target": (r.target_format.value),
                        "status": r.status.value,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["fidelity"],
        )

    # -- report / stats --

    def generate_report(self) -> MigrationReport:
        by_ph: dict[str, int] = {}
        by_src: dict[str, int] = {}
        by_st: dict[str, int] = {}
        for r in self._records:
            by_ph[r.phase.value] = by_ph.get(r.phase.value, 0) + 1
            by_src[r.source_format.value] = by_src.get(r.source_format.value, 0) + 1
            by_st[r.status.value] = by_st.get(r.status.value, 0) + 1
        translated = sum(
            1
            for r in self._records
            if r.status
            in (
                TranslationStatus.TRANSLATED,
                TranslationStatus.VALIDATED,
            )
        )
        trans_rate = (
            round(
                translated / len(self._records) * 100,
                2,
            )
            if self._records
            else 0.0
        )
        scores = [r.fidelity_score for r in self._records]
        avg_fid = round(sum(scores) / len(scores), 2) if scores else 0.0
        recs: list[str] = []
        if avg_fid < self._fidelity_threshold:
            recs.append(f"Avg fidelity {avg_fid} below {self._fidelity_threshold}")
        failed = sum(1 for r in self._records if r.status == TranslationStatus.FAILED)
        if failed > 0:
            recs.append(f"{failed} rules failed translation")
        if not recs:
            recs.append("SIEM migration is on track")
        return MigrationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            translation_rate=trans_rate,
            avg_fidelity=avg_fid,
            by_phase=by_ph,
            by_source=by_src,
            by_status=by_st,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "fidelity_threshold": (self._fidelity_threshold),
            "unique_rules": len({r.rule_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("siem_migration_engine.cleared")
        return {"status": "cleared"}
