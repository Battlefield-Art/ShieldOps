"""OtelConfigGeneratorEngine — OTel Collector config generation and validation."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ConfigSection(StrEnum):
    RECEIVERS = "receivers"
    PROCESSORS = "processors"
    EXPORTERS = "exporters"


class ValidationStatus(StrEnum):
    VALID = "valid"
    WARNING = "warning"
    ERROR = "error"


class PipelineSignal(StrEnum):
    TRACES = "traces"
    METRICS = "metrics"
    LOGS = "logs"


# --- Models ---


class OtelConfigGeneratorRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    config_section: ConfigSection = ConfigSection.RECEIVERS
    validation_status: ValidationStatus = ValidationStatus.VALID
    pipeline_signal: PipelineSignal = PipelineSignal.TRACES
    score: float = 0.0
    component_count: int = 0
    config_hash: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelConfigGeneratorAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    config_section: ConfigSection = ConfigSection.RECEIVERS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelConfigGeneratorReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_config_section: dict[str, int] = Field(default_factory=dict)
    by_validation_status: dict[str, int] = Field(default_factory=dict)
    by_pipeline_signal: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OtelConfigGeneratorEngine:
    """OTel Collector config generation and validation engine."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[OtelConfigGeneratorRecord] = []
        self._analyses: list[OtelConfigGeneratorAnalysis] = []
        logger.info(
            "otel_config_generator_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        config_section: ConfigSection = ConfigSection.RECEIVERS,
        validation_status: ValidationStatus = ValidationStatus.VALID,
        pipeline_signal: PipelineSignal = PipelineSignal.TRACES,
        score: float = 0.0,
        component_count: int = 0,
        config_hash: str = "",
        service: str = "",
        team: str = "",
    ) -> OtelConfigGeneratorRecord:
        record = OtelConfigGeneratorRecord(
            name=name,
            config_section=config_section,
            validation_status=validation_status,
            pipeline_signal=pipeline_signal,
            score=score,
            component_count=component_count,
            config_hash=config_hash,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel_config_generator_engine.record_added",
            record_id=record.id,
            name=name,
            config_section=config_section.value,
            validation_status=validation_status.value,
        )
        return record

    def get_record(self, record_id: str) -> OtelConfigGeneratorRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        config_section: ConfigSection | None = None,
        validation_status: ValidationStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[OtelConfigGeneratorRecord]:
        results = list(self._records)
        if config_section is not None:
            results = [r for r in results if r.config_section == config_section]
        if validation_status is not None:
            results = [r for r in results if r.validation_status == validation_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        config_section: ConfigSection = ConfigSection.RECEIVERS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> OtelConfigGeneratorAnalysis:
        analysis = OtelConfigGeneratorAnalysis(
            name=name,
            config_section=config_section,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "otel_config_generator_engine.analysis_added",
            name=name,
            config_section=config_section.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def validate_config_consistency(self) -> list[dict[str, Any]]:
        """Validate that configs have matching receivers/processors/exporters."""
        svc_sections: dict[str, dict[str, int]] = {}
        for r in self._records:
            svc_sections.setdefault(r.service, {})
            section = r.config_section.value
            svc_sections[r.service][section] = svc_sections[r.service].get(section, 0) + 1
        issues: list[dict[str, Any]] = []
        for svc, sections in svc_sections.items():
            missing = [s.value for s in ConfigSection if s.value not in sections]
            if missing:
                issues.append(
                    {
                        "service": svc,
                        "missing_sections": missing,
                        "existing_sections": list(sections.keys()),
                        "severity": "error" if len(missing) > 1 else "warning",
                    }
                )
        return issues

    def detect_pipeline_gaps(self) -> list[dict[str, Any]]:
        """Detect pipelines that lack coverage for certain signals."""
        svc_signals: dict[str, set[str]] = {}
        for r in self._records:
            svc_signals.setdefault(r.service, set()).add(r.pipeline_signal.value)
        gaps: list[dict[str, Any]] = []
        all_signals = {s.value for s in PipelineSignal}
        for svc, signals in svc_signals.items():
            missing = all_signals - signals
            if missing:
                gaps.append(
                    {
                        "service": svc,
                        "missing_signals": sorted(missing),
                        "covered_signals": sorted(signals),
                        "coverage_pct": round(len(signals) / len(all_signals) * 100, 1),
                    }
                )
        return sorted(gaps, key=lambda x: x["coverage_pct"])

    def recommend_config_improvements(self) -> list[dict[str, Any]]:
        """Recommend improvements based on validation status and scores."""
        recommendations: list[dict[str, Any]] = []
        error_records = [r for r in self._records if r.validation_status == ValidationStatus.ERROR]
        for r in error_records:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "issue": "config_error",
                    "priority": "high",
                    "suggestion": f"Fix config error in {r.config_section.value} section",
                }
            )
        low_score = [
            r
            for r in self._records
            if r.score < self._threshold and r.validation_status != ValidationStatus.ERROR
        ]
        for r in low_score:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "issue": "low_score",
                    "priority": "medium",
                    "suggestion": f"Improve config quality (score: {r.score})",
                }
            )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else 1,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.config_section.value
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
                        "config_section": r.config_section.value,
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

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> OtelConfigGeneratorReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.config_section.value] = by_e1.get(r.config_section.value, 0) + 1
            by_e2[r.validation_status.value] = by_e2.get(r.validation_status.value, 0) + 1
            by_e3[r.pipeline_signal.value] = by_e3.get(r.pipeline_signal.value, 0) + 1
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
            recs.append("OTel Config Generator Engine is healthy")
        return OtelConfigGeneratorReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_config_section=by_e1,
            by_validation_status=by_e2,
            by_pipeline_signal=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel_config_generator_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.config_section.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "config_section_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
