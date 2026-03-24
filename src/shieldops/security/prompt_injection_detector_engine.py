"""PromptInjectionDetectorEngine — Detect and classify prompt injection attacks."""

from __future__ import annotations

import re
import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class InjectionType(StrEnum):
    DIRECT = "direct"
    INDIRECT = "indirect"
    JAILBREAK = "jailbreak"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionResult(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"


# --- Models ---


class PromptInjectionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    prompt_text: str = ""
    injection_type: InjectionType = InjectionType.DIRECT
    severity: Severity = Severity.LOW
    detection_result: DetectionResult = DetectionResult.CLEAN
    score: float = 0.0
    source_app: str = ""
    user_id: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class PromptInjectionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    injection_type: InjectionType = InjectionType.DIRECT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PromptInjectionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_injection_type: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_detection_result: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Patterns ---

INJECTION_PATTERNS: list[tuple[str, InjectionType, Severity]] = [
    (r"ignore\s+(previous|all|above)\s+instructions", InjectionType.DIRECT, Severity.CRITICAL),
    (r"you\s+are\s+now\s+", InjectionType.JAILBREAK, Severity.HIGH),
    (r"system\s*:\s*", InjectionType.DIRECT, Severity.MEDIUM),
    (r"<\|im_start\|>", InjectionType.DIRECT, Severity.CRITICAL),
    (r"do\s+anything\s+now", InjectionType.JAILBREAK, Severity.HIGH),
    (r"pretend\s+you\s+are", InjectionType.JAILBREAK, Severity.MEDIUM),
]


# --- Engine ---


class PromptInjectionDetectorEngine:
    """Detect and classify prompt injection attacks against LLM applications."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[PromptInjectionRecord] = []
        self._analyses: list[PromptInjectionAnalysis] = []
        logger.info(
            "prompt_injection_detector_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        prompt_text: str = "",
        injection_type: InjectionType = InjectionType.DIRECT,
        severity: Severity = Severity.LOW,
        detection_result: DetectionResult = DetectionResult.CLEAN,
        score: float = 0.0,
        source_app: str = "",
        user_id: str = "",
        team: str = "",
    ) -> PromptInjectionRecord:
        record = PromptInjectionRecord(
            name=name,
            prompt_text=prompt_text,
            injection_type=injection_type,
            severity=severity,
            detection_result=detection_result,
            score=score,
            source_app=source_app,
            user_id=user_id,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "prompt_injection_detector_engine.record_added",
            record_id=record.id,
            name=name,
            detection_result=detection_result.value,
        )
        return record

    def get_record(self, record_id: str) -> PromptInjectionRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        injection_type: InjectionType | None = None,
        severity: Severity | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[PromptInjectionRecord]:
        results = list(self._records)
        if injection_type is not None:
            results = [r for r in results if r.injection_type == injection_type]
        if severity is not None:
            results = [r for r in results if r.severity == severity]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    # -- domain operations --------------------------------------------------

    def analyze_prompt(self, prompt_text: str) -> dict[str, Any]:
        """Analyze a prompt for injection patterns. Returns detection details."""
        detections: list[dict[str, Any]] = []
        for pattern, inj_type, sev in INJECTION_PATTERNS:
            if re.search(pattern, prompt_text, re.IGNORECASE):
                detections.append(
                    {
                        "pattern": pattern,
                        "injection_type": inj_type.value,
                        "severity": sev.value,
                    }
                )
        if not detections:
            return {
                "result": DetectionResult.CLEAN.value,
                "detections": [],
                "risk_score": 0.0,
            }
        max_sev = max(
            detections,
            key=lambda d: list(Severity).index(Severity(d["severity"])),
        )
        risk_score = (list(Severity).index(Severity(max_sev["severity"])) + 1) * 25.0
        return {
            "result": DetectionResult.BLOCKED.value
            if risk_score >= 75.0
            else DetectionResult.SUSPICIOUS.value,
            "detections": detections,
            "risk_score": risk_score,
        }

    def detect_pattern(self, prompt_text: str) -> list[dict[str, Any]]:
        """Return all matching injection patterns for a given prompt."""
        matches: list[dict[str, Any]] = []
        for pattern, inj_type, sev in INJECTION_PATTERNS:
            match = re.search(pattern, prompt_text, re.IGNORECASE)
            if match:
                matches.append(
                    {
                        "pattern": pattern,
                        "matched_text": match.group(),
                        "injection_type": inj_type.value,
                        "severity": sev.value,
                    }
                )
        return matches

    def get_top_attackers(self) -> list[dict[str, Any]]:
        """Identify users with the most blocked or suspicious prompts."""
        user_stats: dict[str, dict[str, int]] = {}
        for r in self._records:
            if r.detection_result != DetectionResult.CLEAN and r.user_id:
                stats = user_stats.setdefault(r.user_id, {"blocked": 0, "suspicious": 0})
                if r.detection_result == DetectionResult.BLOCKED:
                    stats["blocked"] += 1
                else:
                    stats["suspicious"] += 1
        results = [
            {
                "user_id": uid,
                "blocked": stats["blocked"],
                "suspicious": stats["suspicious"],
                "total": stats["blocked"] + stats["suspicious"],
            }
            for uid, stats in user_stats.items()
        ]
        return sorted(results, key=lambda x: x["total"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.source_app == key]
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

    def generate_report(self) -> PromptInjectionReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.injection_type.value] = by_e1.get(r.injection_type.value, 0) + 1
            by_e2[r.severity.value] = by_e2.get(r.severity.value, 0) + 1
            by_e3[r.detection_result.value] = by_e3.get(r.detection_result.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = [r.name for r in self._records if r.score < self._threshold]
        top_gaps = gap_list[:5]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Prompt Injection Detector Engine is healthy")
        return PromptInjectionReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_injection_type=by_e1,
            by_severity=by_e2,
            by_detection_result=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("prompt_injection_detector_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.injection_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "injection_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_source_apps": len({r.source_app for r in self._records}),
        }
