"""Prompt Injection Detector — detect and classify prompt injection attacks."""

from __future__ import annotations

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
    ROLE_PLAY = "role_play"
    ENCODING_BYPASS = "encoding_bypass"


class InjectionSeverity(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    CONFIRMED_INJECTION = "confirmed_injection"


class DetectionMethod(StrEnum):
    PATTERN_MATCH = "pattern_match"
    SEMANTIC_ANALYSIS = "semantic_analysis"
    CANARY_TOKEN = "canary_token"  # noqa: S105
    OUTPUT_DIVERGENCE = "output_divergence"
    LLM_CLASSIFIER = "llm_classifier"


# --- Models ---


class PromptInjectionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    prompt_hash: str = ""
    injection_type: InjectionType = InjectionType.DIRECT
    severity: InjectionSeverity = InjectionSeverity.SUSPICIOUS
    detection_method: DetectionMethod = DetectionMethod.PATTERN_MATCH
    confidence: float = 0.0
    risk_score: float = 0.0
    app_id: str = ""
    user_id: str = ""
    blocked: bool = False
    created_at: float = Field(default_factory=time.time)


class InjectionPattern(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pattern: str = ""
    injection_type: InjectionType = InjectionType.DIRECT
    severity: InjectionSeverity = InjectionSeverity.SUSPICIOUS
    match_count: int = 0
    false_positive_rate: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PromptInjectionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_patterns: int = 0
    confirmed_injections: int = 0
    avg_confidence: float = 0.0
    avg_risk_score: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_method: dict[str, int] = Field(default_factory=dict)
    top_patterns: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class PromptInjectionDetector:
    """Detect and classify prompt injection attacks in LLM applications."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 0.7,
    ) -> None:
        self._max_records = max_records
        self._risk_threshold = risk_threshold
        self._records: list[PromptInjectionRecord] = []
        self._patterns: list[InjectionPattern] = []
        logger.info(
            "prompt_injection_detector.initialized",
            max_records=max_records,
            risk_threshold=risk_threshold,
        )

    # -- record / query --------------------------------------------------------

    def record_injection(
        self,
        prompt_hash: str,
        injection_type: InjectionType = InjectionType.DIRECT,
        severity: InjectionSeverity = InjectionSeverity.SUSPICIOUS,
        detection_method: DetectionMethod = DetectionMethod.PATTERN_MATCH,
        confidence: float = 0.0,
        risk_score: float = 0.0,
        app_id: str = "",
        user_id: str = "",
        blocked: bool = False,
    ) -> PromptInjectionRecord:
        record = PromptInjectionRecord(
            prompt_hash=prompt_hash,
            injection_type=injection_type,
            severity=severity,
            detection_method=detection_method,
            confidence=confidence,
            risk_score=risk_score,
            app_id=app_id,
            user_id=user_id,
            blocked=blocked,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "prompt_injection_detector.recorded",
            record_id=record.id,
            injection_type=injection_type.value,
            severity=severity.value,
        )
        return record

    def analyze_prompt(self, text: str, app_id: str = "") -> dict[str, Any]:
        """Analyze a prompt for injection patterns; return detection result."""
        text_lower = text.lower()
        matches: list[dict[str, Any]] = []
        for p in self._patterns:
            if p.pattern.lower() in text_lower:
                p.match_count += 1
                matches.append(
                    {
                        "pattern_id": p.id,
                        "pattern": p.pattern,
                        "injection_type": p.injection_type.value,
                        "severity": p.severity.value,
                    }
                )
        risk = min(1.0, len(matches) * 0.3) if matches else 0.0
        return {
            "app_id": app_id,
            "matches": matches,
            "match_count": len(matches),
            "risk_score": round(risk, 2),
            "is_injection": risk >= self._risk_threshold,
        }

    # -- domain operations -----------------------------------------------------

    def detect_pattern(self) -> list[dict[str, Any]]:
        """Identify recurring injection patterns from recorded events."""
        type_counts: dict[str, int] = {}
        for r in self._records:
            key = r.injection_type.value
            type_counts[key] = type_counts.get(key, 0) + 1
        results: list[dict[str, Any]] = []
        for itype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            relevant = [r for r in self._records if r.injection_type.value == itype]
            avg_conf = sum(r.confidence for r in relevant) / len(relevant) if relevant else 0.0
            results.append(
                {
                    "injection_type": itype,
                    "count": count,
                    "avg_confidence": round(avg_conf, 2),
                    "pct_blocked": round(
                        sum(1 for r in relevant if r.blocked) / len(relevant) * 100, 1
                    )
                    if relevant
                    else 0.0,
                }
            )
        return results

    def update_pattern_database(
        self,
        pattern: str,
        injection_type: InjectionType = InjectionType.DIRECT,
        severity: InjectionSeverity = InjectionSeverity.SUSPICIOUS,
        description: str = "",
    ) -> InjectionPattern:
        """Add or update a pattern in the detection database."""
        # Check if pattern already exists
        for existing in self._patterns:
            if existing.pattern == pattern:
                existing.severity = severity
                existing.description = description
                logger.info("prompt_injection_detector.pattern_updated", pattern=pattern)
                return existing
        new_pattern = InjectionPattern(
            pattern=pattern,
            injection_type=injection_type,
            severity=severity,
            description=description,
        )
        self._patterns.append(new_pattern)
        logger.info("prompt_injection_detector.pattern_added", pattern=pattern)
        return new_pattern

    def calculate_risk_score(self) -> dict[str, Any]:
        """Calculate aggregate risk score across all records."""
        if not self._records:
            return {"overall_risk": 0.0, "risk_level": "none", "record_count": 0}
        avg_risk = sum(r.risk_score for r in self._records) / len(self._records)
        confirmed = sum(
            1 for r in self._records if r.severity == InjectionSeverity.CONFIRMED_INJECTION
        )
        confirmed_pct = confirmed / len(self._records) * 100
        if avg_risk >= 0.8 or confirmed_pct > 10:
            level = "critical"
        elif avg_risk >= 0.5:
            level = "high"
        elif avg_risk >= 0.3:
            level = "medium"
        else:
            level = "low"
        return {
            "overall_risk": round(avg_risk, 3),
            "risk_level": level,
            "record_count": len(self._records),
            "confirmed_injections": confirmed,
            "confirmed_pct": round(confirmed_pct, 2),
        }

    # -- report / stats --------------------------------------------------------

    def generate_report(self) -> PromptInjectionReport:
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_method: dict[str, int] = {}
        for r in self._records:
            by_type[r.injection_type.value] = by_type.get(r.injection_type.value, 0) + 1
            by_severity[r.severity.value] = by_severity.get(r.severity.value, 0) + 1
            by_method[r.detection_method.value] = by_method.get(r.detection_method.value, 0) + 1

        confirmed = sum(
            1 for r in self._records if r.severity == InjectionSeverity.CONFIRMED_INJECTION
        )
        avg_conf = (
            round(sum(r.confidence for r in self._records) / len(self._records), 2)
            if self._records
            else 0.0
        )
        avg_risk = (
            round(sum(r.risk_score for r in self._records) / len(self._records), 2)
            if self._records
            else 0.0
        )
        top_patterns = [
            p.pattern for p in sorted(self._patterns, key=lambda x: x.match_count, reverse=True)[:5]
        ]

        recs: list[str] = []
        if confirmed > 0:
            recs.append(f"{confirmed} confirmed injection(s) — review and update filters")
        if avg_risk >= self._risk_threshold:
            recs.append(f"Average risk {avg_risk} exceeds threshold ({self._risk_threshold})")
        if not recs:
            recs.append("Prompt injection risk levels are within acceptable range")

        return PromptInjectionReport(
            total_records=len(self._records),
            total_patterns=len(self._patterns),
            confirmed_injections=confirmed,
            avg_confidence=avg_conf,
            avg_risk_score=avg_risk,
            by_type=by_type,
            by_severity=by_severity,
            by_method=by_method,
            top_patterns=top_patterns,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            key = r.injection_type.value
            type_dist[key] = type_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_patterns": len(self._patterns),
            "risk_threshold": self._risk_threshold,
            "type_distribution": type_dist,
            "unique_apps": len({r.app_id for r in self._records}),
            "unique_users": len({r.user_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._patterns.clear()
        logger.info("prompt_injection_detector.cleared")
        return {"status": "cleared"}
