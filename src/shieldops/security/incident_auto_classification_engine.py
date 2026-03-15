"""Incident Auto-Classification Engine —
auto-classify security incidents by type, severity,
and response requirements."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class IncidentClass(StrEnum):
    MALWARE = "malware"
    PHISHING = "phishing"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    DDOS = "ddos"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


class ClassificationMethod(StrEnum):
    RULE_BASED = "rule_based"
    ML_BASED = "ml_based"
    HYBRID = "hybrid"
    MANUAL = "manual"


class ClassificationConfidence(StrEnum):
    DEFINITIVE = "definitive"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    UNKNOWN = "unknown"


# --- Models ---


class IncidentClassificationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    incident_class: IncidentClass = IncidentClass.MALWARE
    classification_method: ClassificationMethod = ClassificationMethod.HYBRID
    classification_confidence: ClassificationConfidence = ClassificationConfidence.UNKNOWN
    indicators: list[str] = Field(default_factory=list)
    severity: float = 0.0
    actual_class: str = ""
    was_correct: bool | None = None
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class IncidentClassificationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    predicted_class: IncidentClass = IncidentClass.MALWARE
    classification_method: ClassificationMethod = ClassificationMethod.HYBRID
    classification_confidence: ClassificationConfidence = ClassificationConfidence.UNKNOWN
    confidence_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class IncidentClassificationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    accuracy_rate: float = 0.0
    by_incident_class: dict[str, int] = Field(default_factory=dict)
    by_classification_method: dict[str, int] = Field(default_factory=dict)
    by_classification_confidence: dict[str, int] = Field(default_factory=dict)
    misclassified_ids: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class IncidentAutoClassificationEngine:
    """Auto-classify security incidents by type, severity,
    and response requirements."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[IncidentClassificationRecord] = []
        self._analyses: dict[str, IncidentClassificationAnalysis] = {}
        logger.info(
            "incident_auto_classification_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        incident_id: str = "",
        incident_class: IncidentClass = IncidentClass.MALWARE,
        classification_method: ClassificationMethod = (ClassificationMethod.HYBRID),
        classification_confidence: ClassificationConfidence = (ClassificationConfidence.UNKNOWN),
        indicators: list[str] | None = None,
        severity: float = 0.0,
        actual_class: str = "",
        was_correct: bool | None = None,
        description: str = "",
    ) -> IncidentClassificationRecord:
        record = IncidentClassificationRecord(
            incident_id=incident_id,
            incident_class=incident_class,
            classification_method=classification_method,
            classification_confidence=classification_confidence,
            indicators=indicators or [],
            severity=severity,
            actual_class=actual_class,
            was_correct=was_correct,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "incident_classification.record_added",
            record_id=record.id,
            incident_id=incident_id,
        )
        return record

    def process(self, key: str) -> IncidentClassificationAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        indicator_count = len(rec.indicators)
        if indicator_count >= 5 and rec.severity >= 0.7:
            confidence = ClassificationConfidence.DEFINITIVE
            score = 0.95
        elif indicator_count >= 3 and rec.severity >= 0.5:
            confidence = ClassificationConfidence.PROBABLE
            score = 0.75
        elif indicator_count >= 1:
            confidence = ClassificationConfidence.POSSIBLE
            score = 0.45
        else:
            confidence = ClassificationConfidence.UNKNOWN
            score = 0.1
        analysis = IncidentClassificationAnalysis(
            incident_id=rec.incident_id,
            predicted_class=rec.incident_class,
            classification_method=rec.classification_method,
            classification_confidence=confidence,
            confidence_score=round(score, 4),
            description=(
                f"Incident {rec.incident_id} classified as "
                f"{rec.incident_class.value} confidence={confidence.value}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> IncidentClassificationReport:
        by_class: dict[str, int] = {}
        by_method: dict[str, int] = {}
        by_conf: dict[str, int] = {}
        for r in self._records:
            by_class[r.incident_class.value] = by_class.get(r.incident_class.value, 0) + 1
            by_method[r.classification_method.value] = (
                by_method.get(r.classification_method.value, 0) + 1
            )
            by_conf[r.classification_confidence.value] = (
                by_conf.get(r.classification_confidence.value, 0) + 1
            )
        verified = [r for r in self._records if r.was_correct is not None]
        correct = sum(1 for r in verified if r.was_correct)
        accuracy = round(correct / len(verified) * 100, 2) if verified else 0.0
        misclassified = list(
            {r.incident_id for r in self._records if r.was_correct is False and r.incident_id}
        )[:10]
        recs: list[str] = []
        if misclassified:
            recs.append(f"{len(misclassified)} incidents were misclassified")
        if accuracy < 80 and verified:
            recs.append(f"Classification accuracy at {accuracy}% — below 80% target")
        if not recs:
            recs.append("Incident classification operating within normal parameters")
        return IncidentClassificationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            accuracy_rate=accuracy,
            by_incident_class=by_class,
            by_classification_method=by_method,
            by_classification_confidence=by_conf,
            misclassified_ids=misclassified,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        class_dist: dict[str, int] = {}
        for r in self._records:
            class_dist[r.incident_class.value] = class_dist.get(r.incident_class.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "incident_class_distribution": class_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("incident_auto_classification_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def classify_incident(self, indicators: list[str] | None = None) -> dict[str, Any]:
        """Auto-classify an incident based on indicators."""
        indicators = indicators or []
        indicator_set = {i.lower() for i in indicators}

        malware_keywords = {
            "ransomware",
            "trojan",
            "worm",
            "virus",
            "payload",
            "c2",
            "command_and_control",
            "malicious_binary",
        }
        phishing_keywords = {
            "email",
            "spear_phishing",
            "credential_harvest",
            "suspicious_link",
            "social_engineering",
        }
        breach_keywords = {
            "data_loss",
            "exfiltration",
            "pii",
            "sensitive_data",
            "unauthorized_transfer",
        }
        insider_keywords = {
            "insider",
            "privilege_abuse",
            "policy_violation",
            "abnormal_access",
            "data_hoarding",
        }
        ddos_keywords = {
            "ddos",
            "flood",
            "volumetric",
            "syn_flood",
            "amplification",
        }
        unauth_keywords = {
            "brute_force",
            "credential_stuffing",
            "unauthorized",
            "lateral_movement",
            "privilege_escalation",
        }

        scores: dict[str, int] = {
            IncidentClass.MALWARE.value: len(indicator_set & malware_keywords),
            IncidentClass.PHISHING.value: len(indicator_set & phishing_keywords),
            IncidentClass.DATA_BREACH.value: len(indicator_set & breach_keywords),
            IncidentClass.INSIDER_THREAT.value: len(indicator_set & insider_keywords),
            IncidentClass.DDOS.value: len(indicator_set & ddos_keywords),
            IncidentClass.UNAUTHORIZED_ACCESS.value: len(indicator_set & unauth_keywords),
        }
        best_class = max(scores, key=lambda k: scores[k])
        best_score = scores[best_class]
        total_indicators = len(indicators)

        if best_score >= 3:
            confidence = ClassificationConfidence.DEFINITIVE
        elif best_score >= 2:
            confidence = ClassificationConfidence.PROBABLE
        elif best_score >= 1:
            confidence = ClassificationConfidence.POSSIBLE
        else:
            confidence = ClassificationConfidence.UNKNOWN
            best_class = IncidentClass.MALWARE.value

        return {
            "predicted_class": best_class,
            "confidence": confidence.value,
            "matched_indicators": best_score,
            "total_indicators": total_indicators,
            "class_scores": scores,
        }

    def measure_classification_accuracy(self) -> dict[str, Any]:
        """Track classification precision and recall per class."""
        verified = [r for r in self._records if r.was_correct is not None]
        if not verified:
            return {
                "total_verified": 0,
                "overall_accuracy": 0.0,
                "per_class_accuracy": {},
                "grade": "no_data",
            }
        correct = sum(1 for r in verified if r.was_correct)
        overall = round(correct / len(verified) * 100, 2)
        per_class: dict[str, dict[str, Any]] = {}
        for ic in IncidentClass:
            class_recs = [r for r in verified if r.incident_class == ic]
            if class_recs:
                class_correct = sum(1 for r in class_recs if r.was_correct)
                per_class[ic.value] = {
                    "total": len(class_recs),
                    "correct": class_correct,
                    "accuracy": round(class_correct / len(class_recs) * 100, 2),
                }
        if overall >= 90:
            grade = "excellent"
        elif overall >= 75:
            grade = "good"
        elif overall >= 60:
            grade = "fair"
        else:
            grade = "poor"
        return {
            "total_verified": len(verified),
            "overall_accuracy": overall,
            "per_class_accuracy": per_class,
            "grade": grade,
        }

    def identify_misclassified_incidents(self) -> list[dict[str, Any]]:
        """Find incidents that may be misclassified."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            is_misclassified = False
            reason = ""
            if r.was_correct is False:
                is_misclassified = True
                reason = "verified_incorrect"
            elif (
                r.classification_confidence == ClassificationConfidence.UNKNOWN
                and r.severity >= 0.5
            ):
                is_misclassified = True
                reason = "low_confidence_high_severity"
            elif r.actual_class and r.actual_class != r.incident_class.value:
                is_misclassified = True
                reason = "class_mismatch"
            if is_misclassified:
                results.append(
                    {
                        "incident_id": r.incident_id,
                        "predicted_class": r.incident_class.value,
                        "actual_class": r.actual_class or "unknown",
                        "confidence": r.classification_confidence.value,
                        "severity": r.severity,
                        "reason": reason,
                        "indicator_count": len(r.indicators),
                    }
                )
        results.sort(key=lambda x: x["severity"], reverse=True)
        return results
