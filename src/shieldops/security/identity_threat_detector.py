"""Identity Threat Detector — real-time identity threats."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ThreatVector(StrEnum):
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    CREDENTIAL_STUFFING = "credential_stuffing"
    MFA_FATIGUE = "mfa_fatigue"
    TOKEN_REPLAY = "token_replay"  # noqa: S105
    BRUTE_FORCE = "brute_force"


class DetectionMethod(StrEnum):
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    RULE_BASED = "rule_based"
    ML_MODEL = "ml_model"
    CORRELATION = "correlation"
    ANOMALY_DETECTION = "anomaly_detection"


class ResponseAction(StrEnum):
    ALERT = "alert"
    BLOCK = "block"
    MFA_CHALLENGE = "mfa_challenge"
    SESSION_REVOKE = "session_revoke"
    ACCOUNT_LOCK = "account_lock"


# --- Models ---


class IdentityThreatRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    threat_id: str = ""
    vector: ThreatVector = ThreatVector.CREDENTIAL_STUFFING
    method: DetectionMethod = DetectionMethod.RULE_BASED
    action: ResponseAction = ResponseAction.ALERT
    identity_id: str = ""
    source_ip: str = ""
    location: str = ""
    confidence: float = 0.0
    attempts: int = 0
    blocked: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class IdentityThreatAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    threat_id: str = ""
    vector: ThreatVector = ThreatVector.CREDENTIAL_STUFFING
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class IdentityThreatReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    blocked_count: int = 0
    avg_confidence: float = 0.0
    by_vector: dict[str, int] = Field(default_factory=dict)
    by_method: dict[str, int] = Field(default_factory=dict)
    by_action: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class IdentityThreatDetector:
    """Detect identity-based threats in real-time."""

    def __init__(
        self,
        max_records: int = 200000,
        confidence_threshold: float = 0.75,
    ) -> None:
        self._max_records = max_records
        self._threshold = confidence_threshold
        self._records: list[IdentityThreatRecord] = []
        self._analyses: list[IdentityThreatAnalysis] = []
        logger.info(
            "identity_threat_detector.initialized",
            max_records=max_records,
            confidence_threshold=confidence_threshold,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        threat_id: str,
        vector: ThreatVector = (ThreatVector.CREDENTIAL_STUFFING),
        method: DetectionMethod = (DetectionMethod.RULE_BASED),
        action: ResponseAction = (ResponseAction.ALERT),
        identity_id: str = "",
        source_ip: str = "",
        location: str = "",
        confidence: float = 0.0,
        attempts: int = 0,
        blocked: bool = False,
        service: str = "",
        team: str = "",
    ) -> IdentityThreatRecord:
        record = IdentityThreatRecord(
            threat_id=threat_id,
            vector=vector,
            method=method,
            action=action,
            identity_id=identity_id,
            source_ip=source_ip,
            location=location,
            confidence=confidence,
            attempts=attempts,
            blocked=blocked,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "identity_threat_detector.record_added",
            record_id=record.id,
            threat_id=threat_id,
            vector=vector.value,
            action=action.value,
        )
        return record

    def get_record(self, record_id: str) -> IdentityThreatRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        vector: ThreatVector | None = None,
        action: ResponseAction | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[IdentityThreatRecord]:
        results = list(self._records)
        if vector is not None:
            results = [r for r in results if r.vector == vector]
        if action is not None:
            results = [r for r in results if r.action == action]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def process(self, threat_id: str) -> IdentityThreatAnalysis:
        matched = [r for r in self._records if r.threat_id == threat_id]
        scores = [r.confidence for r in matched]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        breached = avg > self._threshold
        analysis = IdentityThreatAnalysis(
            threat_id=threat_id,
            vector=(matched[-1].vector if matched else ThreatVector.CREDENTIAL_STUFFING),
            analysis_score=avg,
            threshold=self._threshold,
            breached=breached,
            description=(f"Confidence {avg} for {threat_id}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ------------------------------------

    def detect_impossible_travel(
        self,
        identity_id: str,
        location_a: str,
        location_b: str,
        time_diff_min: float,
    ) -> dict[str, Any]:
        """Detect impossible travel events."""
        is_impossible = location_a != location_b and time_diff_min < 120
        confidence = 0.0
        if is_impossible:
            confidence = round(
                min(
                    1.0,
                    1.0 - (time_diff_min / 120),
                ),
                4,
            )
            self.add_record(
                threat_id=f"it-{identity_id}",
                vector=ThreatVector.IMPOSSIBLE_TRAVEL,
                method=(DetectionMethod.BEHAVIORAL_ANALYSIS),
                identity_id=identity_id,
                location=f"{location_a}->{location_b}",
                confidence=confidence,
                blocked=confidence > 0.9,
                action=(ResponseAction.BLOCK if confidence > 0.9 else ResponseAction.MFA_CHALLENGE),
            )
        return {
            "identity_id": identity_id,
            "is_impossible": is_impossible,
            "confidence": confidence,
            "location_a": location_a,
            "location_b": location_b,
            "time_diff_min": time_diff_min,
        }

    def detect_credential_stuffing(
        self,
        identity_id: str,
        failed_attempts: int,
        unique_passwords: int,
        time_window_min: float = 60.0,
    ) -> dict[str, Any]:
        """Detect credential stuffing attacks."""
        rate = (
            round(
                failed_attempts / time_window_min,
                2,
            )
            if time_window_min > 0
            else 0.0
        )
        is_stuffing = failed_attempts > 10 and unique_passwords > 5
        confidence = min(1.0, rate * 0.1 + unique_passwords * 0.05)
        if is_stuffing:
            self.add_record(
                threat_id=f"cs-{identity_id}",
                vector=(ThreatVector.CREDENTIAL_STUFFING),
                method=DetectionMethod.RULE_BASED,
                identity_id=identity_id,
                confidence=round(confidence, 4),
                attempts=failed_attempts,
                blocked=True,
                action=ResponseAction.ACCOUNT_LOCK,
            )
        return {
            "identity_id": identity_id,
            "is_stuffing": is_stuffing,
            "confidence": round(confidence, 4),
            "failed_attempts": failed_attempts,
            "unique_passwords": unique_passwords,
            "rate_per_min": rate,
        }

    def detect_mfa_fatigue(
        self,
        identity_id: str,
        mfa_prompts: int,
        accepted_after: int,
        time_window_min: float = 30.0,
    ) -> dict[str, Any]:
        """Detect MFA fatigue attacks."""
        is_fatigue = mfa_prompts > 5 and accepted_after > 3
        confidence = min(
            1.0,
            (mfa_prompts - 3) * 0.15 + (accepted_after - 1) * 0.1,
        )
        confidence = max(0.0, round(confidence, 4))
        if is_fatigue:
            self.add_record(
                threat_id=f"mfa-{identity_id}",
                vector=ThreatVector.MFA_FATIGUE,
                method=(DetectionMethod.ANOMALY_DETECTION),
                identity_id=identity_id,
                confidence=confidence,
                attempts=mfa_prompts,
                blocked=True,
                action=(ResponseAction.SESSION_REVOKE),
            )
        return {
            "identity_id": identity_id,
            "is_fatigue": is_fatigue,
            "confidence": confidence,
            "mfa_prompts": mfa_prompts,
            "accepted_after": accepted_after,
            "time_window_min": time_window_min,
        }

    # -- report / stats ----------------------------------------

    def generate_report(
        self,
    ) -> IdentityThreatReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.vector.value] = by_e1.get(r.vector.value, 0) + 1
            by_e2[r.method.value] = by_e2.get(r.method.value, 0) + 1
            by_e3[r.action.value] = by_e3.get(r.action.value, 0) + 1
        scores = [r.confidence for r in self._records]
        avg_conf = round(sum(scores) / len(scores), 2) if scores else 0.0
        blocked_ct = sum(1 for r in self._records if r.blocked)
        gap_count = sum(
            1 for r in self._records if r.confidence > self._threshold and not r.blocked
        )
        top_gaps = [
            r.threat_id for r in self._records if r.confidence > self._threshold and not r.blocked
        ][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} unblocked high-conf threat(s)")
        if blocked_ct > 0:
            recs.append(f"{blocked_ct} threat(s) blocked")
        if not recs:
            recs.append("Identity Threat Detector healthy")
        return IdentityThreatReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            blocked_count=blocked_ct,
            avg_confidence=avg_conf,
            by_vector=by_e1,
            by_method=by_e2,
            by_action=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("identity_threat_detector.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.vector.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "vector_distribution": e1_dist,
            "unique_identities": len({r.identity_id for r in self._records}),
            "blocked_count": sum(1 for r in self._records if r.blocked),
        }
