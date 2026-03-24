"""AI Exfiltration Guard — detect and prevent data exfiltration via LLM channels."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ExfilChannel(StrEnum):
    MODEL_OUTPUT = "model_output"
    TOOL_CALL = "tool_call"
    EMBEDDING_VECTOR = "embedding_vector"
    LOG_INJECTION = "log_injection"
    SIDE_CHANNEL = "side_channel"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PII = "pii"
    PHI = "phi"
    PCI = "pci"


class ExfilAction(StrEnum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    ALERT = "alert"
    QUARANTINE = "quarantine"


# --- Models ---


class ExfiltrationAttemptRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    channel: ExfilChannel = ExfilChannel.MODEL_OUTPUT
    classification: DataClassification = DataClassification.INTERNAL
    action_taken: ExfilAction = ExfilAction.ALERT
    confidence: float = 0.0
    content_hash: str = ""
    app_id: str = ""
    user_id: str = ""
    model_id: str = ""
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DataBoundary(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    classification: DataClassification = DataClassification.INTERNAL
    allowed_channels: list[ExfilChannel] = Field(default_factory=list)
    max_sensitivity_score: float = 0.0
    action_on_violation: ExfilAction = ExfilAction.BLOCK
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ExfiltrationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_boundaries: int = 0
    blocked_attempts: int = 0
    avg_confidence: float = 0.0
    by_channel: dict[str, int] = Field(default_factory=dict)
    by_classification: dict[str, int] = Field(default_factory=dict)
    by_action: dict[str, int] = Field(default_factory=dict)
    top_violators: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AIExfiltrationGuard:
    """Detect and prevent data exfiltration through LLM output channels."""

    def __init__(
        self,
        max_records: int = 200000,
        default_action: ExfilAction = ExfilAction.BLOCK,
    ) -> None:
        self._max_records = max_records
        self._default_action = default_action
        self._records: list[ExfiltrationAttemptRecord] = []
        self._boundaries: list[DataBoundary] = []
        logger.info(
            "ai_exfiltration_guard.initialized",
            max_records=max_records,
            default_action=default_action.value,
        )

    # -- record / query --------------------------------------------------------

    def record_attempt(
        self,
        channel: ExfilChannel = ExfilChannel.MODEL_OUTPUT,
        classification: DataClassification = DataClassification.INTERNAL,
        action_taken: ExfilAction = ExfilAction.ALERT,
        confidence: float = 0.0,
        content_hash: str = "",
        app_id: str = "",
        user_id: str = "",
        model_id: str = "",
        description: str = "",
    ) -> ExfiltrationAttemptRecord:
        record = ExfiltrationAttemptRecord(
            channel=channel,
            classification=classification,
            action_taken=action_taken,
            confidence=confidence,
            content_hash=content_hash,
            app_id=app_id,
            user_id=user_id,
            model_id=model_id,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ai_exfiltration_guard.attempt_recorded",
            record_id=record.id,
            channel=channel.value,
            classification=classification.value,
            action_taken=action_taken.value,
        )
        return record

    # -- domain operations -----------------------------------------------------

    def classify_output(self, content: str, app_id: str = "") -> dict[str, Any]:
        """Classify output content for sensitive data exposure."""
        content_lower = content.lower()
        detections: list[dict[str, str]] = []

        sensitive_markers = {
            DataClassification.PII: ["ssn", "social security", "date of birth", "email"],
            DataClassification.PHI: ["patient", "diagnosis", "medical record", "prescription"],
            DataClassification.PCI: ["credit card", "card number", "cvv", "expiration"],
            DataClassification.RESTRICTED: ["top secret", "classified", "restricted"],
            DataClassification.CONFIDENTIAL: ["api_key", "password", "secret", "token"],
        }

        highest = DataClassification.PUBLIC
        for cls, markers in sensitive_markers.items():
            for marker in markers:
                if marker in content_lower:
                    detections.append({"marker": marker, "classification": cls.value})
                    if list(DataClassification).index(cls) > list(DataClassification).index(
                        highest
                    ):
                        highest = cls

        return {
            "app_id": app_id,
            "classification": highest.value,
            "detections": detections,
            "detection_count": len(detections),
            "requires_action": highest != DataClassification.PUBLIC,
        }

    def enforce_boundary(
        self,
        content_hash: str,
        channel: ExfilChannel,
        classification: DataClassification,
    ) -> dict[str, Any]:
        """Check content against data boundaries and enforce action."""
        for boundary in self._boundaries:
            if (
                classification == boundary.classification
                or list(DataClassification).index(classification)
                >= list(DataClassification).index(boundary.classification)
            ) and channel not in boundary.allowed_channels:
                return {
                    "boundary_id": boundary.id,
                    "boundary_name": boundary.name,
                    "action": boundary.action_on_violation.value,
                    "reason": f"Channel {channel.value} not allowed for {classification.value}",
                    "enforced": True,
                }
        return {
            "boundary_id": "",
            "action": ExfilAction.ALLOW.value,
            "reason": "No boundary violation",
            "enforced": False,
        }

    def check_embedding_leakage(self) -> list[dict[str, Any]]:
        """Detect data leakage through embedding vector channels."""
        embedding_records = [r for r in self._records if r.channel == ExfilChannel.EMBEDDING_VECTOR]
        user_counts: dict[str, int] = {}
        for r in embedding_records:
            user_counts[r.user_id] = user_counts.get(r.user_id, 0) + 1

        results: list[dict[str, Any]] = []
        for user_id, count in sorted(user_counts.items(), key=lambda x: x[1], reverse=True):
            if count >= 3:
                results.append(
                    {
                        "user_id": user_id,
                        "embedding_attempts": count,
                        "risk": "high" if count >= 10 else "medium",
                    }
                )
        return results

    def detect_encoded_exfil(self) -> dict[str, Any]:
        """Detect encoded exfiltration patterns across records."""
        side_channel = [r for r in self._records if r.channel == ExfilChannel.SIDE_CHANNEL]
        log_injection = [r for r in self._records if r.channel == ExfilChannel.LOG_INJECTION]
        return {
            "side_channel_attempts": len(side_channel),
            "log_injection_attempts": len(log_injection),
            "total_covert_attempts": len(side_channel) + len(log_injection),
            "avg_confidence": round(
                sum(r.confidence for r in side_channel + log_injection)
                / max(len(side_channel) + len(log_injection), 1),
                2,
            ),
            "risk_level": "high" if len(side_channel) + len(log_injection) > 5 else "low",
        }

    # -- report / stats --------------------------------------------------------

    def generate_report(self) -> ExfiltrationReport:
        by_channel: dict[str, int] = {}
        by_classification: dict[str, int] = {}
        by_action: dict[str, int] = {}
        for r in self._records:
            by_channel[r.channel.value] = by_channel.get(r.channel.value, 0) + 1
            by_classification[r.classification.value] = (
                by_classification.get(r.classification.value, 0) + 1
            )
            by_action[r.action_taken.value] = by_action.get(r.action_taken.value, 0) + 1

        blocked = sum(1 for r in self._records if r.action_taken == ExfilAction.BLOCK)
        avg_conf = (
            round(sum(r.confidence for r in self._records) / len(self._records), 2)
            if self._records
            else 0.0
        )

        # Top violators by user
        user_counts: dict[str, int] = {}
        for r in self._records:
            user_counts[r.user_id] = user_counts.get(r.user_id, 0) + 1
        top_violators = [
            u for u, _ in sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ]

        recs: list[str] = []
        if blocked > 0:
            recs.append(f"{blocked} exfiltration attempt(s) blocked — review data boundaries")
        pii_count = by_classification.get(DataClassification.PII.value, 0)
        if pii_count > 0:
            recs.append(f"{pii_count} PII exposure(s) detected — enforce output filtering")
        if not recs:
            recs.append("No significant exfiltration attempts detected")

        return ExfiltrationReport(
            total_records=len(self._records),
            total_boundaries=len(self._boundaries),
            blocked_attempts=blocked,
            avg_confidence=avg_conf,
            by_channel=by_channel,
            by_classification=by_classification,
            by_action=by_action,
            top_violators=top_violators,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        channel_dist: dict[str, int] = {}
        for r in self._records:
            key = r.channel.value
            channel_dist[key] = channel_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_boundaries": len(self._boundaries),
            "default_action": self._default_action.value,
            "channel_distribution": channel_dist,
            "unique_apps": len({r.app_id for r in self._records}),
            "unique_users": len({r.user_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._boundaries.clear()
        logger.info("ai_exfiltration_guard.cleared")
        return {"status": "cleared"}
