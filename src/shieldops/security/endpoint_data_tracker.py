"""Endpoint Data Tracker — data movement and DLP."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DataChannel(StrEnum):
    USB = "usb"
    EMAIL = "email"
    CLOUD_UPLOAD = "cloud_upload"
    CLIPBOARD = "clipboard"
    PRINT = "print"


class SensitivityMatch(StrEnum):
    NONE = "none"
    PII = "pii"
    PHI = "phi"
    FINANCIAL = "financial"
    CLASSIFIED = "classified"


class PolicyResult(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    WARNED = "warned"
    LOGGED = "logged"
    QUARANTINED = "quarantined"


# --- Models ---


class EndpointDataRecord(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    endpoint_id: str = ""
    channel: DataChannel = DataChannel.EMAIL
    sensitivity: SensitivityMatch = SensitivityMatch.NONE
    policy_result: PolicyResult = PolicyResult.ALLOWED
    file_name: str = ""
    file_size_bytes: int = 0
    user_id: str = ""
    created_at: float = Field(default_factory=time.time)


class EndpointDataAnalysis(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    endpoint_id: str = ""
    total_transfers: int = 0
    blocked_count: int = 0
    sensitive_count: int = 0
    risk_score: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class EndpointDataReport(BaseModel):
    total_events: int = 0
    blocked_count: int = 0
    sensitive_data_events: int = 0
    by_channel: dict[str, int] = Field(
        default_factory=dict,
    )
    by_sensitivity: dict[str, int] = Field(
        default_factory=dict,
    )
    recommendations: list[str] = Field(
        default_factory=list,
    )
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class EndpointDataTracker:
    """Track data movement and enforce DLP."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[EndpointDataRecord] = []
        logger.info(
            "endpoint_data_tracker.initialized",
            max_records=max_records,
        )

    def _evict(self) -> None:
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]

    def add_record(
        self,
        **kwargs: Any,
    ) -> EndpointDataRecord:
        record = EndpointDataRecord(**kwargs)
        self._records.append(record)
        self._evict()
        logger.info(
            "endpoint_data.record_added",
            record_id=record.id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> EndpointDataAnalysis:
        matches = [r for r in self._records if r.endpoint_id == key]
        blocked = sum(1 for r in matches if r.policy_result == PolicyResult.BLOCKED)
        sensitive = sum(1 for r in matches if r.sensitivity != SensitivityMatch.NONE)
        risk = (
            round(
                sensitive / len(matches),
                4,
            )
            if matches
            else 0.0
        )
        return EndpointDataAnalysis(
            endpoint_id=key,
            total_transfers=len(matches),
            blocked_count=blocked,
            sensitive_count=sensitive,
            risk_score=risk,
        )

    def generate_report(self) -> EndpointDataReport:
        by_ch: dict[str, int] = {}
        by_sens: dict[str, int] = {}
        blocked = 0
        sensitive = 0
        for r in self._records:
            ch = r.channel.value
            by_ch[ch] = by_ch.get(ch, 0) + 1
            s = r.sensitivity.value
            by_sens[s] = by_sens.get(s, 0) + 1
            if r.policy_result == PolicyResult.BLOCKED:
                blocked += 1
            if r.sensitivity != SensitivityMatch.NONE:
                sensitive += 1
        recs: list[str] = []
        if sensitive > 0:
            recs.append(f"{sensitive} sensitive data event(s)")
        if blocked > 0:
            recs.append(f"{blocked} transfer(s) blocked")
        if not recs:
            recs.append("No data policy violations")
        return EndpointDataReport(
            total_events=len(self._records),
            blocked_count=blocked,
            sensitive_data_events=sensitive,
            by_channel=by_ch,
            by_sensitivity=by_sens,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("endpoint_data_tracker.cleared")
        return {"status": "cleared"}

    # -- domain methods --

    def track_data_movement(
        self,
        endpoint_id: str,
        channel: DataChannel,
        file_name: str = "",
        user_id: str = "",
    ) -> dict[str, Any]:
        """Track a data movement event."""
        record = self.add_record(
            endpoint_id=endpoint_id,
            channel=channel,
            file_name=file_name,
            user_id=user_id,
        )
        return {
            "record_id": record.id,
            "channel": channel.value,
            "endpoint_id": endpoint_id,
        }

    def match_sensitivity(
        self,
        record_id: str,
        sensitivity: SensitivityMatch,
    ) -> dict[str, Any]:
        """Tag a record with sensitivity match."""
        for r in self._records:
            if r.id == record_id:
                r.sensitivity = sensitivity
                return {
                    "record_id": record_id,
                    "updated": True,
                    "sensitivity": sensitivity.value,
                }
        return {
            "record_id": record_id,
            "updated": False,
        }

    def enforce_endpoint_policy(
        self,
        endpoint_id: str,
    ) -> dict[str, Any]:
        """Enforce DLP policy for an endpoint."""
        matches = [r for r in self._records if r.endpoint_id == endpoint_id]
        violations = [
            r
            for r in matches
            if r.sensitivity != SensitivityMatch.NONE and r.policy_result == PolicyResult.ALLOWED
        ]
        for v in violations:
            v.policy_result = PolicyResult.BLOCKED
        return {
            "endpoint_id": endpoint_id,
            "total_events": len(matches),
            "violations_blocked": len(violations),
        }
