"""Notification Delivery Engine — track notification delivery and acks."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DeliveryChannel(StrEnum):
    SLACK = "slack"
    EMAIL = "email"
    PAGERDUTY = "pagerduty"
    SMS = "sms"
    TEAMS = "teams"


class DeliveryStatus(StrEnum):
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"
    BOUNCED = "bounced"


class AcknowledgmentType(StrEnum):
    MANUAL = "manual"
    AUTO = "auto"
    ESCALATED = "escalated"
    TIMED_OUT = "timed_out"
    SUPPRESSED = "suppressed"


# --- Models ---


class DeliveryRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    notification_id: str = ""
    channel: DeliveryChannel = DeliveryChannel.SLACK
    status: DeliveryStatus = DeliveryStatus.PENDING
    ack_type: AcknowledgmentType = AcknowledgmentType.MANUAL
    recipient: str = ""
    ack_time_sec: float = 0.0
    retry_count: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class DeliveryAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    notification_id: str = ""
    channel: DeliveryChannel = DeliveryChannel.SLACK
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DeliveryReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_ack_time_sec: float = 0.0
    delivery_rate: float = 0.0
    by_channel: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_ack: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class NotificationDeliveryEngine:
    """Track notification delivery and acks."""

    def __init__(
        self,
        max_records: int = 200000,
        ack_threshold_sec: float = 300.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = ack_threshold_sec
        self._records: list[DeliveryRecord] = []
        self._analyses: list[DeliveryAnalysis] = []
        logger.info(
            "notification_delivery.initialized",
            max_records=max_records,
        )

    def record_item(
        self,
        notification_id: str,
        channel: DeliveryChannel = (DeliveryChannel.SLACK),
        status: DeliveryStatus = (DeliveryStatus.PENDING),
        ack_type: AcknowledgmentType = (AcknowledgmentType.MANUAL),
        recipient: str = "",
        ack_time_sec: float = 0.0,
        retry_count: int = 0,
        service: str = "",
        team: str = "",
    ) -> DeliveryRecord:
        record = DeliveryRecord(
            notification_id=notification_id,
            channel=channel,
            status=status,
            ack_type=ack_type,
            recipient=recipient,
            ack_time_sec=ack_time_sec,
            retry_count=retry_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "notification_delivery.record_added",
            record_id=record.id,
            channel=channel.value,
        )
        return record

    def get_record(self, record_id: str) -> DeliveryRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        channel: DeliveryChannel | None = None,
        status: DeliveryStatus | None = None,
        limit: int = 50,
    ) -> list[DeliveryRecord]:
        results = list(self._records)
        if channel is not None:
            results = [r for r in results if r.channel == channel]
        if status is not None:
            results = [r for r in results if r.status == status]
        return results[-limit:]

    # -- domain operations ---

    def track_delivery(
        self,
    ) -> list[dict[str, Any]]:
        """Track delivery rates by channel."""
        ch_data: dict[str, list[DeliveryRecord]] = {}
        for r in self._records:
            ch_data.setdefault(r.channel.value, []).append(r)
        results: list[dict[str, Any]] = []
        for ch, records in ch_data.items():
            delivered = sum(1 for r in records if r.status == DeliveryStatus.DELIVERED)
            rate = round(delivered / len(records) * 100, 2) if records else 0.0
            results.append(
                {
                    "channel": ch,
                    "total": len(records),
                    "delivered": delivered,
                    "delivery_rate": rate,
                }
            )
        return sorted(
            results,
            key=lambda x: x["delivery_rate"],
        )

    def measure_ack_time(
        self,
    ) -> list[dict[str, Any]]:
        """Measure acknowledgment time by channel."""
        ch_data: dict[str, list[DeliveryRecord]] = {}
        for r in self._records:
            if r.ack_time_sec > 0:
                ch_data.setdefault(r.channel.value, []).append(r)
        results: list[dict[str, Any]] = []
        for ch, records in ch_data.items():
            times = [r.ack_time_sec for r in records]
            avg = round(sum(times) / len(times), 2) if times else 0.0
            slow = sum(1 for t in times if t > self._threshold)
            results.append(
                {
                    "channel": ch,
                    "avg_ack_sec": avg,
                    "slow_count": slow,
                    "max_ack_sec": max(times) if times else 0.0,
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_ack_sec"],
            reverse=True,
        )

    def escalate_unacked(
        self,
    ) -> list[dict[str, Any]]:
        """Find unacknowledged notifications."""
        unacked = [
            r
            for r in self._records
            if r.ack_type == AcknowledgmentType.TIMED_OUT
            or (r.status == DeliveryStatus.DELIVERED and r.ack_time_sec == 0)
        ]
        results: list[dict[str, Any]] = []
        for r in unacked[-50:]:
            results.append(
                {
                    "notification_id": r.notification_id,
                    "channel": r.channel.value,
                    "recipient": r.recipient,
                    "status": r.status.value,
                }
            )
        return results

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.notification_id == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
        }

    def generate_report(self) -> DeliveryReport:
        by_ch: dict[str, int] = {}
        by_st: dict[str, int] = {}
        by_ack: dict[str, int] = {}
        for r in self._records:
            by_ch[r.channel.value] = by_ch.get(r.channel.value, 0) + 1
            by_st[r.status.value] = by_st.get(r.status.value, 0) + 1
            by_ack[r.ack_type.value] = by_ack.get(r.ack_type.value, 0) + 1
        times = [r.ack_time_sec for r in self._records if r.ack_time_sec > 0]
        avg_ack = round(sum(times) / len(times), 2) if times else 0.0
        delivered = sum(1 for r in self._records if r.status == DeliveryStatus.DELIVERED)
        rate = (
            round(
                delivered / len(self._records) * 100,
                2,
            )
            if self._records
            else 0.0
        )
        recs: list[str] = []
        if rate < 95:
            recs.append(f"Delivery rate {rate}% below 95%")
        if avg_ack > self._threshold:
            recs.append(f"Avg ack {avg_ack}s exceeds {self._threshold}s")
        if not recs:
            recs.append("Notification Delivery healthy")
        return DeliveryReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_ack_time_sec=avg_ack,
            delivery_rate=rate,
            by_channel=by_ch,
            by_status=by_st,
            by_ack=by_ack,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("notification_delivery.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        ch_dist: dict[str, int] = {}
        for r in self._records:
            k = r.channel.value
            ch_dist[k] = ch_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "ack_threshold_sec": self._threshold,
            "channel_distribution": ch_dist,
        }
