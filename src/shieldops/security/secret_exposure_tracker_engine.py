"""Secret Exposure Tracker Engine — track detected secret exposures and remediation."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SecretCategory(StrEnum):
    API_KEY = "api_key"
    CLOUD_CREDENTIAL = "cloud_credential"
    DATABASE_URL = "database_url"
    PRIVATE_KEY = "private_key"
    TOKEN = "token"  # noqa: S105
    PASSWORD = "password"  # noqa: S105


class ExposureChannel(StrEnum):
    GIT_REPO = "git_repo"
    CONFIG_FILE = "config_file"
    LOG_FILE = "log_file"
    CONTAINER_IMAGE = "container_image"
    CI_CD = "ci_cd"


class RemediationState(StrEnum):
    DETECTED = "detected"
    TRIAGED = "triaged"
    ROTATING = "rotating"
    ROTATED = "rotated"
    VERIFIED = "verified"
    FAILED = "failed"


# --- Models ---


class SecretExposureRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    secret_category: SecretCategory = SecretCategory.API_KEY
    exposure_channel: ExposureChannel = ExposureChannel.GIT_REPO
    remediation_state: RemediationState = RemediationState.DETECTED
    is_active: bool = True
    is_public: bool = False
    time_to_remediate_hours: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SecretExposureAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    secret_category: SecretCategory = SecretCategory.API_KEY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SecretExposureReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_remediation_hours: float = 0.0
    by_secret_category: dict[str, int] = Field(default_factory=dict)
    by_exposure_channel: dict[str, int] = Field(default_factory=dict)
    by_remediation_state: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class SecretExposureTrackerEngine:
    """Track detected secret exposures and remediation status."""

    def __init__(
        self,
        max_records: int = 200000,
        remediation_threshold: float = 24.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = remediation_threshold
        self._records: list[SecretExposureRecord] = []
        self._analyses: list[SecretExposureAnalysis] = []
        logger.info(
            "secret_exposure_tracker_engine.initialized",
            max_records=max_records,
            remediation_threshold=remediation_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        finding_id: str,
        secret_category: SecretCategory = SecretCategory.API_KEY,
        exposure_channel: ExposureChannel = ExposureChannel.GIT_REPO,
        remediation_state: RemediationState = RemediationState.DETECTED,
        is_active: bool = True,
        is_public: bool = False,
        time_to_remediate_hours: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> SecretExposureRecord:
        record = SecretExposureRecord(
            finding_id=finding_id,
            secret_category=secret_category,
            exposure_channel=exposure_channel,
            remediation_state=remediation_state,
            is_active=is_active,
            is_public=is_public,
            time_to_remediate_hours=time_to_remediate_hours,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "secret_exposure_tracker_engine.record_added",
            record_id=record.id,
            finding_id=finding_id,
            secret_category=secret_category.value,
            exposure_channel=exposure_channel.value,
        )
        return record

    def get_record(self, record_id: str) -> SecretExposureRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        secret_category: SecretCategory | None = None,
        exposure_channel: ExposureChannel | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[SecretExposureRecord]:
        results = list(self._records)
        if secret_category is not None:
            results = [r for r in results if r.secret_category == secret_category]
        if exposure_channel is not None:
            results = [r for r in results if r.exposure_channel == exposure_channel]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        finding_id: str,
        secret_category: SecretCategory = SecretCategory.API_KEY,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> SecretExposureAnalysis:
        analysis = SecretExposureAnalysis(
            finding_id=finding_id,
            secret_category=secret_category,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "secret_exposure_tracker_engine.analysis_added",
            finding_id=finding_id,
            secret_category=secret_category.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_exposure_distribution(self) -> dict[str, Any]:
        """Analyze exposure distribution by category and channel."""
        channel_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.exposure_channel.value
            channel_data.setdefault(key, {})
            cat = r.secret_category.value
            channel_data[key][cat] = channel_data[key].get(cat, 0) + 1
        result: dict[str, Any] = {}
        for channel, cats in channel_data.items():
            total = sum(cats.values())
            active_ct = sum(
                1 for r in self._records if r.exposure_channel.value == channel and r.is_active
            )
            result[channel] = {
                "total": total,
                "categories": cats,
                "active_count": active_ct,
                "active_pct": round(active_ct / total * 100, 2) if total else 0.0,
            }
        return result

    def identify_active_exposures(self) -> list[dict[str, Any]]:
        """Identify active and public secret exposures requiring urgent action."""
        active: list[dict[str, Any]] = []
        for r in self._records:
            if r.is_active and r.remediation_state not in (
                RemediationState.ROTATED,
                RemediationState.VERIFIED,
            ):
                active.append(
                    {
                        "record_id": r.id,
                        "finding_id": r.finding_id,
                        "secret_category": r.secret_category.value,
                        "exposure_channel": r.exposure_channel.value,
                        "remediation_state": r.remediation_state.value,
                        "is_public": r.is_public,
                        "time_to_remediate_hours": r.time_to_remediate_hours,
                        "service": r.service,
                    }
                )
        return sorted(
            active,
            key=lambda x: (not x["is_public"], x["time_to_remediate_hours"]),
        )

    def detect_remediation_trends(self) -> list[dict[str, Any]]:
        """Detect trends in secret remediation over time."""
        buckets: dict[str, list[SecretExposureRecord]] = {}
        for r in self._records:
            day = time.strftime("%Y-%m-%d", time.gmtime(r.created_at))
            buckets.setdefault(day, []).append(r)
        trends: list[dict[str, Any]] = []
        for day, records in sorted(buckets.items()):
            remediated_ct = sum(
                1
                for r in records
                if r.remediation_state in (RemediationState.ROTATED, RemediationState.VERIFIED)
            )
            over_threshold = sum(1 for r in records if r.time_to_remediate_hours > self._threshold)
            trends.append(
                {
                    "date": day,
                    "total_findings": len(records),
                    "remediated": remediated_ct,
                    "over_sla": over_threshold,
                }
            )
        return trends

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> SecretExposureReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.secret_category.value] = by_e1.get(r.secret_category.value, 0) + 1
            by_e2[r.exposure_channel.value] = by_e2.get(r.exposure_channel.value, 0) + 1
            by_e3[r.remediation_state.value] = by_e3.get(r.remediation_state.value, 0) + 1
        hours = [r.time_to_remediate_hours for r in self._records]
        avg_hours = round(sum(hours) / len(hours), 2) if hours else 0.0
        gap_count = sum(
            1
            for r in self._records
            if r.is_active
            and r.remediation_state not in (RemediationState.ROTATED, RemediationState.VERIFIED)
        )
        gap_list = self.identify_active_exposures()
        top_gaps = [o["finding_id"] for o in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} active unremediated secret exposure(s)")
        if avg_hours > self._threshold:
            recs.append(f"Avg remediation time {avg_hours}h exceeds threshold ({self._threshold}h)")
        if not recs:
            recs.append("Secret Exposure Tracker Engine is healthy")
        return SecretExposureReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_remediation_hours=avg_hours,
            by_secret_category=by_e1,
            by_exposure_channel=by_e2,
            by_remediation_state=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("secret_exposure_tracker_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.secret_category.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "secret_category_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
