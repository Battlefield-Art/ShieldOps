"""Burn Rate Alert Engine — track SLO burn rate alerts and response."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AlertWindow(StrEnum):
    ONE_HOUR = "one_hour"
    SIX_HOUR = "six_hour"
    ONE_DAY = "one_day"
    THREE_DAY = "three_day"
    THIRTY_DAY = "thirty_day"


class AlertSeverity(StrEnum):
    PAGE = "page"
    TICKET = "ticket"
    WARNING = "warning"
    INFO = "info"
    RESOLVED = "resolved"


class ResponseOutcome(StrEnum):
    MITIGATED = "mitigated"
    ESCALATED = "escalated"
    AUTO_RESOLVED = "auto_resolved"
    FALSE_ALARM = "false_alarm"
    ONGOING = "ongoing"


# --- Models ---


class BurnRateAlertRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    slo_name: str = ""
    alert_window: AlertWindow = AlertWindow.ONE_HOUR
    alert_severity: AlertSeverity = AlertSeverity.WARNING
    response_outcome: ResponseOutcome = ResponseOutcome.ONGOING
    burn_rate_multiplier: float = 1.0
    error_budget_consumed_pct: float = 0.0
    response_time_seconds: float = 0.0
    mitigation_time_seconds: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class BurnRateAlertAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    analysis_score: float = 0.0
    alert_window: AlertWindow = AlertWindow.ONE_HOUR
    false_alarm_rate: float = 0.0
    data_points: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class BurnRateAlertReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_response_time: float = 0.0
    by_window: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    high_burn_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class BurnRateAlertEngine:
    """Track SLO burn rate alerts and response effectiveness."""

    def __init__(
        self,
        max_records: int = 200000,
        burn_rate_threshold: float = 10.0,
    ) -> None:
        self._max_records = max_records
        self._burn_rate_threshold = burn_rate_threshold
        self._records: list[BurnRateAlertRecord] = []
        self._analyses: dict[str, BurnRateAlertAnalysis] = {}
        logger.info(
            "burn_rate_alert_engine.init",
            max_records=max_records,
            burn_rate_threshold=burn_rate_threshold,
        )

    def add_record(
        self,
        service_id: str = "",
        slo_name: str = "",
        alert_window: AlertWindow = AlertWindow.ONE_HOUR,
        alert_severity: AlertSeverity = AlertSeverity.WARNING,
        response_outcome: ResponseOutcome = ResponseOutcome.ONGOING,
        burn_rate_multiplier: float = 1.0,
        error_budget_consumed_pct: float = 0.0,
        response_time_seconds: float = 0.0,
        mitigation_time_seconds: float = 0.0,
        description: str = "",
    ) -> BurnRateAlertRecord:
        record = BurnRateAlertRecord(
            service_id=service_id,
            slo_name=slo_name,
            alert_window=alert_window,
            alert_severity=alert_severity,
            response_outcome=response_outcome,
            burn_rate_multiplier=burn_rate_multiplier,
            error_budget_consumed_pct=error_budget_consumed_pct,
            response_time_seconds=response_time_seconds,
            mitigation_time_seconds=mitigation_time_seconds,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "burn_rate_alert_engine.record_added",
            record_id=record.id,
            service_id=service_id,
        )
        return record

    def process(
        self, key: str,
    ) -> BurnRateAlertAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        svc_recs = [
            r for r in self._records if r.service_id == rec.service_id
        ]
        false_alarms = sum(
            1
            for r in svc_recs
            if r.response_outcome == ResponseOutcome.FALSE_ALARM
        )
        total = len(svc_recs)
        fa_rate = (
            round(false_alarms / total * 100, 2) if total > 0 else 0.0
        )
        score = round(100.0 - fa_rate, 2)
        analysis = BurnRateAlertAnalysis(
            service_id=rec.service_id,
            analysis_score=score,
            alert_window=rec.alert_window,
            false_alarm_rate=fa_rate,
            data_points=total,
            description=(
                f"Burn rate alert quality {score}% for {rec.service_id}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> BurnRateAlertReport:
        by_w: dict[str, int] = {}
        by_s: dict[str, int] = {}
        by_o: dict[str, int] = {}
        resp_times: list[float] = []
        for r in self._records:
            by_w[r.alert_window.value] = (
                by_w.get(r.alert_window.value, 0) + 1
            )
            by_s[r.alert_severity.value] = (
                by_s.get(r.alert_severity.value, 0) + 1
            )
            by_o[r.response_outcome.value] = (
                by_o.get(r.response_outcome.value, 0) + 1
            )
            if r.response_time_seconds > 0:
                resp_times.append(r.response_time_seconds)
        avg_resp = (
            round(sum(resp_times) / len(resp_times), 2)
            if resp_times
            else 0.0
        )
        high_burn = list(
            {
                r.service_id
                for r in self._records
                if r.burn_rate_multiplier >= self._burn_rate_threshold
            }
        )[:10]
        recs: list[str] = []
        false_alarm_count = by_o.get(ResponseOutcome.FALSE_ALARM.value, 0)
        total = len(self._records)
        if total > 0 and false_alarm_count / total > 0.3:
            recs.append(
                f"High false alarm rate ({false_alarm_count}/{total})"
                " — tune alert thresholds"
            )
        if high_burn:
            recs.append(
                f"{len(high_burn)} services with burn rate"
                f" >= {self._burn_rate_threshold}x"
            )
        pages = by_s.get(AlertSeverity.PAGE.value, 0)
        if pages > 10:
            recs.append(f"{pages} page-level alerts — review SLO targets")
        if not recs:
            recs.append(
                "Burn rate alerting healthy — response times acceptable"
            )
        return BurnRateAlertReport(
            total_records=total,
            total_analyses=len(self._analyses),
            avg_response_time=avg_resp,
            by_window=by_w,
            by_severity=by_s,
            by_outcome=by_o,
            high_burn_services=high_burn,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        window_dist: dict[str, int] = {}
        for r in self._records:
            k = r.alert_window.value
            window_dist[k] = window_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "burn_rate_threshold": self._burn_rate_threshold,
            "window_distribution": window_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("burn_rate_alert_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def rank_alerts_by_burn_rate(self) -> list[dict[str, Any]]:
        """Rank alerts by burn rate multiplier."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            results.append(
                {
                    "service_id": r.service_id,
                    "slo_name": r.slo_name,
                    "burn_rate_multiplier": r.burn_rate_multiplier,
                    "alert_window": r.alert_window.value,
                    "severity": r.alert_severity.value,
                    "budget_consumed_pct": r.error_budget_consumed_pct,
                }
            )
        results.sort(
            key=lambda x: x["burn_rate_multiplier"], reverse=True
        )
        return results[:50]

    def compute_response_effectiveness(self) -> list[dict[str, Any]]:
        """Compute response effectiveness per service."""
        svc_data: dict[str, dict[str, int]] = {}
        svc_times: dict[str, list[float]] = {}
        for r in self._records:
            svc_data.setdefault(
                r.service_id, {"mitigated": 0, "total": 0}
            )
            svc_data[r.service_id]["total"] += 1
            if r.response_outcome == ResponseOutcome.MITIGATED:
                svc_data[r.service_id]["mitigated"] += 1
            if r.mitigation_time_seconds > 0:
                svc_times.setdefault(r.service_id, []).append(
                    r.mitigation_time_seconds
                )
        results: list[dict[str, Any]] = []
        for sid, data in svc_data.items():
            rate = (
                round(data["mitigated"] / data["total"] * 100, 2)
                if data["total"]
                else 0.0
            )
            times = svc_times.get(sid, [])
            avg_mit = (
                round(sum(times) / len(times), 2) if times else 0.0
            )
            results.append(
                {
                    "service_id": sid,
                    "mitigation_rate_pct": rate,
                    "avg_mitigation_seconds": avg_mit,
                    "alert_count": data["total"],
                }
            )
        results.sort(key=lambda x: x["mitigation_rate_pct"])
        return results

    def analyze_alert_windows(self) -> list[dict[str, Any]]:
        """Analyze alert distribution and effectiveness per window."""
        window_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            k = r.alert_window.value
            window_data.setdefault(
                k, {"total": 0, "false_alarm": 0, "mitigated": 0}
            )
            window_data[k]["total"] += 1
            if r.response_outcome == ResponseOutcome.FALSE_ALARM:
                window_data[k]["false_alarm"] += 1
            elif r.response_outcome == ResponseOutcome.MITIGATED:
                window_data[k]["mitigated"] += 1
        results: list[dict[str, Any]] = []
        for window, data in window_data.items():
            fa_rate = (
                round(data["false_alarm"] / data["total"] * 100, 2)
                if data["total"]
                else 0.0
            )
            results.append(
                {
                    "alert_window": window,
                    "total_alerts": data["total"],
                    "false_alarm_rate_pct": fa_rate,
                    "mitigated_count": data["mitigated"],
                }
            )
        results.sort(key=lambda x: x["total_alerts"], reverse=True)
        return results
