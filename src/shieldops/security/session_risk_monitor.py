"""Session Risk Monitor — monitor active sessions for zero trust verification."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SessionRisk(StrEnum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"


class RiskTrigger(StrEnum):
    LOCATION_CHANGE = "location_change"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ANOMALOUS_ACCESS = "anomalous_access"
    TIME_ANOMALY = "time_anomaly"


class SessionAction(StrEnum):
    CONTINUE = "continue"
    REAUTHENTICATE = "reauthenticate"
    TERMINATE = "terminate"


# --- Models ---


class SessionRiskRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    session_risk: SessionRisk = SessionRisk.NORMAL
    risk_trigger: RiskTrigger = RiskTrigger.ANOMALOUS_ACCESS
    session_action: SessionAction = SessionAction.CONTINUE
    score: float = 0.0
    session_id: str = ""
    identity_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SessionRiskAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    session_risk: SessionRisk = SessionRisk.NORMAL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SessionRiskReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_session_risk: dict[str, int] = Field(default_factory=dict)
    by_risk_trigger: dict[str, int] = Field(default_factory=dict)
    by_session_action: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class SessionRiskMonitorEngine:
    """Monitor sessions for zero trust verification."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[SessionRiskRecord] = []
        self._analyses: list[SessionRiskAnalysis] = []
        logger.info(
            "session_risk_monitor.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ---

    def add_record(
        self,
        name: str,
        session_risk: SessionRisk = (SessionRisk.NORMAL),
        risk_trigger: RiskTrigger = (RiskTrigger.ANOMALOUS_ACCESS),
        session_action: SessionAction = (SessionAction.CONTINUE),
        score: float = 0.0,
        session_id: str = "",
        identity_id: str = "",
        service: str = "",
        team: str = "",
    ) -> SessionRiskRecord:
        record = SessionRiskRecord(
            name=name,
            session_risk=session_risk,
            risk_trigger=risk_trigger,
            session_action=session_action,
            score=score,
            session_id=session_id,
            identity_id=identity_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "session_risk_monitor.record_added",
            record_id=record.id,
            name=name,
            session_risk=session_risk.value,
        )
        return record

    def get_record(self, record_id: str) -> SessionRiskRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        session_risk: SessionRisk | None = None,
        risk_trigger: RiskTrigger | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[SessionRiskRecord]:
        results = list(self._records)
        if session_risk is not None:
            results = [r for r in results if r.session_risk == session_risk]
        if risk_trigger is not None:
            results = [r for r in results if r.risk_trigger == risk_trigger]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        session_risk: SessionRisk = (SessionRisk.NORMAL),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> SessionRiskAnalysis:
        analysis = SessionRiskAnalysis(
            name=name,
            session_risk=session_risk,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "session_risk_monitor.analysis_added",
            name=name,
            session_risk=session_risk.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ---

    def monitor_session(
        self,
    ) -> list[dict[str, Any]]:
        """Monitor active sessions and risk levels."""
        session_data: dict[str, list[SessionRiskRecord]] = {}
        for r in self._records:
            if r.session_id:
                session_data.setdefault(r.session_id, []).append(r)
        results: list[dict[str, Any]] = []
        for sid, records in session_data.items():
            latest = records[-1]
            triggers = {r.risk_trigger.value for r in records}
            escalations = sum(
                1
                for r in records
                if r.session_risk
                in (
                    SessionRisk.SUSPICIOUS,
                    SessionRisk.COMPROMISED,
                )
            )
            results.append(
                {
                    "session_id": sid,
                    "current_risk": (latest.session_risk.value),
                    "triggers": sorted(triggers),
                    "escalation_count": escalations,
                    "event_count": len(records),
                    "identity_id": (latest.identity_id),
                    "recommended_action": (latest.session_action.value),
                }
            )
        return sorted(
            results,
            key=lambda x: x["escalation_count"],
            reverse=True,
        )

    def detect_session_anomaly(
        self,
    ) -> list[dict[str, Any]]:
        """Detect anomalous session behaviors."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.session_risk in (
                SessionRisk.SUSPICIOUS,
                SessionRisk.COMPROMISED,
            ):
                severity = "critical" if r.session_risk == SessionRisk.COMPROMISED else "high"
                results.append(
                    {
                        "session_id": r.session_id,
                        "identity_id": (r.identity_id),
                        "risk_level": (r.session_risk.value),
                        "trigger": (r.risk_trigger.value),
                        "severity": severity,
                        "score": r.score,
                        "action": (r.session_action.value),
                    }
                )
        return sorted(
            results,
            key=lambda x: x["score"],
            reverse=True,
        )

    def trigger_reauthentication(
        self,
    ) -> list[dict[str, Any]]:
        """Identify sessions requiring reauth."""
        session_data: dict[str, list[SessionRiskRecord]] = {}
        for r in self._records:
            if r.session_id:
                session_data.setdefault(r.session_id, []).append(r)
        reauths: list[dict[str, Any]] = []
        for sid, records in session_data.items():
            risk_events = sum(1 for r in records if r.session_risk != SessionRisk.NORMAL)
            total = len(records)
            risk_pct = round(risk_events / total * 100, 1)
            if risk_pct > 30:
                latest = records[-1]
                action = "terminate" if risk_pct > 70 else "reauthenticate"
                reauths.append(
                    {
                        "session_id": sid,
                        "identity_id": (latest.identity_id),
                        "risk_event_pct": risk_pct,
                        "action": action,
                        "trigger_count": risk_events,
                        "current_risk": (latest.session_risk.value),
                    }
                )
        return sorted(
            reauths,
            key=lambda x: x["risk_event_pct"],
            reverse=True,
        )

    # -- standard methods ---

    def analyze_distribution(
        self,
    ) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.session_risk.value
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
                        "session_risk": (r.session_risk.value),
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc: dict[str, list[float]] = {}
        for r in self._records:
            svc.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for s, scores in svc.items():
            results.append(
                {
                    "service": s,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats ---

    def generate_report(
        self,
    ) -> SessionRiskReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            k1 = r.session_risk.value
            by_e1[k1] = by_e1.get(k1, 0) + 1
            k2 = r.risk_trigger.value
            by_e2[k2] = by_e2.get(k2, 0) + 1
            k3 = r.session_action.value
            by_e3[k3] = by_e3.get(k3, 0) + 1
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
            recs.append("Session Risk Monitor is healthy")
        return SessionRiskReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_session_risk=by_e1,
            by_risk_trigger=by_e2,
            by_session_action=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("session_risk_monitor.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.session_risk.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "session_risk_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
