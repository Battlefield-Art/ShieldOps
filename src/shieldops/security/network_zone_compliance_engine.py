"""NetworkZoneComplianceEngine — Track and enforce network zone compliance."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ZoneClassification(StrEnum):
    DMZ = "dmz"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    PUBLIC = "public"
    MANAGEMENT = "management"


class TrafficVerdict(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    FLAGGED = "flagged"
    RATE_LIMITED = "rate_limited"
    LOGGED = "logged"


class ViolationType(StrEnum):
    UNAUTHORIZED_FLOW = "unauthorized_flow"
    MISSING_ENCRYPTION = "missing_encryption"
    EXCESSIVE_ACCESS = "excessive_access"
    LATERAL_MOVEMENT = "lateral_movement"
    POLICY_GAP = "policy_gap"


# --- Models ---


class NetworkZoneComplianceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    zone_classification: ZoneClassification = ZoneClassification.INTERNAL
    traffic_verdict: TrafficVerdict = TrafficVerdict.ALLOWED
    violation_type: ViolationType = ViolationType.UNAUTHORIZED_FLOW
    score: float = 0.0
    source_zone: str = ""
    destination_zone: str = ""
    protocol: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class NetworkZoneComplianceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    zone_classification: ZoneClassification = ZoneClassification.INTERNAL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class NetworkZoneComplianceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_zone_classification: dict[str, int] = Field(default_factory=dict)
    by_traffic_verdict: dict[str, int] = Field(default_factory=dict)
    by_violation_type: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class NetworkZoneComplianceEngine:
    """Track and enforce network zone compliance across infrastructure."""

    def __init__(
        self,
        max_records: int = 200000,
        compliance_threshold: float = 90.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = compliance_threshold
        self._records: list[NetworkZoneComplianceRecord] = []
        self._analyses: list[NetworkZoneComplianceAnalysis] = []
        logger.info(
            "network_zone_compliance_engine.initialized",
            max_records=max_records,
            compliance_threshold=compliance_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        zone_classification: ZoneClassification = ZoneClassification.INTERNAL,
        traffic_verdict: TrafficVerdict = TrafficVerdict.ALLOWED,
        violation_type: ViolationType = ViolationType.UNAUTHORIZED_FLOW,
        score: float = 0.0,
        source_zone: str = "",
        destination_zone: str = "",
        protocol: str = "",
        service: str = "",
        team: str = "",
    ) -> NetworkZoneComplianceRecord:
        record = NetworkZoneComplianceRecord(
            name=name,
            zone_classification=zone_classification,
            traffic_verdict=traffic_verdict,
            violation_type=violation_type,
            score=score,
            source_zone=source_zone,
            destination_zone=destination_zone,
            protocol=protocol,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "network_zone_compliance_engine.record_added",
            record_id=record.id,
            name=name,
            zone_classification=zone_classification.value,
            traffic_verdict=traffic_verdict.value,
        )
        return record

    def get_record(self, record_id: str) -> NetworkZoneComplianceRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        zone_classification: ZoneClassification | None = None,
        traffic_verdict: TrafficVerdict | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[NetworkZoneComplianceRecord]:
        results = list(self._records)
        if zone_classification is not None:
            results = [r for r in results if r.zone_classification == zone_classification]
        if traffic_verdict is not None:
            results = [r for r in results if r.traffic_verdict == traffic_verdict]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        zone_classification: ZoneClassification = ZoneClassification.INTERNAL,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> NetworkZoneComplianceAnalysis:
        analysis = NetworkZoneComplianceAnalysis(
            name=name,
            zone_classification=zone_classification,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "network_zone_compliance_engine.analysis_added",
            name=name,
            zone_classification=zone_classification.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_zone_violations(self) -> list[dict[str, Any]]:
        """Identify zones with high violation rates."""
        zone_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            z = r.zone_classification.value
            zone_data.setdefault(z, {})
            v = r.traffic_verdict.value
            zone_data[z][v] = zone_data[z].get(v, 0) + 1
        violations: list[dict[str, Any]] = []
        for zone, verdicts in zone_data.items():
            total = sum(verdicts.values())
            blocked = verdicts.get("blocked", 0)
            flagged = verdicts.get("flagged", 0)
            violation_pct = round((blocked + flagged) / total * 100, 1) if total else 0.0
            if blocked > 0 or flagged > 0:
                violations.append(
                    {
                        "zone": zone,
                        "total_flows": total,
                        "blocked": blocked,
                        "flagged": flagged,
                        "violation_pct": violation_pct,
                        "severity": "critical" if blocked > flagged else "warning",
                    }
                )
        return sorted(violations, key=lambda x: x["violation_pct"], reverse=True)

    def compute_zone_compliance(self) -> list[dict[str, Any]]:
        """Compute compliance score per zone classification."""
        zone_records: dict[str, list[NetworkZoneComplianceRecord]] = {}
        for r in self._records:
            zone_records.setdefault(r.zone_classification.value, []).append(r)
        results: list[dict[str, Any]] = []
        for zone, records in zone_records.items():
            total = len(records)
            compliant = sum(
                1
                for r in records
                if r.traffic_verdict in (TrafficVerdict.ALLOWED, TrafficVerdict.LOGGED)
            )
            compliance_pct = round(compliant / total * 100, 1) if total else 0.0
            avg_score = round(sum(r.score for r in records) / total, 2) if total else 0.0
            results.append(
                {
                    "zone": zone,
                    "total_flows": total,
                    "compliant": compliant,
                    "compliance_pct": compliance_pct,
                    "avg_score": avg_score,
                }
            )
        return sorted(results, key=lambda x: x["compliance_pct"])

    def recommend_policy_changes(self) -> list[dict[str, Any]]:
        """Recommend policy changes based on violation patterns."""
        recommendations: list[dict[str, Any]] = []
        unauthorized = [
            r for r in self._records if r.violation_type == ViolationType.UNAUTHORIZED_FLOW
        ]
        for r in unauthorized:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "zone": r.zone_classification.value,
                    "issue": "unauthorized_flow",
                    "priority": "critical",
                    "suggestion": (
                        f"Block unauthorized flow from {r.source_zone} to {r.destination_zone}"
                    ),
                }
            )
        lateral = [r for r in self._records if r.violation_type == ViolationType.LATERAL_MOVEMENT]
        for r in lateral:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "zone": r.zone_classification.value,
                    "issue": "lateral_movement",
                    "priority": "critical",
                    "suggestion": (f"Restrict lateral movement in {r.zone_classification.value}"),
                }
            )
        unencrypted = [
            r for r in self._records if r.violation_type == ViolationType.MISSING_ENCRYPTION
        ]
        for r in unencrypted:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "zone": r.zone_classification.value,
                    "issue": "missing_encryption",
                    "priority": "high",
                    "suggestion": f"Enable TLS for {r.protocol} traffic",
                }
            )
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        return sorted(recommendations, key=lambda x: priority_order.get(x["priority"], 3))

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        zone_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.zone_classification.value
            zone_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in zone_data.items():
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
                        "zone_classification": r.zone_classification.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
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

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> NetworkZoneComplianceReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.zone_classification.value] = by_e1.get(r.zone_classification.value, 0) + 1
            by_e2[r.traffic_verdict.value] = by_e2.get(r.traffic_verdict.value, 0) + 1
            by_e3[r.violation_type.value] = by_e3.get(r.violation_type.value, 0) + 1
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
            recs.append("Network Zone Compliance Engine is healthy")
        return NetworkZoneComplianceReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_zone_classification=by_e1,
            by_traffic_verdict=by_e2,
            by_violation_type=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("network_zone_compliance_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.zone_classification.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "zone_classification_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
