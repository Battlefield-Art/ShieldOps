"""Cross-Cloud Pivot Detector Engine — detect privilege escalation across cloud boundaries."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PivotType(StrEnum):
    IAM_ROLE_CHAIN = "iam_role_chain"
    TOKEN_EXCHANGE = "token_exchange"  # noqa: S105
    FEDERATION_ABUSE = "federation_abuse"
    CREDENTIAL_STUFFING = "credential_stuffing"
    API_KEY_REUSE = "api_key_reuse"


class CloudPair(StrEnum):
    AWS_TO_GCP = "aws_to_gcp"
    AWS_TO_AZURE = "aws_to_azure"
    GCP_TO_AWS = "gcp_to_aws"
    GCP_TO_AZURE = "gcp_to_azure"
    AZURE_TO_AWS = "azure_to_aws"
    AZURE_TO_GCP = "azure_to_gcp"


class PivotSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    BENIGN = "benign"


# --- Models ---


class CrossCloudPivotRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detection_id: str = ""
    pivot_type: PivotType = PivotType.IAM_ROLE_CHAIN
    cloud_pair: CloudPair = CloudPair.AWS_TO_GCP
    pivot_severity: PivotSeverity = PivotSeverity.MEDIUM
    source_account: str = ""
    target_account: str = ""
    confidence: float = 0.0
    escalation_depth: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CrossCloudPivotAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detection_id: str = ""
    pivot_type: PivotType = PivotType.IAM_ROLE_CHAIN
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CrossCloudPivotReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_confidence: float = 0.0
    by_pivot_type: dict[str, int] = Field(default_factory=dict)
    by_cloud_pair: dict[str, int] = Field(default_factory=dict)
    by_pivot_severity: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CrossCloudPivotDetectorEngine:
    """Detect privilege escalation across cloud boundaries."""

    def __init__(
        self,
        max_records: int = 200000,
        severity_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = severity_threshold
        self._records: list[CrossCloudPivotRecord] = []
        self._analyses: list[CrossCloudPivotAnalysis] = []
        logger.info(
            "cross_cloud_pivot_detector_engine.initialized",
            max_records=max_records,
            severity_threshold=severity_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        detection_id: str,
        pivot_type: PivotType = PivotType.IAM_ROLE_CHAIN,
        cloud_pair: CloudPair = CloudPair.AWS_TO_GCP,
        pivot_severity: PivotSeverity = PivotSeverity.MEDIUM,
        source_account: str = "",
        target_account: str = "",
        confidence: float = 0.0,
        escalation_depth: int = 0,
        service: str = "",
        team: str = "",
    ) -> CrossCloudPivotRecord:
        record = CrossCloudPivotRecord(
            detection_id=detection_id,
            pivot_type=pivot_type,
            cloud_pair=cloud_pair,
            pivot_severity=pivot_severity,
            source_account=source_account,
            target_account=target_account,
            confidence=confidence,
            escalation_depth=escalation_depth,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "cross_cloud_pivot_detector_engine.record_added",
            record_id=record.id,
            detection_id=detection_id,
            pivot_type=pivot_type.value,
            pivot_severity=pivot_severity.value,
        )
        return record

    def get_record(self, record_id: str) -> CrossCloudPivotRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        pivot_type: PivotType | None = None,
        pivot_severity: PivotSeverity | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CrossCloudPivotRecord]:
        results = list(self._records)
        if pivot_type is not None:
            results = [r for r in results if r.pivot_type == pivot_type]
        if pivot_severity is not None:
            results = [r for r in results if r.pivot_severity == pivot_severity]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        detection_id: str,
        pivot_type: PivotType = PivotType.IAM_ROLE_CHAIN,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CrossCloudPivotAnalysis:
        analysis = CrossCloudPivotAnalysis(
            detection_id=detection_id,
            pivot_type=pivot_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "cross_cloud_pivot_detector_engine.analysis_added",
            detection_id=detection_id,
            pivot_type=pivot_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_pivot_distribution(self) -> dict[str, Any]:
        """Analyze pivot distribution by cloud pair and type."""
        pair_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.cloud_pair.value
            pair_data.setdefault(key, {})
            pt = r.pivot_type.value
            pair_data[key][pt] = pair_data[key].get(pt, 0) + 1
        result: dict[str, Any] = {}
        for pair, types in pair_data.items():
            total = sum(types.values())
            confs = [r.confidence for r in self._records if r.cloud_pair.value == pair]
            avg_conf = round(sum(confs) / len(confs), 2) if confs else 0.0
            result[pair] = {
                "total": total,
                "types": types,
                "avg_confidence": avg_conf,
                "above_threshold": avg_conf > self._threshold,
            }
        return result

    def identify_critical_pivots(self) -> list[dict[str, Any]]:
        """Identify critical and high severity cross-cloud pivots."""
        critical: list[dict[str, Any]] = []
        for r in self._records:
            if r.pivot_severity in (PivotSeverity.CRITICAL, PivotSeverity.HIGH):
                critical.append(
                    {
                        "record_id": r.id,
                        "detection_id": r.detection_id,
                        "pivot_type": r.pivot_type.value,
                        "cloud_pair": r.cloud_pair.value,
                        "pivot_severity": r.pivot_severity.value,
                        "source_account": r.source_account,
                        "target_account": r.target_account,
                        "confidence": r.confidence,
                        "escalation_depth": r.escalation_depth,
                    }
                )
        return sorted(critical, key=lambda x: x["confidence"], reverse=True)

    def detect_pivot_trends(self) -> list[dict[str, Any]]:
        """Detect trends in cross-cloud pivot detections over time."""
        buckets: dict[str, list[CrossCloudPivotRecord]] = {}
        for r in self._records:
            day = time.strftime("%Y-%m-%d", time.gmtime(r.created_at))
            buckets.setdefault(day, []).append(r)
        trends: list[dict[str, Any]] = []
        for day, records in sorted(buckets.items()):
            critical_ct = sum(1 for r in records if r.pivot_severity == PivotSeverity.CRITICAL)
            avg_depth = (
                round(sum(r.escalation_depth for r in records) / len(records), 2)
                if records
                else 0.0
            )
            trends.append(
                {
                    "date": day,
                    "total_pivots": len(records),
                    "critical_pivots": critical_ct,
                    "avg_escalation_depth": avg_depth,
                }
            )
        return trends

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> CrossCloudPivotReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.pivot_type.value] = by_e1.get(r.pivot_type.value, 0) + 1
            by_e2[r.cloud_pair.value] = by_e2.get(r.cloud_pair.value, 0) + 1
            by_e3[r.pivot_severity.value] = by_e3.get(r.pivot_severity.value, 0) + 1
        confs = [r.confidence for r in self._records]
        avg_conf = round(sum(confs) / len(confs), 2) if confs else 0.0
        gap_count = sum(
            1
            for r in self._records
            if r.pivot_severity in (PivotSeverity.CRITICAL, PivotSeverity.HIGH)
        )
        gap_list = self.identify_critical_pivots()
        top_gaps = [o["detection_id"] for o in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} critical/high severity pivot(s) detected")
        if not recs:
            recs.append("Cross-Cloud Pivot Detector Engine is healthy")
        return CrossCloudPivotReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_confidence=avg_conf,
            by_pivot_type=by_e1,
            by_cloud_pair=by_e2,
            by_pivot_severity=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("cross_cloud_pivot_detector_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.pivot_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "pivot_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
