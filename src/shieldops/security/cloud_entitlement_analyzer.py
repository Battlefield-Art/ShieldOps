"""Cloud Entitlement Analyzer — analyze cloud identity entitlements (CIEM)."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EntitlementRisk(StrEnum):
    OVER_PRIVILEGED = "over_privileged"
    UNUSED = "unused"
    SHARED = "shared"
    STALE = "stale"


class CloudProvider(StrEnum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    KUBERNETES = "kubernetes"


class RemediationAction(StrEnum):
    REMOVE = "remove"
    RESTRICT = "restrict"
    ROTATE = "rotate"
    MONITOR = "monitor"


# --- Models ---


class CloudEntitlementRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    entitlement_risk: EntitlementRisk = EntitlementRisk.OVER_PRIVILEGED
    cloud_provider: CloudProvider = CloudProvider.AWS
    remediation_action: RemediationAction = RemediationAction.MONITOR
    score: float = 0.0
    permission_count: int = 0
    used_permissions: int = 0
    identity_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CloudEntitlementAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    entitlement_risk: EntitlementRisk = EntitlementRisk.OVER_PRIVILEGED
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CloudEntitlementReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_entitlement_risk: dict[str, int] = Field(default_factory=dict)
    by_cloud_provider: dict[str, int] = Field(default_factory=dict)
    by_remediation_action: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CloudEntitlementAnalyzerEngine:
    """Analyze cloud identity entitlements (CIEM)."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[CloudEntitlementRecord] = []
        self._analyses: list[CloudEntitlementAnalysis] = []
        logger.info(
            "cloud_entitlement_analyzer.init",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ---

    def add_record(
        self,
        name: str,
        entitlement_risk: EntitlementRisk = (EntitlementRisk.OVER_PRIVILEGED),
        cloud_provider: CloudProvider = (CloudProvider.AWS),
        remediation_action: RemediationAction = (RemediationAction.MONITOR),
        score: float = 0.0,
        permission_count: int = 0,
        used_permissions: int = 0,
        identity_id: str = "",
        service: str = "",
        team: str = "",
    ) -> CloudEntitlementRecord:
        record = CloudEntitlementRecord(
            name=name,
            entitlement_risk=entitlement_risk,
            cloud_provider=cloud_provider,
            remediation_action=remediation_action,
            score=score,
            permission_count=permission_count,
            used_permissions=used_permissions,
            identity_id=identity_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "cloud_entitlement.record_added",
            record_id=record.id,
            name=name,
            cloud_provider=cloud_provider.value,
        )
        return record

    def get_record(self, record_id: str) -> CloudEntitlementRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        entitlement_risk: (EntitlementRisk | None) = None,
        cloud_provider: (CloudProvider | None) = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CloudEntitlementRecord]:
        results = list(self._records)
        if entitlement_risk is not None:
            results = [r for r in results if r.entitlement_risk == entitlement_risk]
        if cloud_provider is not None:
            results = [r for r in results if r.cloud_provider == cloud_provider]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        entitlement_risk: EntitlementRisk = (EntitlementRisk.OVER_PRIVILEGED),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CloudEntitlementAnalysis:
        analysis = CloudEntitlementAnalysis(
            name=name,
            entitlement_risk=entitlement_risk,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "cloud_entitlement.analysis_added",
            name=name,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ---

    def analyze_entitlements(
        self,
    ) -> list[dict[str, Any]]:
        """Analyze entitlement usage per identity."""
        id_data: dict[str, list[CloudEntitlementRecord]] = {}
        for r in self._records:
            if r.identity_id:
                id_data.setdefault(r.identity_id, []).append(r)
        results: list[dict[str, Any]] = []
        for iid, records in id_data.items():
            total_perms = sum(r.permission_count for r in records)
            used = sum(r.used_permissions for r in records)
            usage_pct = round(used / total_perms * 100, 1) if total_perms else 0.0
            risk_ct: dict[str, int] = {}
            for r in records:
                rk = r.entitlement_risk.value
                risk_ct[rk] = risk_ct.get(rk, 0) + 1
            results.append(
                {
                    "identity_id": iid,
                    "total_permissions": total_perms,
                    "used_permissions": used,
                    "usage_pct": usage_pct,
                    "risk_distribution": risk_ct,
                    "over_privileged": usage_pct < 20,
                }
            )
        return sorted(results, key=lambda x: x["usage_pct"])

    def detect_privilege_escalation_paths(
        self,
    ) -> list[dict[str, Any]]:
        """Detect potential privilege escalation paths."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.entitlement_risk == EntitlementRisk.OVER_PRIVILEGED and r.permission_count > 50:
                excess = r.permission_count - r.used_permissions
                results.append(
                    {
                        "identity_id": (r.identity_id),
                        "name": r.name,
                        "cloud": (r.cloud_provider.value),
                        "total_perms": (r.permission_count),
                        "excess_perms": excess,
                        "risk_score": r.score,
                        "escalation_risk": (
                            "critical" if excess > 100 else ("high" if excess > 50 else "medium")
                        ),
                    }
                )
        return sorted(
            results,
            key=lambda x: x["excess_perms"],
            reverse=True,
        )

    def recommend_right_sizing(
        self,
    ) -> list[dict[str, Any]]:
        """Recommend permission right-sizing."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            usage = r.used_permissions / r.permission_count * 100 if r.permission_count > 0 else 0.0
            if usage < 50:
                action = RemediationAction.REMOVE if usage < 10 else RemediationAction.RESTRICT
                results.append(
                    {
                        "identity_id": (r.identity_id),
                        "name": r.name,
                        "usage_pct": round(usage, 1),
                        "action": action.value,
                        "removable": (r.permission_count - r.used_permissions),
                        "cloud": (r.cloud_provider.value),
                    }
                )
        return sorted(results, key=lambda x: x["usage_pct"])

    # -- standard methods ---

    def analyze_distribution(
        self,
    ) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.entitlement_risk.value
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
                        "entitlement_risk": (r.entitlement_risk.value),
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
    ) -> CloudEntitlementReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            k1 = r.entitlement_risk.value
            by_e1[k1] = by_e1.get(k1, 0) + 1
            k2 = r.cloud_provider.value
            by_e2[k2] = by_e2.get(k2, 0) + 1
            k3 = r.remediation_action.value
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
            recs.append("Cloud Entitlement Analyzer healthy")
        return CloudEntitlementReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_entitlement_risk=by_e1,
            by_cloud_provider=by_e2,
            by_remediation_action=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("cloud_entitlement_analyzer.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.entitlement_risk.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "entitlement_risk_dist": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
