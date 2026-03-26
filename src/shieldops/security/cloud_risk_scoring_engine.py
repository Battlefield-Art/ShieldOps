"""Cloud Risk Scoring Engine — exploitability and attacker TTPs."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RiskFactor(StrEnum):
    EXPOSURE = "exposure"
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    IDENTITY_RISK = "identity_risk"
    DATA_SENSITIVITY = "data_sensitivity"


class ExploitMaturity(StrEnum):
    WEAPONIZED = "weaponized"
    POC_AVAILABLE = "poc_available"
    THEORETICAL = "theoretical"
    UNPROVEN = "unproven"
    NOT_APPLICABLE = "not_applicable"


class BusinessImpact(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


# --- Models ---


class CloudRiskRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_id: str = ""
    risk_factor: RiskFactor = RiskFactor.EXPOSURE
    exploit_maturity: ExploitMaturity = ExploitMaturity.THEORETICAL
    impact: BusinessImpact = BusinessImpact.MEDIUM
    risk_score: float = 0.0
    attacker_ttp: str = ""
    cloud_provider: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CloudRiskAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_id: str = ""
    risk_factor: RiskFactor = RiskFactor.EXPOSURE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CloudRiskReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_risk_score: float = 0.0
    critical_count: int = 0
    by_factor: dict[str, int] = Field(default_factory=dict)
    by_maturity: dict[str, int] = Field(default_factory=dict)
    by_impact: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class CloudRiskScoringEngine:
    """Score cloud risks by exploitability."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 75.0,
    ) -> None:
        self._max_records = max_records
        self._risk_threshold = risk_threshold
        self._records: list[CloudRiskRecord] = []
        self._analyses: list[CloudRiskAnalysis] = []
        logger.info(
            "cloud_risk_scoring_engine.init",
            max_records=max_records,
        )

    # -- record --

    def add_record(
        self,
        resource_id: str = "",
        risk_factor: RiskFactor = (RiskFactor.EXPOSURE),
        exploit_maturity: ExploitMaturity = (ExploitMaturity.THEORETICAL),
        impact: BusinessImpact = (BusinessImpact.MEDIUM),
        risk_score: float = 0.0,
        attacker_ttp: str = "",
        cloud_provider: str = "",
        service: str = "",
        team: str = "",
    ) -> CloudRiskRecord:
        record = CloudRiskRecord(
            resource_id=resource_id,
            risk_factor=risk_factor,
            exploit_maturity=exploit_maturity,
            impact=impact,
            risk_score=risk_score,
            attacker_ttp=attacker_ttp,
            cloud_provider=cloud_provider,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "cloud_risk_scoring.record_added",
            record_id=record.id,
        )
        return record

    # -- process --

    def process(self, resource_id: str) -> CloudRiskAnalysis:
        relevant = [r for r in self._records if r.resource_id == resource_id]
        if not relevant:
            analysis = CloudRiskAnalysis(
                resource_id=resource_id,
                description="no records found",
            )
            self._analyses.append(analysis)
            return analysis
        scores = [r.risk_score for r in relevant]
        avg = sum(scores) / len(scores)
        breached = avg > self._risk_threshold
        analysis = CloudRiskAnalysis(
            resource_id=resource_id,
            analysis_score=round(avg, 2),
            threshold=self._risk_threshold,
            breached=breached,
            description=(f"avg_risk={round(avg, 2)}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain methods --

    def score_exploitability(
        self,
    ) -> dict[str, Any]:
        """Score by exploit maturity level."""
        mat_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.exploit_maturity.value
            mat_data.setdefault(key, []).append(r.risk_score)
        result: dict[str, Any] = {}
        for mat, scores in mat_data.items():
            result[mat] = {
                "count": len(scores),
                "avg_risk": round(sum(scores) / len(scores), 2),
            }
        return result

    def correlate_attacker_ttp(
        self,
    ) -> list[dict[str, Any]]:
        """Group risks by attacker TTP."""
        ttp_data: dict[str, list[float]] = {}
        for r in self._records:
            if r.attacker_ttp:
                ttp_data.setdefault(r.attacker_ttp, []).append(r.risk_score)
        results: list[dict[str, Any]] = []
        for ttp, scores in ttp_data.items():
            avg = sum(scores) / len(scores)
            results.append(
                {
                    "ttp": ttp,
                    "count": len(scores),
                    "avg_risk": round(avg, 2),
                    "max_risk": round(max(scores), 2),
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_risk"],
            reverse=True,
        )

    def prioritize_by_impact(
        self,
    ) -> list[dict[str, Any]]:
        """Prioritize resources by impact + score."""
        resource_data: dict[str, dict[str, Any]] = {}
        for r in self._records:
            key = r.resource_id
            if key not in resource_data:
                resource_data[key] = {
                    "max_score": r.risk_score,
                    "impact": r.impact.value,
                    "provider": (r.cloud_provider),
                }
            else:
                if r.risk_score > resource_data[key]["max_score"]:
                    resource_data[key]["max_score"] = r.risk_score
                    resource_data[key]["impact"] = r.impact.value
        results: list[dict[str, Any]] = []
        for res_id, data in resource_data.items():
            results.append(
                {
                    "resource_id": res_id,
                    "max_score": round(data["max_score"], 2),
                    "impact": data["impact"],
                    "provider": data["provider"],
                }
            )
        return sorted(
            results,
            key=lambda x: x["max_score"],
            reverse=True,
        )

    # -- report / stats --

    def generate_report(self) -> CloudRiskReport:
        by_f: dict[str, int] = {}
        by_m: dict[str, int] = {}
        by_i: dict[str, int] = {}
        for r in self._records:
            by_f[r.risk_factor.value] = by_f.get(r.risk_factor.value, 0) + 1
            by_m[r.exploit_maturity.value] = by_m.get(r.exploit_maturity.value, 0) + 1
            by_i[r.impact.value] = by_i.get(r.impact.value, 0) + 1
        scores = [r.risk_score for r in self._records]
        avg_risk = round(sum(scores) / len(scores), 2) if scores else 0.0
        critical = sum(1 for r in self._records if r.risk_score > self._risk_threshold)
        recs: list[str] = []
        if critical > 0:
            recs.append(f"{critical} resources above risk threshold {self._risk_threshold}")
        weaponized = sum(
            1 for r in self._records if r.exploit_maturity == ExploitMaturity.WEAPONIZED
        )
        if weaponized > 0:
            recs.append(f"{weaponized} weaponized exploits detected")
        if not recs:
            recs.append("Cloud risk posture is healthy")
        return CloudRiskReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_risk_score=avg_risk,
            critical_count=critical,
            by_factor=by_f,
            by_maturity=by_m,
            by_impact=by_i,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "risk_threshold": (self._risk_threshold),
            "unique_resources": len({r.resource_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("cloud_risk_scoring_engine.cleared")
        return {"status": "cleared"}
