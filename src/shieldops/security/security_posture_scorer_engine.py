"""SecurityPostureScorerEngine — Unified security posture scoring across domains."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PostureDomain(StrEnum):
    IDENTITY = "identity"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    CLOUD = "cloud"
    DATA = "data"


class PostureMaturity(StrEnum):
    INITIAL = "initial"
    DEVELOPING = "developing"
    DEFINED = "defined"
    MANAGED = "managed"
    OPTIMIZED = "optimized"


class ComplianceAlignment(StrEnum):
    ALIGNED = "aligned"
    PARTIAL = "partial"
    GAP = "gap"


# --- Models ---


class SecurityPostureScorerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    posture_domain: PostureDomain = PostureDomain.IDENTITY
    posture_maturity: PostureMaturity = PostureMaturity.INITIAL
    compliance_alignment: ComplianceAlignment = ComplianceAlignment.ALIGNED
    score: float = 0.0
    control_count: int = 0
    framework: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SecurityPostureScorerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    posture_domain: PostureDomain = PostureDomain.IDENTITY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SecurityPostureScorerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_posture_domain: dict[str, int] = Field(default_factory=dict)
    by_posture_maturity: dict[str, int] = Field(default_factory=dict)
    by_compliance_alignment: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class SecurityPostureScorerEngine:
    """Unified security posture scoring across domains."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[SecurityPostureScorerRecord] = []
        self._analyses: list[SecurityPostureScorerAnalysis] = []
        logger.info(
            "security_posture_scorer_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        posture_domain: PostureDomain = PostureDomain.IDENTITY,
        posture_maturity: PostureMaturity = PostureMaturity.INITIAL,
        compliance_alignment: ComplianceAlignment = ComplianceAlignment.ALIGNED,
        score: float = 0.0,
        control_count: int = 0,
        framework: str = "",
        service: str = "",
        team: str = "",
    ) -> SecurityPostureScorerRecord:
        record = SecurityPostureScorerRecord(
            name=name,
            posture_domain=posture_domain,
            posture_maturity=posture_maturity,
            compliance_alignment=compliance_alignment,
            score=score,
            control_count=control_count,
            framework=framework,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "security_posture_scorer_engine.record_added",
            record_id=record.id,
            name=name,
            posture_domain=posture_domain.value,
            posture_maturity=posture_maturity.value,
        )
        return record

    def get_record(self, record_id: str) -> SecurityPostureScorerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        posture_domain: PostureDomain | None = None,
        posture_maturity: PostureMaturity | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[SecurityPostureScorerRecord]:
        results = list(self._records)
        if posture_domain is not None:
            results = [r for r in results if r.posture_domain == posture_domain]
        if posture_maturity is not None:
            results = [r for r in results if r.posture_maturity == posture_maturity]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        posture_domain: PostureDomain = PostureDomain.IDENTITY,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> SecurityPostureScorerAnalysis:
        analysis = SecurityPostureScorerAnalysis(
            name=name,
            posture_domain=posture_domain,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "security_posture_scorer_engine.analysis_added",
            name=name,
            posture_domain=posture_domain.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_domain_scores(self) -> list[dict[str, Any]]:
        """Compute aggregate security scores per posture domain."""
        domain_data: dict[str, list[float]] = {}
        domain_maturity: dict[str, dict[str, int]] = {}
        for r in self._records:
            d = r.posture_domain.value
            domain_data.setdefault(d, []).append(r.score)
            domain_maturity.setdefault(d, {})
            m = r.posture_maturity.value
            domain_maturity[d][m] = domain_maturity[d].get(m, 0) + 1
        results: list[dict[str, Any]] = []
        for domain, scores in domain_data.items():
            avg = round(sum(scores) / len(scores), 2)
            results.append(
                {
                    "domain": domain,
                    "avg_score": avg,
                    "record_count": len(scores),
                    "min_score": round(min(scores), 2),
                    "max_score": round(max(scores), 2),
                    "maturity_distribution": domain_maturity.get(domain, {}),
                    "below_threshold": sum(1 for s in scores if s < self._threshold),
                }
            )
        return sorted(results, key=lambda x: x["avg_score"])

    def detect_posture_regression(self) -> list[dict[str, Any]]:
        """Detect services with compliance gaps or low maturity."""
        svc_data: dict[str, list[SecurityPostureScorerRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        regressions: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            gaps = [r for r in records if r.compliance_alignment == ComplianceAlignment.GAP]
            low_maturity = [
                r
                for r in records
                if r.posture_maturity in (PostureMaturity.INITIAL, PostureMaturity.DEVELOPING)
            ]
            if gaps or low_maturity:
                regressions.append(
                    {
                        "service": svc,
                        "gap_count": len(gaps),
                        "low_maturity_count": len(low_maturity),
                        "affected_domains": sorted(
                            {r.posture_domain.value for r in gaps + low_maturity}
                        ),
                        "severity": "critical" if len(gaps) > 2 else "warning",
                    }
                )
        return sorted(regressions, key=lambda x: x["gap_count"], reverse=True)

    def benchmark_against_framework(self) -> list[dict[str, Any]]:
        """Benchmark posture scores against compliance frameworks."""
        fw_data: dict[str, list[SecurityPostureScorerRecord]] = {}
        for r in self._records:
            if r.framework:
                fw_data.setdefault(r.framework, []).append(r)
        results: list[dict[str, Any]] = []
        for fw, records in fw_data.items():
            scores = [r.score for r in records]
            aligned = sum(
                1 for r in records if r.compliance_alignment == ComplianceAlignment.ALIGNED
            )
            total = len(records)
            results.append(
                {
                    "framework": fw,
                    "total_controls": total,
                    "aligned": aligned,
                    "alignment_pct": round(aligned / total * 100, 1) if total else 0.0,
                    "avg_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
                    "gap_count": sum(
                        1 for r in records if r.compliance_alignment == ComplianceAlignment.GAP
                    ),
                }
            )
        return sorted(results, key=lambda x: x["alignment_pct"])

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.posture_domain.value
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
                        "posture_domain": r.posture_domain.value,
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

    def generate_report(self) -> SecurityPostureScorerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.posture_domain.value] = by_e1.get(r.posture_domain.value, 0) + 1
            by_e2[r.posture_maturity.value] = by_e2.get(r.posture_maturity.value, 0) + 1
            by_e3[r.compliance_alignment.value] = by_e3.get(r.compliance_alignment.value, 0) + 1
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
            recs.append("Security Posture Scorer Engine is healthy")
        return SecurityPostureScorerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_posture_domain=by_e1,
            by_posture_maturity=by_e2,
            by_compliance_alignment=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("security_posture_scorer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.posture_domain.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "posture_domain_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
