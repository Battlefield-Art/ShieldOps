"""Cloud Posture Scorer — posture scoring and gaps."""

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
    IAM = "iam"
    NETWORK = "network"
    STORAGE = "storage"
    COMPUTE = "compute"
    LOGGING = "logging"


class BenchmarkSource(StrEnum):
    CIS = "cis"
    NIST = "nist"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    CUSTOM = "custom"


class ComplianceGap(StrEnum):
    NONE = "none"
    MINOR = "minor"
    MODERATE = "moderate"
    MAJOR = "major"
    CRITICAL = "critical"


# --- Models ---


class CloudPostureRecord(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    account_id: str = ""
    provider: str = ""
    domain: PostureDomain = PostureDomain.IAM
    benchmark: BenchmarkSource = BenchmarkSource.CIS
    gap_level: ComplianceGap = ComplianceGap.NONE
    score: float = 0.0
    finding: str = ""
    created_at: float = Field(default_factory=time.time)


class CloudPostureAnalysis(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    account_id: str = ""
    avg_score: float = 0.0
    gap_count: int = 0
    critical_gaps: int = 0
    analyzed_at: float = Field(default_factory=time.time)


class CloudPostureReport(BaseModel):
    total_checks: int = 0
    avg_score: float = 0.0
    gap_count: int = 0
    critical_count: int = 0
    by_domain: dict[str, float] = Field(
        default_factory=dict,
    )
    by_benchmark: dict[str, int] = Field(
        default_factory=dict,
    )
    recommendations: list[str] = Field(
        default_factory=list,
    )
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class CloudPostureScorer:
    """Score cloud posture and identify gaps."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[CloudPostureRecord] = []
        logger.info(
            "cloud_posture_scorer.initialized",
            max_records=max_records,
        )

    def _evict(self) -> None:
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]

    def add_record(
        self,
        **kwargs: Any,
    ) -> CloudPostureRecord:
        record = CloudPostureRecord(**kwargs)
        self._records.append(record)
        self._evict()
        logger.info(
            "cloud_posture.record_added",
            record_id=record.id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> CloudPostureAnalysis:
        matches = [r for r in self._records if r.account_id == key]
        if not matches:
            return CloudPostureAnalysis(account_id=key)
        avg = round(
            sum(r.score for r in matches) / len(matches),
            4,
        )
        gaps = sum(1 for r in matches if r.gap_level != ComplianceGap.NONE)
        critical = sum(1 for r in matches if r.gap_level == ComplianceGap.CRITICAL)
        return CloudPostureAnalysis(
            account_id=key,
            avg_score=avg,
            gap_count=gaps,
            critical_gaps=critical,
        )

    def generate_report(self) -> CloudPostureReport:
        domain_scores: dict[str, list[float]] = {}
        by_bench: dict[str, int] = {}
        gap_count = 0
        critical = 0
        for r in self._records:
            d = r.domain.value
            domain_scores.setdefault(d, []).append(
                r.score,
            )
            b = r.benchmark.value
            by_bench[b] = by_bench.get(b, 0) + 1
            if r.gap_level != ComplianceGap.NONE:
                gap_count += 1
            if r.gap_level == ComplianceGap.CRITICAL:
                critical += 1
        by_domain: dict[str, float] = {}
        for d, scores in domain_scores.items():
            by_domain[d] = round(
                sum(scores) / len(scores),
                2,
            )
        total = len(self._records)
        avg = (
            round(
                sum(r.score for r in self._records) / total,
                2,
            )
            if total
            else 0.0
        )
        recs: list[str] = []
        if critical > 0:
            recs.append(f"{critical} critical gap(s) found")
        if avg < 70:
            recs.append("Overall posture below 70%")
        if not recs:
            recs.append("Cloud posture is healthy")
        return CloudPostureReport(
            total_checks=total,
            avg_score=avg,
            gap_count=gap_count,
            critical_count=critical,
            by_domain=by_domain,
            by_benchmark=by_bench,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("cloud_posture_scorer.cleared")
        return {"status": "cleared"}

    # -- domain methods --

    def score_posture(
        self,
        account_id: str,
    ) -> dict[str, Any]:
        """Compute posture score for an account."""
        matches = [r for r in self._records if r.account_id == account_id]
        if not matches:
            return {
                "account_id": account_id,
                "found": False,
            }
        avg = round(
            sum(r.score for r in matches) / len(matches),
            2,
        )
        return {
            "account_id": account_id,
            "found": True,
            "score": avg,
            "checks": len(matches),
        }

    def benchmark_against_cis(
        self,
        account_id: str,
    ) -> dict[str, Any]:
        """Benchmark against CIS controls."""
        matches = [
            r
            for r in self._records
            if r.account_id == account_id and r.benchmark == BenchmarkSource.CIS
        ]
        passing = sum(1 for r in matches if r.gap_level == ComplianceGap.NONE)
        total = len(matches)
        return {
            "account_id": account_id,
            "benchmark": "cis",
            "total_checks": total,
            "passing": passing,
            "pass_rate_pct": round(
                passing / total * 100,
                2,
            )
            if total
            else 0.0,
        }

    def identify_gaps(
        self,
        account_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Identify compliance gaps."""
        subset = self._records
        if account_id is not None:
            subset = [r for r in subset if r.account_id == account_id]
        gaps = [r for r in subset if r.gap_level != ComplianceGap.NONE]
        return [
            {
                "record_id": r.id,
                "account_id": r.account_id,
                "domain": r.domain.value,
                "gap_level": r.gap_level.value,
                "finding": r.finding,
            }
            for r in gaps
        ]
