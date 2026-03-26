"""Certificate Chain Validator Engine —
validate certificate chains end-to-end,
detect incomplete chains, verify root trust."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ChainStatus(StrEnum):
    VALID = "valid"
    INCOMPLETE = "incomplete"
    EXPIRED_INTERMEDIATE = "expired_intermediate"
    UNTRUSTED_ROOT = "untrusted_root"
    REVOKED_CERT = "revoked_cert"


class ValidationCheck(StrEnum):
    ROOT_TRUST = "root_trust"
    INTERMEDIATE_VALID = "intermediate_valid"
    LEAF_VALID = "leaf_valid"
    KEY_SIZE = "key_size"
    ALGORITHM = "algorithm"


class ChainDepth(StrEnum):
    ROOT_ONLY = "root_only"
    TWO_LEVEL = "two_level"
    THREE_LEVEL = "three_level"
    FOUR_PLUS = "four_plus"
    SELF_SIGNED = "self_signed"


# --- Models ---


class CertificateChainValidatorRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    domain: str = ""
    chain_status: ChainStatus = ChainStatus.VALID
    validation_check: ValidationCheck = ValidationCheck.ROOT_TRUST
    chain_depth: ChainDepth = ChainDepth.THREE_LEVEL
    root_ca: str = ""
    leaf_subject: str = ""
    chain_length: int = 0
    validation_score: float = 0.0
    failed_checks: list[str] = Field(default_factory=list)
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CertificateChainValidatorAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    domain: str = ""
    chain_status: ChainStatus = ChainStatus.VALID
    validation_score: float = 0.0
    failed_check_count: int = 0
    risk_level: str = ""
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CertificateChainValidatorReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_validation_score: float = 0.0
    by_chain_status: dict[str, int] = Field(default_factory=dict)
    by_validation_check: dict[str, int] = Field(default_factory=dict)
    by_chain_depth: dict[str, int] = Field(default_factory=dict)
    invalid_chains: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class CertificateChainValidatorEngine:
    """Validate certificate chains end-to-end,
    detect incomplete chains, verify root trust."""

    def __init__(self, max_records: int = 200000, validation_threshold: float = 95.0) -> None:
        self._max_records = max_records
        self._validation_threshold = validation_threshold
        self._records: list[CertificateChainValidatorRecord] = []
        self._analyses: dict[str, CertificateChainValidatorAnalysis] = {}
        logger.info(
            "certificate_chain_validator_engine.init",
            max_records=max_records,
            validation_threshold=validation_threshold,
        )

    def add_record(
        self,
        domain: str = "",
        chain_status: ChainStatus = ChainStatus.VALID,
        validation_check: ValidationCheck = ValidationCheck.ROOT_TRUST,
        chain_depth: ChainDepth = ChainDepth.THREE_LEVEL,
        root_ca: str = "",
        leaf_subject: str = "",
        chain_length: int = 0,
        validation_score: float = 0.0,
        failed_checks: list[str] | None = None,
        description: str = "",
    ) -> CertificateChainValidatorRecord:
        record = CertificateChainValidatorRecord(
            domain=domain,
            chain_status=chain_status,
            validation_check=validation_check,
            chain_depth=chain_depth,
            root_ca=root_ca,
            leaf_subject=leaf_subject,
            chain_length=chain_length,
            validation_score=validation_score,
            failed_checks=failed_checks or [],
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "certificate_chain_validator.record_added",
            record_id=record.id,
            domain=domain,
        )
        return record

    def process(self, key: str) -> CertificateChainValidatorAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key or r.domain == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        failed_count = len(rec.failed_checks)
        if rec.validation_score >= self._validation_threshold:
            risk = "low"
        elif rec.validation_score >= 70.0:
            risk = "medium"
        else:
            risk = "high"
        analysis = CertificateChainValidatorAnalysis(
            domain=rec.domain,
            chain_status=rec.chain_status,
            validation_score=rec.validation_score,
            failed_check_count=failed_count,
            risk_level=risk,
            description=(
                f"{rec.domain} chain={rec.chain_status.value} "
                f"score={rec.validation_score} risk={risk}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> CertificateChainValidatorReport:
        by_status: dict[str, int] = {}
        by_check: dict[str, int] = {}
        by_depth: dict[str, int] = {}
        scores: list[float] = []
        for r in self._records:
            s = r.chain_status.value
            by_status[s] = by_status.get(s, 0) + 1
            c = r.validation_check.value
            by_check[c] = by_check.get(c, 0) + 1
            d = r.chain_depth.value
            by_depth[d] = by_depth.get(d, 0) + 1
            scores.append(r.validation_score)
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        invalid = list({r.domain for r in self._records if r.chain_status != ChainStatus.VALID})[
            :10
        ]
        recs: list[str] = []
        if invalid:
            recs.append(f"{len(invalid)} domains with invalid certificate chains")
        incomplete = by_status.get("incomplete", 0)
        if incomplete:
            recs.append(f"{incomplete} chains missing intermediate certificates")
        if not recs:
            recs.append("All certificate chains pass validation checks")
        return CertificateChainValidatorReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_validation_score=avg_score,
            by_chain_status=by_status,
            by_validation_check=by_check,
            by_chain_depth=by_depth,
            invalid_chains=invalid,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        status_dist: dict[str, int] = {}
        for r in self._records:
            k = r.chain_status.value
            status_dist[k] = status_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "status_distribution": status_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("certificate_chain_validator_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def find_broken_chains(self) -> list[dict[str, Any]]:
        """Find certificate chains with validation failures."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.chain_status != ChainStatus.VALID:
                results.append(
                    {
                        "domain": r.domain,
                        "chain_status": r.chain_status.value,
                        "chain_depth": r.chain_depth.value,
                        "root_ca": r.root_ca,
                        "failed_checks": r.failed_checks,
                        "validation_score": r.validation_score,
                    }
                )
        results.sort(key=lambda x: x["validation_score"])
        return results

    def analyze_root_trust_coverage(self) -> list[dict[str, Any]]:
        """Analyze root CA trust coverage across domains."""
        ca_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            ca = r.root_ca or "unknown"
            ca_data.setdefault(ca, {"total": 0, "valid": 0, "untrusted": 0})
            ca_data[ca]["total"] += 1
            if r.chain_status == ChainStatus.VALID:
                ca_data[ca]["valid"] += 1
            if r.chain_status == ChainStatus.UNTRUSTED_ROOT:
                ca_data[ca]["untrusted"] += 1
        results: list[dict[str, Any]] = []
        for ca, counts in ca_data.items():
            results.append(
                {
                    "root_ca": ca,
                    "total_chains": counts["total"],
                    "valid": counts["valid"],
                    "untrusted": counts["untrusted"],
                    "trust_pct": round(counts["valid"] / counts["total"] * 100, 2)
                    if counts["total"] > 0
                    else 0.0,
                }
            )
        results.sort(key=lambda x: x["total_chains"], reverse=True)
        return results

    def rank_chains_by_risk(self) -> list[dict[str, Any]]:
        """Rank certificate chains by risk score."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            risk = 100.0 - r.validation_score + len(r.failed_checks) * 10
            results.append(
                {
                    "domain": r.domain,
                    "chain_status": r.chain_status.value,
                    "validation_score": r.validation_score,
                    "failed_checks": len(r.failed_checks),
                    "risk_score": round(risk, 2),
                    "rank": 0,
                }
            )
        results.sort(key=lambda x: x["risk_score"], reverse=True)
        for idx, entry in enumerate(results, 1):
            entry["rank"] = idx
        return results
