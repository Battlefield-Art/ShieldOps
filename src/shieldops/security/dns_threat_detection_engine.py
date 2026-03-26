"""DNS Threat Detection Engine —
detect DNS-based threats including tunneling, DGA,
typosquatting, rebinding, and cache poisoning."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DNSThreatType(StrEnum):
    TUNNELING = "tunneling"
    DGA = "dga"
    TYPOSQUATTING = "typosquatting"
    DNS_REBINDING = "dns_rebinding"
    CACHE_POISONING = "cache_poisoning"


class DetectionMethod(StrEnum):
    ENTROPY = "entropy"
    FREQUENCY = "frequency"
    ML_MODEL = "ml_model"
    BLOCKLIST = "blocklist"
    HEURISTIC = "heuristic"


class ThreatConfidence(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"


# --- Models ---


class DNSThreatDetectionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_domain: str = ""
    source_ip: str = ""
    threat_type: DNSThreatType = DNSThreatType.TUNNELING
    detection_method: DetectionMethod = DetectionMethod.ENTROPY
    threat_confidence: ThreatConfidence = ThreatConfidence.UNVERIFIED
    entropy_score: float = 0.0
    query_frequency: int = 0
    payload_size_bytes: int = 0
    is_blocked: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DNSThreatDetectionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_domain: str = ""
    threat_type: DNSThreatType = DNSThreatType.TUNNELING
    threat_confidence: ThreatConfidence = ThreatConfidence.UNVERIFIED
    risk_score: float = 0.0
    indicators: list[str] = Field(default_factory=list)
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DNSThreatDetectionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_risk_score: float = 0.0
    by_threat_type: dict[str, int] = Field(default_factory=dict)
    by_detection_method: dict[str, int] = Field(default_factory=dict)
    by_threat_confidence: dict[str, int] = Field(default_factory=dict)
    top_threat_domains: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class DNSThreatDetectionEngine:
    """Detect DNS-based threats including tunneling, DGA,
    typosquatting, rebinding, and cache poisoning."""

    def __init__(self, max_records: int = 200000, confidence_threshold: float = 75.0) -> None:
        self._max_records = max_records
        self._confidence_threshold = confidence_threshold
        self._records: list[DNSThreatDetectionRecord] = []
        self._analyses: dict[str, DNSThreatDetectionAnalysis] = {}
        logger.info(
            "dns_threat_detection_engine.init",
            max_records=max_records,
            confidence_threshold=confidence_threshold,
        )

    def add_record(
        self,
        query_domain: str = "",
        source_ip: str = "",
        threat_type: DNSThreatType = DNSThreatType.TUNNELING,
        detection_method: DetectionMethod = DetectionMethod.ENTROPY,
        threat_confidence: ThreatConfidence = ThreatConfidence.UNVERIFIED,
        entropy_score: float = 0.0,
        query_frequency: int = 0,
        payload_size_bytes: int = 0,
        is_blocked: bool = False,
        description: str = "",
    ) -> DNSThreatDetectionRecord:
        record = DNSThreatDetectionRecord(
            query_domain=query_domain,
            source_ip=source_ip,
            threat_type=threat_type,
            detection_method=detection_method,
            threat_confidence=threat_confidence,
            entropy_score=entropy_score,
            query_frequency=query_frequency,
            payload_size_bytes=payload_size_bytes,
            is_blocked=is_blocked,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "dns_threat_detection.record_added",
            record_id=record.id,
            query_domain=query_domain,
        )
        return record

    def process(self, key: str) -> DNSThreatDetectionAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key or r.query_domain == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        indicators: list[str] = []
        risk = 0.0
        if rec.entropy_score > 3.5:
            indicators.append(f"high entropy ({rec.entropy_score:.2f})")
            risk += 30.0
        if rec.query_frequency > 100:
            indicators.append(f"high frequency ({rec.query_frequency} qps)")
            risk += 25.0
        if rec.payload_size_bytes > 512:
            indicators.append(f"large payload ({rec.payload_size_bytes}B)")
            risk += 20.0
        if rec.threat_confidence in (ThreatConfidence.CONFIRMED, ThreatConfidence.HIGH):
            risk += 25.0
        risk = min(round(risk, 2), 100.0)
        analysis = DNSThreatDetectionAnalysis(
            query_domain=rec.query_domain,
            threat_type=rec.threat_type,
            threat_confidence=rec.threat_confidence,
            risk_score=risk,
            indicators=indicators,
            description=(
                f"{rec.query_domain} threat={rec.threat_type.value} "
                f"confidence={rec.threat_confidence.value} risk={risk}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> DNSThreatDetectionReport:
        by_type: dict[str, int] = {}
        by_method: dict[str, int] = {}
        by_conf: dict[str, int] = {}
        for r in self._records:
            tt = r.threat_type.value
            by_type[tt] = by_type.get(tt, 0) + 1
            dm = r.detection_method.value
            by_method[dm] = by_method.get(dm, 0) + 1
            tc = r.threat_confidence.value
            by_conf[tc] = by_conf.get(tc, 0) + 1
        risks = [a.risk_score for a in self._analyses.values()]
        avg_risk = round(sum(risks) / len(risks), 2) if risks else 0.0
        top_domains = list(
            {
                r.query_domain
                for r in self._records
                if r.threat_confidence in (ThreatConfidence.CONFIRMED, ThreatConfidence.HIGH)
            }
        )[:10]
        recs: list[str] = []
        if top_domains:
            recs.append(f"{len(top_domains)} high-confidence threat domains detected")
        tunneling = by_type.get("tunneling", 0)
        if tunneling:
            recs.append(f"{tunneling} DNS tunneling attempts — review egress controls")
        if not recs:
            recs.append("No significant DNS threats detected")
        return DNSThreatDetectionReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_risk_score=avg_risk,
            by_threat_type=by_type,
            by_detection_method=by_method,
            by_threat_confidence=by_conf,
            top_threat_domains=top_domains,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            k = r.threat_type.value
            type_dist[k] = type_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threat_type_distribution": type_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("dns_threat_detection_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def detect_tunneling_candidates(self) -> list[dict[str, Any]]:
        """Detect potential DNS tunneling based on entropy and payload size."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.entropy_score > 3.5 or r.payload_size_bytes > 512:
                results.append(
                    {
                        "query_domain": r.query_domain,
                        "source_ip": r.source_ip,
                        "entropy_score": r.entropy_score,
                        "payload_size_bytes": r.payload_size_bytes,
                        "query_frequency": r.query_frequency,
                        "threat_confidence": r.threat_confidence.value,
                    }
                )
        results.sort(key=lambda x: x["entropy_score"], reverse=True)
        return results

    def analyze_dga_patterns(self) -> list[dict[str, Any]]:
        """Analyze Domain Generation Algorithm patterns in queries."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.threat_type == DNSThreatType.DGA:
                results.append(
                    {
                        "query_domain": r.query_domain,
                        "detection_method": r.detection_method.value,
                        "entropy_score": r.entropy_score,
                        "threat_confidence": r.threat_confidence.value,
                        "is_blocked": r.is_blocked,
                    }
                )
        results.sort(key=lambda x: x["entropy_score"], reverse=True)
        return results

    def summarize_threats_by_source(self) -> list[dict[str, Any]]:
        """Summarize threat detections grouped by source IP."""
        src_data: dict[str, dict[str, Any]] = {}
        for r in self._records:
            ip = r.source_ip or "unknown"
            src_data.setdefault(ip, {"total": 0, "types": {}, "blocked": 0})
            src_data[ip]["total"] += 1
            tt = r.threat_type.value
            src_data[ip]["types"][tt] = src_data[ip]["types"].get(tt, 0) + 1
            if r.is_blocked:
                src_data[ip]["blocked"] += 1
        results: list[dict[str, Any]] = []
        for ip, data in src_data.items():
            results.append(
                {
                    "source_ip": ip,
                    "total_threats": data["total"],
                    "threat_types": data["types"],
                    "blocked_count": data["blocked"],
                    "block_rate_pct": round(data["blocked"] / data["total"] * 100, 2)
                    if data["total"] > 0
                    else 0.0,
                }
            )
        results.sort(key=lambda x: x["total_threats"], reverse=True)
        return results
