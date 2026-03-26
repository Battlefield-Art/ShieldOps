"""AI Supply Chain Integrity — verify AI component provenance."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ComponentType(StrEnum):
    MODEL_WEIGHT = "model_weight"
    RAG_DOC = "rag_doc"
    PROMPT_TEMPLATE = "prompt_template"
    TOOL_DEF = "tool_def"
    TRAINING_DATA = "training_data"


class IntegrityMethod(StrEnum):
    CHECKSUM = "checksum"
    SIGNATURE = "signature"
    PROVENANCE = "provenance"
    BEHAVIORAL = "behavioral"


class TamperIndicator(StrEnum):
    HASH_MISMATCH = "hash_mismatch"
    UNSIGNED = "unsigned"
    UNKNOWN_SOURCE = "unknown_source"
    ANOMALOUS_OUTPUT = "anomalous_output"


# --- Models ---


class IntegrityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    component_name: str = ""
    component_type: ComponentType = ComponentType.MODEL_WEIGHT
    method: IntegrityMethod = IntegrityMethod.CHECKSUM
    tamper_indicator: TamperIndicator | None = None
    expected_hash: str = ""
    actual_hash: str = ""
    source: str = ""
    verified: bool = False
    risk_score: float = 0.0
    created_at: float = Field(default_factory=time.time)


class IntegrityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    component_type: str = ""
    total_checked: int = 0
    tampered_count: int = 0
    unsigned_count: int = 0
    verification_rate: float = 0.0
    avg_risk: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class IntegrityReport(BaseModel):
    total_components: int = 0
    verified_count: int = 0
    tampered_count: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_indicator: dict[str, int] = Field(default_factory=dict)
    avg_risk_score: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AISupplyChainIntegrityEngine:
    """Verify AI component supply chain integrity."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 0.7,
    ) -> None:
        self._max_records = max_records
        self._risk_threshold = risk_threshold
        self._records: list[IntegrityRecord] = []
        logger.info(
            "ai_supply_chain_integrity.initialized",
            max_records=max_records,
            risk_threshold=risk_threshold,
        )

    # -- record / query --

    def add_record(
        self,
        component_name: str,
        component_type: ComponentType = (ComponentType.MODEL_WEIGHT),
        method: IntegrityMethod = (IntegrityMethod.CHECKSUM),
        expected_hash: str = "",
        actual_hash: str = "",
        source: str = "",
        risk_score: float = 0.0,
    ) -> IntegrityRecord:
        tamper: TamperIndicator | None = None
        verified = True
        if expected_hash and actual_hash and expected_hash != actual_hash:
            tamper = TamperIndicator.HASH_MISMATCH
            verified = False
            risk_score = max(risk_score, 0.9)
        if not source:
            tamper = TamperIndicator.UNKNOWN_SOURCE
            verified = False
            risk_score = max(risk_score, 0.6)
        if method == IntegrityMethod.SIGNATURE and not expected_hash:
            tamper = TamperIndicator.UNSIGNED
            verified = False
            risk_score = max(risk_score, 0.5)
        record = IntegrityRecord(
            component_name=component_name,
            component_type=component_type,
            method=method,
            tamper_indicator=tamper,
            expected_hash=expected_hash,
            actual_hash=actual_hash,
            source=source,
            verified=verified,
            risk_score=risk_score,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ai_supply_chain_integrity.record_added",
            record_id=record.id,
            component=component_name,
            verified=verified,
        )
        return record

    def process(self, component_type: str) -> IntegrityAnalysis:
        items = [r for r in self._records if r.component_type.value == component_type]
        if not items:
            return IntegrityAnalysis(component_type=component_type)
        tampered = sum(1 for r in items if r.tamper_indicator is not None)
        unsigned = sum(1 for r in items if r.tamper_indicator == TamperIndicator.UNSIGNED)
        verified = sum(1 for r in items if r.verified)
        ver_rate = round(verified / len(items) * 100, 2)
        avg_risk = round(
            sum(r.risk_score for r in items) / len(items),
            4,
        )
        return IntegrityAnalysis(
            component_type=component_type,
            total_checked=len(items),
            tampered_count=tampered,
            unsigned_count=unsigned,
            verification_rate=ver_rate,
            avg_risk=avg_risk,
        )

    def generate_report(self) -> IntegrityReport:
        by_type: dict[str, int] = {}
        by_indicator: dict[str, int] = {}
        for r in self._records:
            by_type[r.component_type.value] = by_type.get(r.component_type.value, 0) + 1
            if r.tamper_indicator:
                key = r.tamper_indicator.value
                by_indicator[key] = by_indicator.get(key, 0) + 1
        total = len(self._records)
        verified = sum(1 for r in self._records if r.verified)
        tampered = sum(1 for r in self._records if r.tamper_indicator is not None)
        avg_risk = (
            round(
                sum(r.risk_score for r in self._records) / total,
                4,
            )
            if total
            else 0.0
        )
        recs: list[str] = []
        if tampered > 0:
            recs.append(f"{tampered} component(s) show tamper indicators")
        unverified = total - verified
        if unverified > 0:
            recs.append(f"{unverified} component(s) unverified")
        if avg_risk > self._risk_threshold:
            recs.append("High average risk — audit supply chain")
        if not recs:
            recs.append("Supply chain integrity looks healthy")
        return IntegrityReport(
            total_components=total,
            verified_count=verified,
            tampered_count=tampered,
            by_type=by_type,
            by_indicator=by_indicator,
            avg_risk_score=avg_risk,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            key = r.component_type.value
            type_dist[key] = type_dist.get(key, 0) + 1
        return {
            "total_components": len(self._records),
            "max_records": self._max_records,
            "risk_threshold": self._risk_threshold,
            "type_distribution": type_dist,
            "verified": sum(1 for r in self._records if r.verified),
            "tampered": sum(1 for r in self._records if r.tamper_indicator is not None),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("ai_supply_chain_integrity.cleared")
        return {"status": "cleared"}

    # -- domain operations --

    def verify_component(
        self,
        component_name: str,
        component_type: ComponentType,
        method: IntegrityMethod = (IntegrityMethod.CHECKSUM),
        expected_hash: str = "",
        actual_hash: str = "",
        source: str = "",
    ) -> dict[str, Any]:
        """Verify integrity of an AI component."""
        record = self.add_record(
            component_name=component_name,
            component_type=component_type,
            method=method,
            expected_hash=expected_hash,
            actual_hash=actual_hash,
            source=source,
        )
        logger.info(
            "ai_supply_chain_integrity.verified",
            component=component_name,
            verified=record.verified,
        )
        return {
            "record_id": record.id,
            "component": component_name,
            "type": component_type.value,
            "verified": record.verified,
            "tamper_indicator": (
                record.tamper_indicator.value if record.tamper_indicator else None
            ),
            "risk_score": record.risk_score,
        }

    def detect_poisoning(
        self,
        component_name: str,
        behavioral_score: float = 0.0,
        output_anomaly: bool = False,
    ) -> dict[str, Any]:
        """Detect potential poisoning via behavior."""
        is_poisoned = behavioral_score > 0.7 or output_anomaly
        risk = behavioral_score
        if output_anomaly:
            risk = max(risk, 0.8)
        indicator = None
        if is_poisoned:
            indicator = TamperIndicator.ANOMALOUS_OUTPUT
        record = IntegrityRecord(
            component_name=component_name,
            component_type=ComponentType.MODEL_WEIGHT,
            method=IntegrityMethod.BEHAVIORAL,
            tamper_indicator=indicator,
            verified=not is_poisoned,
            risk_score=risk,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ai_supply_chain_integrity.poisoning_check",
            component=component_name,
            is_poisoned=is_poisoned,
        )
        return {
            "record_id": record.id,
            "component": component_name,
            "is_poisoned": is_poisoned,
            "behavioral_score": behavioral_score,
            "output_anomaly": output_anomaly,
            "risk_score": risk,
        }

    def audit_provenance_chain(
        self,
        component_name: str,
    ) -> dict[str, Any]:
        """Audit provenance chain for a component."""
        records = [r for r in self._records if r.component_name == component_name]
        if not records:
            return {
                "component": component_name,
                "found": False,
                "chain_length": 0,
            }
        sources = list({r.source for r in records if r.source})
        methods = list({r.method.value for r in records})
        all_verified = all(r.verified for r in records)
        tamper_events = [r for r in records if r.tamper_indicator is not None]
        max_risk = max(r.risk_score for r in records)
        logger.info(
            "ai_supply_chain_integrity.provenance_audited",
            component=component_name,
            chain_length=len(records),
        )
        return {
            "component": component_name,
            "found": True,
            "chain_length": len(records),
            "sources": sources,
            "methods_used": methods,
            "all_verified": all_verified,
            "tamper_events": len(tamper_events),
            "max_risk_score": max_risk,
        }
