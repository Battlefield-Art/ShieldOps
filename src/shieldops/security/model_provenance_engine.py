"""ModelProvenanceEngine — model origins, lineage, supply chain."""

from __future__ import annotations

import time
import uuid
from collections import Counter
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ProvenanceStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    TAMPERED = "tampered"
    UNKNOWN = "unknown"


class ModelSource(StrEnum):
    HUGGINGFACE = "huggingface"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    SELF_HOSTED = "self_hosted"
    CUSTOM = "custom"


class IntegrityLevel(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    COMPROMISED = "compromised"


# --- Models ---


class ProvenanceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_id: str = ""
    model_name: str = ""
    version: str = ""
    source: ModelSource = ModelSource.CUSTOM
    checksum: str = ""
    expected_checksum: str = ""
    status: ProvenanceStatus = ProvenanceStatus.UNKNOWN
    integrity: IntegrityLevel = IntegrityLevel.MEDIUM
    training_data_sources: list[str] = Field(default_factory=list)
    parent_model_id: str = ""
    publisher: str = ""
    license_type: str = ""
    signed_by: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)


class ProvenanceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_id: str = ""
    total_versions: int = 0
    status_history: list[str] = Field(default_factory=list)
    integrity_level: IntegrityLevel = IntegrityLevel.MEDIUM
    lineage_depth: int = 0
    supply_chain_risks: list[str] = Field(default_factory=list)
    checksum_verified: bool = False
    training_data_coverage: int = 0
    recommendations: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)


class ProvenanceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    unique_models: int = 0
    verified_count: int = 0
    tampered_count: int = 0
    source_breakdown: dict[str, int] = Field(default_factory=dict)
    integrity_breakdown: dict[str, int] = Field(default_factory=dict)
    supply_chain_risks: list[dict[str, Any]] = Field(default_factory=list)
    unsigned_models: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ModelProvenanceEngine:
    """Tracks model origins, training data lineage, and supply chain integrity."""

    def __init__(self, max_records: int = 10000) -> None:
        self._records: list[ProvenanceRecord] = []
        self._max = max_records
        logger.info("model_provenance_engine.initialized", max_records=max_records)

    # -- core methods --

    def add_record(self, **kwargs: Any) -> ProvenanceRecord:
        """Register a model provenance record."""
        rec = ProvenanceRecord(**kwargs)
        # Auto-verify checksum if both provided
        if rec.checksum and rec.expected_checksum:
            if rec.checksum == rec.expected_checksum:
                rec.status = ProvenanceStatus.VERIFIED
                rec.integrity = IntegrityLevel.HIGH
            else:
                rec.status = ProvenanceStatus.TAMPERED
                rec.integrity = IntegrityLevel.COMPROMISED
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.debug(
            "model_provenance_engine.record_added",
            model_id=rec.model_id,
            source=rec.source,
            status=rec.status,
        )
        return rec

    def process(self, model_id: str) -> ProvenanceAnalysis:
        """Analyze provenance for a specific model."""
        filtered = [r for r in self._records if r.model_id == model_id]
        if not filtered:
            return ProvenanceAnalysis(model_id=model_id)

        latest = filtered[-1]
        status_history = [r.status.value for r in filtered]

        # Compute lineage depth by following parent chain
        lineage_depth = 0
        current = latest.parent_model_id
        seen: set[str] = set()
        while current and current not in seen:
            seen.add(current)
            parent_recs = [r for r in self._records if r.model_id == current]
            if parent_recs:
                lineage_depth += 1
                current = parent_recs[-1].parent_model_id
            else:
                break

        risks = self.detect_supply_chain_risk(model_id)
        checksum_ok = latest.status == ProvenanceStatus.VERIFIED

        recommendations: list[str] = []
        if not checksum_ok:
            recommendations.append(f"Model {model_id} checksum not verified — validate integrity")
        if not latest.signed_by:
            recommendations.append(f"Model {model_id} is unsigned — require publisher signatures")
        if not latest.training_data_sources:
            recommendations.append(f"Model {model_id} has no training data lineage documented")
        if latest.integrity == IntegrityLevel.COMPROMISED:
            recommendations.append(
                f"Model {model_id} integrity COMPROMISED — quarantine immediately"
            )

        return ProvenanceAnalysis(
            model_id=model_id,
            total_versions=len(filtered),
            status_history=status_history,
            integrity_level=latest.integrity,
            lineage_depth=lineage_depth,
            supply_chain_risks=risks.get("risks", []),
            checksum_verified=checksum_ok,
            training_data_coverage=len(latest.training_data_sources),
            recommendations=recommendations,
        )

    def generate_report(self) -> ProvenanceReport:
        """Generate a comprehensive provenance report."""
        if not self._records:
            return ProvenanceReport()

        source_bk: Counter[str] = Counter()
        integrity_bk: Counter[str] = Counter()
        verified = 0
        tampered = 0
        unsigned: list[str] = []

        for r in self._records:
            source_bk[r.source.value] += 1
            integrity_bk[r.integrity.value] += 1
            if r.status == ProvenanceStatus.VERIFIED:
                verified += 1
            if r.status == ProvenanceStatus.TAMPERED:
                tampered += 1
            if not r.signed_by and r.model_id not in unsigned:
                unsigned.append(r.model_id)

        # Aggregate supply chain risks
        all_risks: list[dict[str, Any]] = []
        seen_models: set[str] = set()
        for r in self._records:
            if r.model_id not in seen_models:
                seen_models.add(r.model_id)
                risk_info = self.detect_supply_chain_risk(r.model_id)
                if risk_info.get("risks"):
                    all_risks.append(
                        {
                            "model_id": r.model_id,
                            "risks": risk_info["risks"],
                            "risk_level": risk_info.get("risk_level", "unknown"),
                        }
                    )

        return ProvenanceReport(
            total_records=len(self._records),
            unique_models=len(seen_models),
            verified_count=verified,
            tampered_count=tampered,
            source_breakdown=dict(source_bk),
            integrity_breakdown=dict(integrity_bk),
            supply_chain_risks=all_risks,
            unsigned_models=unsigned[:50],
        )

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics."""
        return {
            "total_records": len(self._records),
            "unique_models": len({r.model_id for r in self._records}),
            "verified": sum(1 for r in self._records if r.status == ProvenanceStatus.VERIFIED),
            "tampered": sum(1 for r in self._records if r.status == ProvenanceStatus.TAMPERED),
        }

    def clear_data(self) -> None:
        """Clear all stored records."""
        self._records.clear()
        logger.info("model_provenance_engine.cleared")

    # -- domain methods --

    def verify_checksum(self, model_id: str, provided_checksum: str) -> dict[str, Any]:
        """Verify a model's checksum against stored expected value."""
        records = [r for r in self._records if r.model_id == model_id]
        if not records:
            return {"verified": False, "reason": "model_not_found", "model_id": model_id}

        latest = records[-1]
        if not latest.expected_checksum:
            return {"verified": False, "reason": "no_expected_checksum", "model_id": model_id}

        match = provided_checksum == latest.expected_checksum
        if not match:
            latest.status = ProvenanceStatus.TAMPERED
            latest.integrity = IntegrityLevel.COMPROMISED
            logger.warning(
                "model_provenance_engine.checksum_mismatch",
                model_id=model_id,
                expected=latest.expected_checksum[:16] + "...",
                got=provided_checksum[:16] + "...",
            )
        else:
            latest.status = ProvenanceStatus.VERIFIED
            latest.integrity = IntegrityLevel.HIGH

        return {
            "verified": match,
            "model_id": model_id,
            "status": latest.status.value,
            "integrity": latest.integrity.value,
        }

    def trace_lineage(self, model_id: str) -> dict[str, Any]:
        """Trace full lineage chain for a model back to its root."""
        chain: list[dict[str, Any]] = []
        current = model_id
        visited: set[str] = set()

        while current and current not in visited:
            visited.add(current)
            recs = [r for r in self._records if r.model_id == current]
            if not recs:
                chain.append({"model_id": current, "status": "not_tracked"})
                break
            latest = recs[-1]
            chain.append(
                {
                    "model_id": current,
                    "source": latest.source.value,
                    "version": latest.version,
                    "status": latest.status.value,
                    "publisher": latest.publisher,
                    "training_data_sources": latest.training_data_sources,
                }
            )
            current = latest.parent_model_id

        return {
            "model_id": model_id,
            "lineage_depth": len(chain),
            "chain": chain,
            "root_model": chain[-1]["model_id"] if chain else model_id,
        }

    def detect_supply_chain_risk(self, model_id: str) -> dict[str, Any]:
        """Detect supply chain risks for a model based on provenance data."""
        records = [r for r in self._records if r.model_id == model_id]
        if not records:
            return {"model_id": model_id, "risks": [], "risk_level": "unknown"}

        latest = records[-1]
        risks: list[str] = []

        # Check for unsigned models
        if not latest.signed_by:
            risks.append("unsigned_model")
        # Check for unverified checksums
        if latest.status in (ProvenanceStatus.UNVERIFIED, ProvenanceStatus.UNKNOWN):
            risks.append("unverified_checksum")
        # Check for tampered models
        if latest.status == ProvenanceStatus.TAMPERED:
            risks.append("checksum_tampered")
        # Check for missing training data documentation
        if not latest.training_data_sources:
            risks.append("undocumented_training_data")
        # Check for unknown source
        if latest.source == ModelSource.CUSTOM and not latest.publisher:
            risks.append("unknown_publisher")
        # Check for missing license
        if not latest.license_type:
            risks.append("no_license")

        if "checksum_tampered" in risks:
            level = "critical"
        elif len(risks) >= 3:
            level = "high"
        elif len(risks) >= 1:
            level = "medium"
        else:
            level = "low"

        return {
            "model_id": model_id,
            "risks": risks,
            "risk_level": level,
            "total_risk_factors": len(risks),
        }
