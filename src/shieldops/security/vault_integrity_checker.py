"""Vault Integrity Checker — verify hash chains and detect tampering."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class HashAlgorithm(StrEnum):
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    BLAKE2B = "blake2b"
    BLAKE3 = "blake3"


class ChainStatus(StrEnum):
    VALID = "valid"
    BROKEN = "broken"
    REBUILDING = "rebuilding"
    UNVERIFIED = "unverified"
    CORRUPTED = "corrupted"


class TamperEvidence(StrEnum):
    NONE_DETECTED = "none_detected"
    HASH_MISMATCH = "hash_mismatch"
    CHAIN_GAP = "chain_gap"
    TIMESTAMP_ANOMALY = "timestamp_anomaly"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


# --- Models ---


class VaultIntegrityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vault_id: str = ""
    artifact_id: str = ""
    algorithm: HashAlgorithm = HashAlgorithm.SHA256
    chain_status: ChainStatus = ChainStatus.UNVERIFIED
    tamper_evidence: TamperEvidence = TamperEvidence.NONE_DETECTED
    expected_hash: str = ""
    actual_hash: str = ""
    verified: bool = False
    accessor: str = ""
    created_at: float = Field(default_factory=time.time)


class VaultIntegrityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    record_id: str = ""
    chain_depth: int = 0
    verification_time_ms: float = 0.0
    trust_score: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class VaultIntegrityReport(BaseModel):
    total_checks: int = 0
    valid_chains: int = 0
    broken_chains: int = 0
    tamper_events: int = 0
    by_algorithm: dict[str, int] = Field(default_factory=dict)
    by_chain_status: dict[str, int] = Field(default_factory=dict)
    by_tamper_evidence: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class VaultIntegrityChecker:
    """Verify hash chains and detect vault tampering."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[VaultIntegrityRecord] = []
        logger.info(
            "vault_integrity_checker.initialized",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> VaultIntegrityRecord:
        record = VaultIntegrityRecord(**kwargs)
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "vault_integrity_checker.record_added",
            record_id=record.id,
            vault_id=record.vault_id,
        )
        return record

    def process(self, key: str) -> dict[str, Any]:
        matches = [r for r in self._records if r.id == key]
        if not matches:
            return {"found": False, "key": key}
        rec = matches[0]
        return {
            "found": True,
            "id": rec.id,
            "vault_id": rec.vault_id,
            "chain_status": rec.chain_status.value,
        }

    # -- domain methods --

    def verify_hash_chain(
        self,
        vault_id: str,
        artifact_id: str,
        expected_hash: str,
        actual_hash: str,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    ) -> VaultIntegrityRecord:
        """Verify a hash chain entry."""
        matches = expected_hash == actual_hash
        chain_status = ChainStatus.VALID if matches else ChainStatus.BROKEN
        tamper = TamperEvidence.NONE_DETECTED if matches else TamperEvidence.HASH_MISMATCH
        record = self.add_record(
            vault_id=vault_id,
            artifact_id=artifact_id,
            algorithm=algorithm,
            chain_status=chain_status,
            tamper_evidence=tamper,
            expected_hash=expected_hash,
            actual_hash=actual_hash,
            verified=True,
        )
        logger.info(
            "vault_integrity_checker.hash_verified",
            vault_id=vault_id,
            chain_status=chain_status.value,
        )
        return record

    def detect_tampering(self, vault_id: str) -> list[dict[str, Any]]:
        """Detect tampering evidence for a vault."""
        vault_records = [r for r in self._records if r.vault_id == vault_id]
        tampered: list[dict[str, Any]] = []
        for r in vault_records:
            if r.tamper_evidence != TamperEvidence.NONE_DETECTED:
                tampered.append(
                    {
                        "record_id": r.id,
                        "artifact_id": r.artifact_id,
                        "evidence": r.tamper_evidence.value,
                        "chain_status": r.chain_status.value,
                        "timestamp": r.created_at,
                    }
                )
        return tampered

    def audit_access_log(self, vault_id: str) -> list[dict[str, Any]]:
        """Audit access log for a vault."""
        vault_records = [r for r in self._records if r.vault_id == vault_id]
        log: list[dict[str, Any]] = []
        for r in vault_records:
            log.append(
                {
                    "record_id": r.id,
                    "artifact_id": r.artifact_id,
                    "accessor": r.accessor,
                    "verified": r.verified,
                    "chain_status": r.chain_status.value,
                    "timestamp": r.created_at,
                }
            )
        log.sort(key=lambda x: x["timestamp"], reverse=True)
        return log[:100]

    # -- report / stats --

    def generate_report(self) -> VaultIntegrityReport:
        by_algo: dict[str, int] = {}
        by_chain: dict[str, int] = {}
        by_tamper: dict[str, int] = {}
        for r in self._records:
            by_algo[r.algorithm.value] = by_algo.get(r.algorithm.value, 0) + 1
            by_chain[r.chain_status.value] = by_chain.get(r.chain_status.value, 0) + 1
            by_tamper[r.tamper_evidence.value] = by_tamper.get(r.tamper_evidence.value, 0) + 1
        valid = by_chain.get("valid", 0)
        broken = by_chain.get("broken", 0) + by_chain.get("corrupted", 0)
        tamper_events = sum(
            1 for r in self._records if r.tamper_evidence != TamperEvidence.NONE_DETECTED
        )
        recs: list[str] = []
        if broken > 0:
            recs.append(f"{broken} broken/corrupted chain(s)")
        if tamper_events > 0:
            recs.append(f"{tamper_events} tampering event(s) detected")
        if not recs:
            recs.append("Vault integrity verified")
        return VaultIntegrityReport(
            total_checks=len(self._records),
            valid_chains=valid,
            broken_chains=broken,
            tamper_events=tamper_events,
            by_algorithm=by_algo,
            by_chain_status=by_chain,
            by_tamper_evidence=by_tamper,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "verified": sum(1 for r in self._records if r.verified),
            "unique_vaults": len({r.vault_id for r in self._records if r.vault_id}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("vault_integrity_checker.cleared")
        return {"status": "cleared"}
