"""Tests for crypto_agility_manager."""

from __future__ import annotations

from shieldops.agents.crypto_agility_manager.models import (
    CryptoAgilityManagerState,
    MigrationPriority,
    MigrationStage,
    PQCAlgorithm,
)


class TestEnums:
    def test_migration_stage(self) -> None:
        assert MigrationStage.DISCOVER_ALGORITHMS == "discover_algorithms"
        assert len(MigrationStage) >= 3

    def test_pqc_algorithm(self) -> None:
        assert PQCAlgorithm.CRYSTALS_KYBER == "crystals_kyber"
        assert len(PQCAlgorithm) >= 3

    def test_migration_priority(self) -> None:
        assert MigrationPriority.CRITICAL == "critical"
        assert len(MigrationPriority) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = CryptoAgilityManagerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = CryptoAgilityManagerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
