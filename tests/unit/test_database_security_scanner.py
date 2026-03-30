"""Unit tests for database_security_scanner agent models."""

from __future__ import annotations

from shieldops.agents.database_security_scanner.models import (
    DatabaseEngine,
    DatabaseSecurityScannerState,
    DSSStage,
    FindingSeverity,
)


class TestEnums:
    def test_dss_stage_values(self) -> None:
        assert DSSStage.DISCOVER_DATABASES == "discover_databases"
        assert DSSStage.CHECK_AUTH == "check_auth"
        assert DSSStage.REPORT == "report"

    def test_database_engine_values(self) -> None:
        assert DatabaseEngine.POSTGRESQL == "postgresql"
        assert DatabaseEngine.MYSQL == "mysql"
        assert DatabaseEngine.REDIS == "redis"

    def test_finding_severity_values(self) -> None:
        assert FindingSeverity.CRITICAL == "critical"
        assert FindingSeverity.HIGH == "high"
        assert FindingSeverity.LOW == "low"


class TestState:
    def test_default_state(self) -> None:
        state = DatabaseSecurityScannerState()
        assert state.request_id == ""
        assert state.stage == DSSStage.DISCOVER_DATABASES
        assert state.error == ""

    def test_state_with_values(self) -> None:
        state = DatabaseSecurityScannerState(
            request_id="req-001",
            tenant_id="t-001",
            stage=DSSStage.CHECK_AUTH,
        )
        assert state.request_id == "req-001"
        assert state.stage == DSSStage.CHECK_AUTH
