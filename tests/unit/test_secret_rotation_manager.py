"""Unit tests for secret_rotation_manager agent models."""

from __future__ import annotations

from shieldops.agents.secret_rotation_manager.models import (
    RotationStatus,
    SecretRotationManagerState,
    SecretType,
    SRMStage,
)


class TestEnums:
    def test_srm_stage_values(self) -> None:
        assert SRMStage.INVENTORY_SECRETS == "inventory_secrets"
        assert SRMStage.EXECUTE_ROTATION == "execute_rotation"
        assert SRMStage.REPORT == "report"

    def test_secret_type_values(self) -> None:
        assert SecretType.API_KEY == "api_key"
        assert SecretType.DATABASE_CREDENTIAL == "database_credential"
        assert SecretType.TLS_CERTIFICATE == "tls_certificate"

    def test_rotation_status_values(self) -> None:
        assert RotationStatus.PENDING == "pending"
        assert RotationStatus.COMPLETED == "completed"
        assert RotationStatus.ROLLED_BACK == "rolled_back"


class TestState:
    def test_default_state(self) -> None:
        state = SecretRotationManagerState()
        assert state.request_id == ""
        assert state.stage == SRMStage.INVENTORY_SECRETS
        assert state.error == ""

    def test_state_with_values(self) -> None:
        state = SecretRotationManagerState(
            request_id="req-001",
            tenant_id="t-001",
            stage=SRMStage.EXECUTE_ROTATION,
        )
        assert state.request_id == "req-001"
        assert state.stage == SRMStage.EXECUTE_ROTATION
