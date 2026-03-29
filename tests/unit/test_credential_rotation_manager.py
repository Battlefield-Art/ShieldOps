"""Tests for credential_rotation_manager."""

from __future__ import annotations

from shieldops.agents.credential_rotation_manager.models import (
    CredentialRotationManagerState,
    CredentialType,
    RotationStage,
    RotationStatus,
)


class TestEnums:
    def test_credentialtype(self) -> None:
        assert CredentialType.API_KEY == "api_key"
        assert len(CredentialType) >= 3

    def test_rotationstage(self) -> None:
        assert RotationStage.DISCOVER_CREDENTIALS == "discover_credentials"
        assert len(RotationStage) >= 3

    def test_rotationstatus(self) -> None:
        assert RotationStatus.CURRENT == "current"
        assert len(RotationStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = CredentialRotationManagerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = CredentialRotationManagerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
