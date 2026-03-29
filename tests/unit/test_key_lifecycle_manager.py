"""Tests for key_lifecycle_manager."""

from __future__ import annotations

from shieldops.agents.key_lifecycle_manager.models import (
    KeyLifecycleManagerState,
    KeyStage,
    KeyStatus,
    KeyType,
)


class TestEnums:
    def test_key_stage(self) -> None:
        assert KeyStage.DISCOVER_KEYS == "discover_keys"
        assert len(KeyStage) >= 3

    def test_key_type(self) -> None:
        assert KeyType.SYMMETRIC == "symmetric"
        assert len(KeyType) >= 3

    def test_key_status(self) -> None:
        assert KeyStatus.ACTIVE == "active"
        assert len(KeyStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = KeyLifecycleManagerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = KeyLifecycleManagerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
