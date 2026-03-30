"""Tests for data_retention_enforcer."""

from __future__ import annotations

from shieldops.agents.data_retention_enforcer.models import (
    DataRetentionEnforcerState,
    DREStage,
    ExpiryStatus,
    RetentionPolicy,
)


class TestEnums:
    def test_stage(self) -> None:
        assert DREStage.DISCOVER_DATA == "discover_data"
        assert len(DREStage) >= 3

    def test_retention_policy(self) -> None:
        assert RetentionPolicy.REGULATORY == "regulatory"
        assert len(RetentionPolicy) >= 3

    def test_expiry_status(self) -> None:
        assert ExpiryStatus.EXPIRED == "expired"
        assert len(ExpiryStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = DataRetentionEnforcerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = DataRetentionEnforcerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
