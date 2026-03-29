"""Tests for security_control_mapper."""

from __future__ import annotations

from shieldops.agents.security_control_mapper.models import (
    Framework,
    MappingStage,
    MappingStatus,
    SecurityControlMapperState,
)


class TestEnums:
    def test_framework(self) -> None:
        assert Framework.NIST_CSF == "nist_csf"
        assert len(Framework) >= 3

    def test_mappingstage(self) -> None:
        assert MappingStage.COLLECT_CONTROLS == "collect_controls"
        assert len(MappingStage) >= 3

    def test_mappingstatus(self) -> None:
        assert MappingStatus.MAPPED == "mapped"
        assert len(MappingStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SecurityControlMapperState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SecurityControlMapperState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
