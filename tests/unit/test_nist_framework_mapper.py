"""Tests for nist_framework_mapper."""

from __future__ import annotations

from shieldops.agents.nist_framework_mapper.models import (
    CSFFunction,
    NISTFrameworkMapperState,
    NISTStage,
)


class TestEnums:
    def test_csffunction(self) -> None:
        assert CSFFunction.IDENTIFY == "identify"
        assert len(CSFFunction) >= 3

    def test_niststage(self) -> None:
        assert NISTStage.MAP_FUNCTIONS == "map_functions"
        assert len(NISTStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = NISTFrameworkMapperState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = NISTFrameworkMapperState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
