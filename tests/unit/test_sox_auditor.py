"""Tests for sox_auditor."""

from __future__ import annotations

from shieldops.agents.sox_auditor.models import (
    ControlCategory,
    SOXAuditorState,
    SOXStage,
)


class TestEnums:
    def test_controlcategory(self) -> None:
        assert ControlCategory.ACCESS_CONTROL == "access_control"
        assert len(ControlCategory) >= 3

    def test_soxstage(self) -> None:
        assert SOXStage.IDENTIFY_CONTROLS == "identify_controls"
        assert len(SOXStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SOXAuditorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SOXAuditorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
