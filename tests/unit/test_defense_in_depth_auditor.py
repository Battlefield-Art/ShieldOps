"""Tests for defense_in_depth_auditor."""

from __future__ import annotations

from shieldops.agents.defense_in_depth_auditor.models import (
    AuditStage,
    ControlEffectiveness,
    DefenseInDepthAuditorState,
    DefenseLayer,
)


class TestEnums:
    def test_auditstage(self) -> None:
        assert AuditStage.MAP_LAYERS == "map_layers"
        assert len(AuditStage) >= 3

    def test_controleffectiveness(self) -> None:
        assert ControlEffectiveness.STRONG == "strong"
        assert len(ControlEffectiveness) >= 3

    def test_defenselayer(self) -> None:
        assert DefenseLayer.PERIMETER == "perimeter"
        assert len(DefenseLayer) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = DefenseInDepthAuditorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = DefenseInDepthAuditorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
