"""Tests for apt_emulator."""

from __future__ import annotations

from shieldops.agents.apt_emulator.models import APTEmulatorState


def test_graph_compiles():
    from shieldops.agents.apt_emulator.graph import create_apt_emulator_graph

    assert create_apt_emulator_graph().compile() is not None


def test_state_defaults():
    s = APTEmulatorState(tenant_id="t")
    assert s.error == ""
