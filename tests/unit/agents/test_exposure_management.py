"""Tests for shieldops.agents.exposure_management."""

from __future__ import annotations

from shieldops.agents.exposure_management.models import (
    ExposureManagementState,
)


class TestModels:
    def test_state_defaults(self):
        s = ExposureManagementState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.exposure_management.graph import (
            create_exposure_management_graph,
        )

        sg = create_exposure_management_graph()
        assert sg.compile() is not None
