"""Tests for detection_gap_finder."""

from __future__ import annotations

from shieldops.agents.detection_gap_finder.models import (
    DetectionGapFinderState,
)


class TestModels:
    def test_state_defaults(self):
        s = DetectionGapFinderState(tenant_id="t")
        assert s.error == ""


class TestGraph:
    def test_compiles(self):
        from shieldops.agents.detection_gap_finder.graph import create_detection_gap_finder_graph

        assert create_detection_gap_finder_graph().compile() is not None
