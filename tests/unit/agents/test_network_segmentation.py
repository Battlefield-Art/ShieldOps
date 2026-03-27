"""Tests for shieldops.agents.network_segmentation."""

from __future__ import annotations

from shieldops.agents.network_segmentation.models import (
    NetworkSegmentationState,
    SegmentationStage,
    ViolationSeverity,
    ZoneType,
)


class TestEnums:
    def test_segmentationstage_discover_zones(self):
        assert SegmentationStage.DISCOVER_ZONES == "discover_zones"

    def test_segmentationstage_map_traffic(self):
        assert SegmentationStage.MAP_TRAFFIC == "map_traffic"

    def test_segmentationstage_detect_violations(self):
        assert SegmentationStage.DETECT_VIOLATIONS == "detect_violations"

    def test_segmentationstage_assess_risk(self):
        assert SegmentationStage.ASSESS_RISK == "assess_risk"

    def test_zonetype_dmz(self):
        assert ZoneType.DMZ == "dmz"

    def test_zonetype_internal(self):
        assert ZoneType.INTERNAL == "internal"

    def test_zonetype_restricted(self):
        assert ZoneType.RESTRICTED == "restricted"

    def test_zonetype_public(self):
        assert ZoneType.PUBLIC == "public"

    def test_violationseverity_critical(self):
        assert ViolationSeverity.CRITICAL == "critical"

    def test_violationseverity_high(self):
        assert ViolationSeverity.HIGH == "high"

    def test_violationseverity_medium(self):
        assert ViolationSeverity.MEDIUM == "medium"

    def test_violationseverity_low(self):
        assert ViolationSeverity.LOW == "low"


class TestModels:
    def test_state_exists(self):
        assert NetworkSegmentationState is not None


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.network_segmentation.graph import (
            create_network_segmentation_graph,
        )

        sg = create_network_segmentation_graph()
        assert sg.compile() is not None
