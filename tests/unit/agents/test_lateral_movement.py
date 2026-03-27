"""Tests for shieldops.agents.lateral_movement."""

from __future__ import annotations

from shieldops.agents.lateral_movement.models import (
    DetectorStage,
    LateralMovementState,
    MovementSeverity,
    MovementType,
)


class TestEnums:
    def test_detectorstage_collect_signals(self):
        assert DetectorStage.COLLECT_SIGNALS == "collect_signals"

    def test_detectorstage_analyze_paths(self):
        assert DetectorStage.ANALYZE_PATHS == "analyze_paths"

    def test_detectorstage_detect_pivots(self):
        assert DetectorStage.DETECT_PIVOTS == "detect_pivots"

    def test_detectorstage_assess_blast_radius(self):
        assert DetectorStage.ASSESS_BLAST_RADIUS == "assess_blast_radius"

    def test_movementtype_oauth_token_reuse(self):
        assert MovementType.OAUTH_TOKEN_REUSE == "oauth_token_reuse"  # noqa: S105

    def test_movementtype_service_account_pivot(self):
        assert MovementType.SERVICE_ACCOUNT_PIVOT == "service_account_pivot"

    def test_movementtype_cross_cloud_escalation(self):
        assert MovementType.CROSS_CLOUD_ESCALATION == "cross_cloud_escalation"

    def test_movementtype_federation_abuse(self):
        assert MovementType.FEDERATION_ABUSE == "federation_abuse"

    def test_movementseverity_critical(self):
        assert MovementSeverity.CRITICAL == "critical"

    def test_movementseverity_high(self):
        assert MovementSeverity.HIGH == "high"

    def test_movementseverity_medium(self):
        assert MovementSeverity.MEDIUM == "medium"

    def test_movementseverity_low(self):
        assert MovementSeverity.LOW == "low"


class TestModels:
    def test_state_defaults(self):
        s = LateralMovementState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.lateral_movement.graph import (
            create_lateral_movement_graph,
        )

        sg = create_lateral_movement_graph()
        assert sg.compile() is not None
