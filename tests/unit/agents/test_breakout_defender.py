"""Tests for shieldops.agents.breakout_defender — eCrime breakout detection and containment."""

from __future__ import annotations

import pytest

from shieldops.agents.breakout_defender.models import (
    BreakoutDefenderState,
    BreakoutPhase,
    BreakoutReport,
    BreakoutSignal,
    ContainmentAction,
    ContainmentOrder,
    DefenseReasoningStep,
    DefenseStage,
    LateralMovementPath,
)


def _state(**kw) -> BreakoutDefenderState:
    return BreakoutDefenderState(**kw)


class TestEnums:
    def test_defense_stage_values(self):
        assert DefenseStage.DETECT_INITIAL_ACCESS == "detect_initial_access"
        assert DefenseStage.ANALYZE_LATERAL_MOVEMENT == "analyze_lateral_movement"
        assert DefenseStage.ASSESS_BREAKOUT_RISK == "assess_breakout_risk"
        assert DefenseStage.EXECUTE_CONTAINMENT == "execute_containment"
        assert DefenseStage.VERIFY_CONTAINMENT == "verify_containment"
        assert DefenseStage.REPORT == "report"

    def test_breakout_phase_values(self):
        assert BreakoutPhase.INITIAL_ACCESS == "initial_access"
        assert BreakoutPhase.PRIVILEGE_ESCALATION == "privilege_escalation"
        assert BreakoutPhase.LATERAL_MOVEMENT == "lateral_movement"
        assert BreakoutPhase.DATA_STAGING == "data_staging"
        assert BreakoutPhase.EXFILTRATION == "exfiltration"

    def test_containment_action_values(self):
        assert ContainmentAction.ISOLATE_HOST == "isolate_host"
        assert ContainmentAction.REVOKE_CREDENTIALS == "revoke_credentials"
        assert ContainmentAction.BLOCK_NETWORK == "block_network"
        assert ContainmentAction.DISABLE_ACCOUNT == "disable_account"
        assert ContainmentAction.QUARANTINE_PROCESS == "quarantine_process"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.tenant_id == ""
        assert s.defense_id == ""
        assert s.incoming_signals == []
        assert s.signals == []
        assert s.initial_access_detected is False
        assert s.detected_phase == ""
        assert s.paths == []
        assert s.cross_cloud_detected is False
        assert s.breakout_risk_score == 0.0
        assert s.estimated_breakout_time_minutes == 0.0
        assert s.auto_contain is False
        assert s.containment_orders == []
        assert s.containment_executed is False
        assert s.containment_verified is False
        assert s.residual_risk == 0.0
        assert s.time_to_contain_seconds == 0.0
        assert s.breakout_prevented is False
        assert s.report is None
        assert s.session_start is None
        assert s.current_step == "init"
        assert s.error == ""

    def test_breakout_signal_defaults(self):
        sig = BreakoutSignal()
        assert sig.signal_id == ""
        assert sig.phase == "initial_access"
        assert sig.severity == "medium"
        assert sig.confidence == 0.0
        assert sig.timestamp == 0.0
        assert sig.raw_event == {}

    def test_lateral_movement_path_defaults(self):
        p = LateralMovementPath()
        assert p.path_id == ""
        assert p.credentials_used == []
        assert p.hops == []
        assert p.risk_score == 0.0
        assert p.is_cross_cloud is False

    def test_containment_order_defaults(self):
        o = ContainmentOrder()
        assert o.order_id == ""
        assert o.action == "isolate_host"
        assert o.requires_approval is False
        assert o.executed is False

    def test_breakout_report_defaults(self):
        r = BreakoutReport()
        assert r.report_id == ""
        assert r.breakout_prevented is False
        assert r.time_to_detect_seconds == 0.0
        assert r.mitre_techniques == []

    def test_defense_reasoning_step(self):
        step = DefenseReasoningStep(
            step_number=1, action="detect", input_summary="in", output_summary="out"
        )
        assert step.step_number == 1
        assert step.duration_ms == 0
        assert step.tool_used is None


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.breakout_defender.tools import BreakoutDefenderToolkit

        return BreakoutDefenderToolkit()

    @pytest.mark.asyncio
    async def test_collect_initial_access_signals(self, toolkit):
        raw_signals = [
            {"source": "crowdstrike", "type": "process_exec", "severity": "high"},
            {"source": "defender", "type": "lateral_move", "severity": "critical"},
        ]
        result = await toolkit.collect_initial_access_signals(raw_signals)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_analyze_lateral_paths(self, toolkit):
        signals = [
            {"hostname": "host-1", "ip_address": "10.0.0.1", "user_identity": "admin"},
            {"hostname": "host-2", "ip_address": "10.0.0.2", "user_identity": "admin"},
        ]
        result = await toolkit.analyze_lateral_paths(signals)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_execute_containment_simulated(self, toolkit):
        orders = [{"target": "host-1", "action": "isolate_host", "target_type": "endpoint"}]
        result = await toolkit.execute_containment(orders)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_verify_containment_status(self, toolkit):
        orders = [{"target": "host-1", "action": "isolate_host"}]
        result = await toolkit.verify_containment_status(orders)
        assert isinstance(result, dict)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.breakout_defender.graph import create_breakout_defender_graph

        sg = create_breakout_defender_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.breakout_defender.graph import create_breakout_defender_graph

        sg = create_breakout_defender_graph()
        compiled = sg.compile()
        assert compiled is not None
