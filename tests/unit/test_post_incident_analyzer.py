"""Unit tests for post_incident_analyzer agent."""

from __future__ import annotations

import time

import pytest

from shieldops.agents.post_incident_analyzer.models import (
    ActionItem,
    ImpactLevel,
    PostIncidentAnalyzerState,
    PostIncidentStage,
    RootCauseCategory,
)
from shieldops.agents.post_incident_analyzer.tools import (
    PostIncidentAnalyzerToolkit,
)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class TestEnums:
    def test_post_incident_stage_values(self):
        assert PostIncidentStage.GATHER_TIMELINE == "gather_timeline"
        assert PostIncidentStage.REPORT == "report"

    def test_root_cause_category_values(self):
        assert RootCauseCategory.HUMAN_ERROR == "human_error"
        assert RootCauseCategory.PROCESS_GAP == "process_gap"

    def test_impact_level_values(self):
        assert ImpactLevel.CRITICAL == "critical"
        assert ImpactLevel.NEGLIGIBLE == "negligible"


class TestState:
    def test_defaults(self):
        state = PostIncidentAnalyzerState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.error == ""
        assert state.stage == PostIncidentStage.GATHER_TIMELINE
        assert state.incident_id == ""
        assert state.root_cause == RootCauseCategory.SOFTWARE_BUG
        assert state.impact == ImpactLevel.MEDIUM
        assert state.action_items == []
        assert state.timeline_events == []
        assert state.reasoning_chain == []
        assert state.session_start == 0.0

    def test_with_values(self):
        state = PostIncidentAnalyzerState(
            request_id="req-1",
            tenant_id="t-1",
            incident_id="inc-42",
            root_cause=RootCauseCategory.EXTERNAL_ATTACK,
            impact=ImpactLevel.CRITICAL,
        )
        assert state.request_id == "req-1"
        assert state.root_cause == RootCauseCategory.EXTERNAL_ATTACK
        assert state.impact == ImpactLevel.CRITICAL


class TestModels:
    def test_action_item_defaults(self):
        ai = ActionItem()
        assert ai.title == ""
        assert ai.owner == ""
        assert ai.priority == "medium"
        assert ai.completed is False


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        return PostIncidentAnalyzerToolkit()

    @pytest.mark.asyncio
    async def test_gather_timeline_fallback(self, toolkit):
        events = await toolkit.gather_timeline("inc-1")
        assert len(events) == 5  # fallback baseline events
        assert events[0]["type"] == "alert"
        # Should be sorted by timestamp
        timestamps = [e["timestamp"] for e in events]
        assert timestamps == sorted(timestamps)

    @pytest.mark.asyncio
    async def test_analyze_root_cause_software_bug(self, toolkit):
        events = [
            {"description": "Application crash due to null pointer exception"},
            {"description": "Memory leak detected in production"},
        ]
        category, reasoning = await toolkit.analyze_root_cause(events)
        assert category == RootCauseCategory.SOFTWARE_BUG
        assert "software_bug" in reasoning

    @pytest.mark.asyncio
    async def test_analyze_root_cause_human_error(self, toolkit):
        events = [
            {"description": "Manual change by admin caused outage"},
            {"description": "Typo in configuration file"},
        ]
        category, reasoning = await toolkit.analyze_root_cause(events)
        assert category == RootCauseCategory.HUMAN_ERROR

    @pytest.mark.asyncio
    async def test_analyze_root_cause_external_attack(self, toolkit):
        events = [
            {"description": "DDoS attack from multiple IPs"},
            {"description": "Brute force attempt on admin panel"},
        ]
        category, reasoning = await toolkit.analyze_root_cause(events)
        assert category == RootCauseCategory.EXTERNAL_ATTACK

    @pytest.mark.asyncio
    async def test_analyze_root_cause_no_match(self, toolkit):
        events = [{"description": "something unknown happened"}]
        category, reasoning = await toolkit.analyze_root_cause(events)
        # Falls back to best match or software_bug if none
        assert isinstance(category, RootCauseCategory)

    @pytest.mark.asyncio
    async def test_assess_impact_default(self, toolkit):
        impact = await toolkit.assess_impact(
            "inc-1",
            RootCauseCategory.SOFTWARE_BUG,
        )
        # No incident_db, so affected_services=0, duration=0 -> NEGLIGIBLE
        assert impact == ImpactLevel.NEGLIGIBLE

    @pytest.mark.asyncio
    async def test_assess_impact_external_attack_bias(self, toolkit):
        impact = await toolkit.assess_impact(
            "inc-1",
            RootCauseCategory.EXTERNAL_ATTACK,
        )
        # External attack biases affected_services to >= 3
        assert impact in (ImpactLevel.HIGH, ImpactLevel.MEDIUM, ImpactLevel.LOW)

    @pytest.mark.asyncio
    async def test_extract_lessons(self, toolkit):
        now = time.time()
        timeline = [
            {"timestamp": now - 3600, "type": "alert", "description": "Alert fired"},
            {"timestamp": now - 2400, "type": "action", "description": "Ack'd"},
        ]
        lessons = await toolkit.extract_lessons(
            timeline,
            RootCauseCategory.SOFTWARE_BUG,
        )
        assert len(lessons) >= 2  # detection lesson + cause lesson + observability
        areas = [lesson["area"] for lesson in lessons]
        assert "detection" in areas
        assert "engineering" in areas  # SOFTWARE_BUG -> engineering lesson

    @pytest.mark.asyncio
    async def test_extract_lessons_fast_response(self, toolkit):
        now = time.time()
        timeline = [
            {"timestamp": now - 600, "type": "alert", "description": "Alert"},
            {"timestamp": now - 300, "type": "action", "description": "Responded"},
        ]
        lessons = await toolkit.extract_lessons(
            timeline,
            RootCauseCategory.CONFIGURATION,
        )
        detection_lesson = next((les for les in lessons if les["area"] == "detection"), None)
        assert detection_lesson is not None
        assert detection_lesson["priority"] == "low"  # fast response

    @pytest.mark.asyncio
    async def test_generate_action_items(self, toolkit):
        lessons = [
            {"area": "detection", "lesson": "Fix alerts", "priority": "high"},
            {"area": "security", "lesson": "Patch vuln", "priority": "critical"},
        ]
        items = await toolkit.generate_action_items(lessons)
        assert len(items) == 2
        for item in items:
            assert isinstance(item, ActionItem)
            assert item.id.startswith("act-")
            assert item.completed is False
        assert items[0].owner == "sre-team"  # detection -> sre-team
        assert items[1].owner == "security-team"  # security -> security-team

    @pytest.mark.asyncio
    async def test_match_keywords_helper(self, toolkit):
        key, score = toolkit._match_keywords(
            "disk full and node failure",
            {"infra": ["disk full", "node failure"], "bug": ["crash"]},
        )
        assert key == "infra"
        assert score > 0.0


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


class TestNodes:
    @pytest.mark.asyncio
    async def test_gather_timeline_node(self):
        from shieldops.agents.post_incident_analyzer.nodes import (
            gather_timeline,
            set_toolkit,
        )

        set_toolkit(PostIncidentAnalyzerToolkit())
        state = PostIncidentAnalyzerState(incident_id="inc-1")
        result = await gather_timeline(state)
        assert "timeline_events" in result
        assert len(result["timeline_events"]) > 0
        assert result["stage"] == PostIncidentStage.ROOT_CAUSE_ANALYSIS

    @pytest.mark.asyncio
    async def test_root_cause_analysis_node(self):
        from shieldops.agents.post_incident_analyzer.nodes import (
            root_cause_analysis,
            set_toolkit,
        )

        set_toolkit(PostIncidentAnalyzerToolkit())
        state = PostIncidentAnalyzerState(
            incident_id="inc-1",
            timeline_events=[
                {"description": "Application crash due to bug"},
            ],
        )
        result = await root_cause_analysis(state)
        assert "root_cause" in result
        assert result["stage"] == PostIncidentStage.IMPACT_ASSESSMENT

    @pytest.mark.asyncio
    async def test_impact_assessment_node(self):
        from shieldops.agents.post_incident_analyzer.nodes import (
            impact_assessment,
            set_toolkit,
        )

        set_toolkit(PostIncidentAnalyzerToolkit())
        state = PostIncidentAnalyzerState(
            incident_id="inc-1",
            root_cause=RootCauseCategory.SOFTWARE_BUG,
        )
        result = await impact_assessment(state)
        assert "impact" in result
        assert result["stage"] == PostIncidentStage.LESSONS_LEARNED

    @pytest.mark.asyncio
    async def test_lessons_learned_node(self):
        from shieldops.agents.post_incident_analyzer.nodes import (
            lessons_learned,
            set_toolkit,
        )

        set_toolkit(PostIncidentAnalyzerToolkit())
        now = time.time()
        state = PostIncidentAnalyzerState(
            incident_id="inc-1",
            root_cause=RootCauseCategory.CONFIGURATION,
            impact=ImpactLevel.MEDIUM,
            timeline_events=[
                {"timestamp": now - 1800, "type": "alert", "description": "Alert"},
                {"timestamp": now - 600, "type": "action", "description": "Fixed"},
            ],
        )
        result = await lessons_learned(state)
        assert result["stage"] == PostIncidentStage.ACTION_ITEMS

    @pytest.mark.asyncio
    async def test_action_items_node(self):
        import json

        from shieldops.agents.post_incident_analyzer.nodes import (
            action_items,
            set_toolkit,
        )

        set_toolkit(PostIncidentAnalyzerToolkit())
        lessons_data = json.dumps(
            {
                "_lessons": [
                    {"area": "security", "lesson": "Patch it", "priority": "high"},
                ]
            }
        )
        state = PostIncidentAnalyzerState(
            incident_id="inc-1",
            root_cause=RootCauseCategory.EXTERNAL_ATTACK,
            impact=ImpactLevel.HIGH,
            timeline_events=[],
            reasoning_chain=[lessons_data],
        )
        result = await action_items(state)
        assert "action_items" in result
        assert len(result["action_items"]) >= 1
        assert result["stage"] == PostIncidentStage.REPORT

    @pytest.mark.asyncio
    async def test_report_node(self):
        from shieldops.agents.post_incident_analyzer.nodes import (
            report,
            set_toolkit,
        )

        set_toolkit(PostIncidentAnalyzerToolkit())
        state = PostIncidentAnalyzerState(
            incident_id="inc-1",
            session_start=time.time(),
            root_cause=RootCauseCategory.SOFTWARE_BUG,
            impact=ImpactLevel.MEDIUM,
            action_items=[ActionItem(id="act-1", title="Fix bug")],
            timeline_events=[{"description": "event"}],
        )
        result = await report(state)
        assert result["stage"] == PostIncidentStage.REPORT


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class TestRunner:
    def test_runner_init(self):
        from shieldops.agents.post_incident_analyzer.runner import (
            PostIncidentAnalyzerRunner,
        )

        runner = PostIncidentAnalyzerRunner()
        assert runner is not None
