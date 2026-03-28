"""Tests for shieldops.agents.session_hijack_detector — session hijack detection."""

from __future__ import annotations

import pytest

from shieldops.agents.session_hijack_detector.models import (
    DetectionStage,
    HijackIndicator,
    HijackReport,
    HijackType,
    ReasoningStep,
    ResponseAction,
    SessionEvent,
    SessionHijackDetectorState,
    SessionRisk,
)
from shieldops.agents.session_hijack_detector.tools import (
    SessionHijackDetectorToolkit,
)


def _state(**kw) -> SessionHijackDetectorState:
    return SessionHijackDetectorState(**kw)


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestEnums:
    def test_detection_stage_values(self):
        assert DetectionStage.COLLECT_SESSIONS == "collect_sessions"
        assert DetectionStage.ANALYZE_ANOMALIES == "analyze_anomalies"
        assert DetectionStage.CORRELATE_INDICATORS == "correlate_indicators"
        assert DetectionStage.ASSESS_RISK == "assess_risk"
        assert DetectionStage.RESPOND == "respond"
        assert DetectionStage.REPORT == "report"

    def test_hijack_type_values(self):
        assert HijackType.TOKEN_THEFT == "token_theft"  # noqa: S105
        assert HijackType.COOKIE_MANIPULATION == "cookie_manipulation"
        assert HijackType.IMPOSSIBLE_TRAVEL == "impossible_travel"
        assert HijackType.SESSION_REPLAY == "session_replay"
        assert HijackType.CONCURRENT_GEO == "concurrent_geo"
        assert HijackType.SESSION_FIXATION == "session_fixation"
        assert HijackType.SIDEJACKING == "sidejacking"

    def test_session_risk_values(self):
        assert SessionRisk.CRITICAL == "critical"
        assert SessionRisk.HIGH == "high"
        assert SessionRisk.MEDIUM == "medium"
        assert SessionRisk.LOW == "low"
        assert SessionRisk.INFO == "info"


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.tenant_id == ""
        assert s.detection_id == ""
        assert s.raw_events == []
        assert s.sessions == []
        assert s.unique_users == 0
        assert s.indicators == []
        assert s.anomaly_count == 0
        assert s.correlated_indicators == []
        assert s.confirmed_hijacks == 0
        assert s.overall_risk == "low"
        assert s.risk_score == 0.0
        assert s.auto_respond is False
        assert s.response_actions == []
        assert s.responses_executed == 0
        assert s.report is None
        assert s.session_start is None
        assert s.session_duration_ms == 0
        assert s.reasoning_chain == []
        assert s.current_step == "init"
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(
            tenant_id="t-1",
            detection_id="det-abc",
            overall_risk="high",
            risk_score=75.0,
            confirmed_hijacks=2,
        )
        assert s.tenant_id == "t-1"
        assert s.overall_risk == "high"
        assert s.risk_score == 75.0
        assert s.confirmed_hijacks == 2

    def test_session_event_defaults(self):
        e = SessionEvent()
        assert e.event_id == ""
        assert e.session_id == ""
        assert e.user_id == ""
        assert e.ip_address == ""
        assert e.geo_lat == 0.0
        assert e.geo_lon == 0.0
        assert e.timestamp == 0.0
        assert e.cookie_flags == {}

    def test_hijack_indicator_defaults(self):
        ind = HijackIndicator()
        assert ind.indicator_id == ""
        assert ind.hijack_type == "token_theft"
        assert ind.risk == "medium"
        assert ind.confidence == 0.0
        assert ind.travel_speed_kmh == 0.0
        assert ind.evidence == []
        assert ind.mitre_technique == ""

    def test_response_action_defaults(self):
        ra = ResponseAction()
        assert ra.action_id == ""
        assert ra.action_type == ""
        assert ra.executed is False
        assert ra.requires_approval is False
        assert ra.result == ""
        assert ra.execution_time_ms == 0

    def test_hijack_report_defaults(self):
        r = HijackReport()
        assert r.report_id == ""
        assert r.sessions_analyzed == 0
        assert r.hijacks_confirmed == 0
        assert r.hijack_types == []
        assert r.affected_users == []
        assert r.risk_summary == {}

    def test_reasoning_step(self):
        step = ReasoningStep(
            step_number=1,
            action="collect_sessions",
            input_summary="10 events",
            output_summary="10 sessions",
            duration_ms=50,
            tool_used="session_collector",
        )
        assert step.step_number == 1
        assert step.action == "collect_sessions"
        assert step.duration_ms == 50


# ---------------------------------------------------------------------------
# Toolkit tests
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        return SessionHijackDetectorToolkit()

    @pytest.mark.asyncio()
    async def test_collect_session_events(self, toolkit):
        raw = [
            {"session_id": "s1", "user_id": "u1"},
            {"session_id": "s2", "user_id": "u2"},
        ]
        result = await toolkit.collect_session_events(raw)
        assert len(result) == 2
        assert result[0]["enriched"] is True

    @pytest.mark.asyncio()
    async def test_detect_impossible_travel(self, toolkit):
        sessions = [
            {
                "user_id": "u1",
                "ip_address": "1.1.1.1",
                "geo_lat": 40.7128,
                "geo_lon": -74.0060,
                "geo_city": "NYC",
                "timestamp": 1000.0,
            },
            {
                "user_id": "u1",
                "ip_address": "2.2.2.2",
                "geo_lat": 51.5074,
                "geo_lon": -0.1278,
                "geo_city": "London",
                "timestamp": 1060.0,  # 1 minute later
            },
        ]
        indicators = await toolkit.detect_impossible_travel(
            sessions,
        )
        assert len(indicators) >= 1
        assert indicators[0]["hijack_type"] == "impossible_travel"
        assert indicators[0]["travel_speed_kmh"] > 500.0

    @pytest.mark.asyncio()
    async def test_detect_impossible_travel_no_anomaly(self, toolkit):
        sessions = [
            {
                "user_id": "u1",
                "ip_address": "1.1.1.1",
                "geo_lat": 40.71,
                "geo_lon": -74.00,
                "timestamp": 1000.0,
            },
            {
                "user_id": "u1",
                "ip_address": "1.1.1.2",
                "geo_lat": 40.72,
                "geo_lon": -73.99,
                "timestamp": 2000.0,
            },
        ]
        indicators = await toolkit.detect_impossible_travel(
            sessions,
        )
        assert len(indicators) == 0

    @pytest.mark.asyncio()
    async def test_detect_concurrent_sessions(self, toolkit):
        sessions = [
            {
                "user_id": "u1",
                "ip_address": "1.1.1.1",
                "geo_country": "US",
                "session_id": "s1",
            },
            {
                "user_id": "u1",
                "ip_address": "2.2.2.2",
                "geo_country": "RU",
                "session_id": "s2",
            },
        ]
        indicators = await toolkit.detect_concurrent_sessions(
            sessions,
        )
        assert len(indicators) == 1
        assert indicators[0]["hijack_type"] == "concurrent_geo"

    @pytest.mark.asyncio()
    async def test_detect_token_anomalies(self, toolkit):
        sessions = [
            {
                "token_hash": "abc123",
                "ip_address": "1.1.1.1",
                "session_id": "s1",
                "user_id": "u1",
            },
            {
                "token_hash": "abc123",
                "ip_address": "9.9.9.9",
                "session_id": "s1",
                "user_id": "u1",
            },
        ]
        indicators = await toolkit.detect_token_anomalies(
            sessions,
        )
        assert len(indicators) == 1
        assert indicators[0]["hijack_type"] == "token_theft"
        assert indicators[0]["risk"] == "critical"

    @pytest.mark.asyncio()
    async def test_execute_response(self, toolkit):
        actions = [
            {
                "action_id": "ra-1",
                "action_type": "invalidate_session",
                "target_session_id": "s1",
            },
        ]
        results = await toolkit.execute_response(actions)
        assert len(results) == 1
        assert results[0]["executed"] is True
        assert results[0]["result"] == "success"

    @pytest.mark.asyncio()
    async def test_record_metric(self, toolkit):
        await toolkit.record_metric("test_metric", 42.0)

    def test_calc_travel_speed_zero_time(self, toolkit):
        speed = toolkit._calc_travel_speed(
            {"geo_lat": 40.0, "geo_lon": -74.0, "timestamp": 100},
            {"geo_lat": 51.0, "geo_lon": -0.1, "timestamp": 100},
        )
        assert speed == 0.0

    def test_calc_travel_speed_same_location(self, toolkit):
        speed = toolkit._calc_travel_speed(
            {"geo_lat": 40.0, "geo_lon": -74.0, "timestamp": 100},
            {"geo_lat": 40.0, "geo_lon": -74.0, "timestamp": 200},
        )
        assert speed == 0.0


# ---------------------------------------------------------------------------
# Graph compilation test
# ---------------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.session_hijack_detector.graph import (
            create_session_hijack_detector_graph,
        )

        sg = create_session_hijack_detector_graph()
        app = sg.compile()
        assert app is not None
