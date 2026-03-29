"""Tests for shieldops.agents.browser_isolation."""

from __future__ import annotations

import pytest

from shieldops.agents.browser_isolation.models import (
    BreakoutAttempt,
    BrowserIsolationState,
    BrowserSession,
    ContentPolicy,
    IsolationAction,
    IsolationStage,
    SessionRisk,
)


def _state(**kw) -> BrowserIsolationState:
    return BrowserIsolationState(**kw)


class TestEnums:
    def test_isolation_stage_values(self):
        assert IsolationStage.COLLECT_SESSIONS == "collect_sessions"
        assert IsolationStage.DETECT_BREAKOUTS == "detect_breakouts"
        assert IsolationStage.EVALUATE_POLICIES == "evaluate_policies"
        assert IsolationStage.SANDBOX_CONTENT == "sandbox_content"
        assert IsolationStage.ENFORCE == "enforce"
        assert IsolationStage.REPORT == "report"

    def test_session_risk_values(self):
        assert SessionRisk.CRITICAL == "critical"
        assert SessionRisk.HIGH == "high"
        assert SessionRisk.MEDIUM == "medium"
        assert SessionRisk.LOW == "low"
        assert SessionRisk.SAFE == "safe"

    def test_isolation_action_values(self):
        assert IsolationAction.TERMINATE == "terminate"
        assert IsolationAction.BLOCK == "block"
        assert IsolationAction.ISOLATE == "isolate"
        assert IsolationAction.ALLOW == "allow"
        assert IsolationAction.SANDBOX == "sandbox"
        assert IsolationAction.ALERT == "alert"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == IsolationStage.COLLECT_SESSIONS
        assert s.sessions == []
        assert s.total_sessions == 0
        assert s.active_isolated == 0
        assert s.breakout_attempts == []
        assert s.breakouts_blocked == 0
        assert s.policy_violations == []
        assert s.policies_enforced == 0
        assert s.sandboxed_content == []
        assert s.summary == ""
        assert s.risk_score == 0.0
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(total_sessions=100, breakouts_blocked=3)
        assert s.total_sessions == 100
        assert s.breakouts_blocked == 3

    def test_browser_session_defaults(self):
        b = BrowserSession()
        assert b.session_id == ""
        assert b.isolated is True
        assert b.risk == SessionRisk.LOW

    def test_breakout_attempt_defaults(self):
        b = BreakoutAttempt()
        assert b.id == ""
        assert b.severity == SessionRisk.HIGH
        assert b.blocked is True

    def test_content_policy_defaults(self):
        c = ContentPolicy()
        assert c.action == IsolationAction.ISOLATE
        assert c.enabled is True


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.browser_isolation.tools import (
            BrowserIsolationToolkit,
        )

        return BrowserIsolationToolkit()

    @pytest.mark.asyncio
    async def test_collect_sessions(self, toolkit):
        result = await toolkit.collect_sessions("t-01")
        assert isinstance(result, list)
        assert len(result) >= 3

    @pytest.mark.asyncio
    async def test_detect_breakouts(self, toolkit):
        sessions = await toolkit.collect_sessions("t-01")
        attempts, blocked = await toolkit.detect_breakouts(sessions)
        assert isinstance(attempts, list)
        assert isinstance(blocked, int)
        assert blocked > 0

    @pytest.mark.asyncio
    async def test_evaluate_policies(self, toolkit):
        sessions = await toolkit.collect_sessions("t-01")
        violations, enforced = await toolkit.evaluate_policies(sessions)
        assert isinstance(violations, list)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.browser_isolation.graph import (
            create_browser_isolation_graph,
        )

        sg = create_browser_isolation_graph()
        assert sg.compile() is not None
