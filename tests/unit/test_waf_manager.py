"""Unit tests for waf_manager agent."""

from __future__ import annotations

from shieldops.agents.waf_manager.models import (
    AttackCategory,
    AttackEvent,
    RuleAction,
    WAFManagerState,
)
from shieldops.agents.waf_manager.tools import WAFManagerToolkit


class TestEnums:
    def test_attackcategory(self) -> None:
        assert AttackCategory.SQL_INJECTION == "sql_injection"
        assert len(AttackCategory) >= 3

    def test_ruleaction(self) -> None:
        assert RuleAction.BLOCK == "block"
        assert len(RuleAction) >= 3


class TestState:
    def test_defaults(self) -> None:
        state = WAFManagerState()
        assert state.request_id == ""
        assert state.error == ""

    def test_with_values(self) -> None:
        state = WAFManagerState(
            request_id="t-1",
            tenant_id="t-1",
        )
        assert state.request_id == "t-1"


class TestAttackEvent:
    def test_defaults(self) -> None:
        obj = AttackEvent()
        assert obj is not None


class TestToolkit:
    def test_init(self) -> None:
        tk = WAFManagerToolkit()
        assert tk is not None
