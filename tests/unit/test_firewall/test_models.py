"""Tests for firewall policy models."""

from __future__ import annotations

from shieldops.firewall.models import (
    PolicyAction,
    PolicyCondition,
    PolicyEvaluation,
    PolicyRule,
    ToolCallContext,
)


class TestPolicyAction:
    def test_enum_values(self) -> None:
        assert PolicyAction.ALLOW == "allow"
        assert PolicyAction.DENY == "deny"
        assert PolicyAction.REVIEW == "review"


class TestPolicyCondition:
    def test_defaults(self) -> None:
        cond = PolicyCondition()
        assert cond.tool_name_pattern == "*"
        assert cond.argument_patterns == {}
        assert cond.caller_identity is None
        assert cond.min_risk_score is None
        assert cond.max_risk_score is None

    def test_full_condition(self) -> None:
        cond = PolicyCondition(
            tool_name_pattern="delete_*",
            argument_patterns={"db": "prod*"},
            caller_identity="agent-007",
            min_risk_score=0.5,
            max_risk_score=0.9,
        )
        assert cond.tool_name_pattern == "delete_*"
        assert cond.caller_identity == "agent-007"


class TestPolicyRule:
    def test_defaults(self) -> None:
        rule = PolicyRule(name="test")
        assert rule.name == "test"
        assert rule.action == PolicyAction.ALLOW
        assert rule.priority == 100
        assert rule.enabled is True
        assert rule.org_id == ""
        assert rule.id  # UUID auto-generated

    def test_deny_rule(self) -> None:
        rule = PolicyRule(
            name="block_delete",
            action=PolicyAction.DENY,
            priority=0,
            condition=PolicyCondition(tool_name_pattern="delete_*"),
        )
        assert rule.action == PolicyAction.DENY
        assert rule.priority == 0


class TestToolCallContext:
    def test_minimal(self) -> None:
        ctx = ToolCallContext(tool_name="read_logs")
        assert ctx.tool_name == "read_logs"
        assert ctx.arguments == {}
        assert ctx.caller_identity == ""

    def test_full(self) -> None:
        ctx = ToolCallContext(
            tool_name="delete_database",
            arguments={"db": "production"},
            caller_identity="agent-x",
            org_id="org-123",
        )
        assert ctx.org_id == "org-123"


class TestPolicyEvaluation:
    def test_allow(self) -> None:
        ev = PolicyEvaluation(
            decision=PolicyAction.ALLOW,
            risk_score=0.1,
            explanation="safe",
        )
        assert ev.decision == PolicyAction.ALLOW
        assert ev.matching_rules == []

    def test_deny_with_rules(self) -> None:
        rule = PolicyRule(name="block", action=PolicyAction.DENY)
        ev = PolicyEvaluation(
            decision=PolicyAction.DENY,
            risk_score=0.95,
            matching_rules=[rule],
            explanation="blocked",
            evaluation_ms=1.23,
        )
        assert len(ev.matching_rules) == 1
        assert ev.evaluation_ms == 1.23
