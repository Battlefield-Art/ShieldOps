"""Tests for the firewall policy evaluator."""

from __future__ import annotations

from shieldops.firewall.evaluator import PolicyEvaluator, get_default_policies
from shieldops.firewall.models import (
    PolicyAction,
    PolicyCondition,
    PolicyRule,
    ToolCallContext,
)


class TestDefaultPolicies:
    def test_default_policies_exist(self) -> None:
        defaults = get_default_policies()
        assert len(defaults) > 0

    def test_default_deny_delete_database(self) -> None:
        evaluator = PolicyEvaluator()
        ctx = ToolCallContext(tool_name="delete_database", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.decision == PolicyAction.DENY
        assert len(result.matching_rules) == 1
        assert "delete_database" in result.matching_rules[0].name.lower()

    def test_default_deny_drop_table(self) -> None:
        evaluator = PolicyEvaluator()
        ctx = ToolCallContext(tool_name="drop_table", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.decision == PolicyAction.DENY

    def test_default_deny_modify_iam_root(self) -> None:
        evaluator = PolicyEvaluator()
        ctx = ToolCallContext(tool_name="modify_iam_root", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.decision == PolicyAction.DENY

    def test_default_deny_format_disk(self) -> None:
        evaluator = PolicyEvaluator()
        ctx = ToolCallContext(tool_name="format_disk", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.decision == PolicyAction.DENY

    def test_default_review_create_user(self) -> None:
        evaluator = PolicyEvaluator()
        ctx = ToolCallContext(tool_name="create_user", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.decision == PolicyAction.REVIEW

    def test_default_review_deploy_to_production(self) -> None:
        evaluator = PolicyEvaluator()
        ctx = ToolCallContext(tool_name="deploy_to_production", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.decision == PolicyAction.REVIEW

    def test_default_allow_read(self) -> None:
        evaluator = PolicyEvaluator()
        ctx = ToolCallContext(tool_name="read_logs", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.decision == PolicyAction.ALLOW

    def test_default_allow_list(self) -> None:
        evaluator = PolicyEvaluator()
        ctx = ToolCallContext(tool_name="list_buckets", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.decision == PolicyAction.ALLOW

    def test_default_allow_get(self) -> None:
        evaluator = PolicyEvaluator()
        ctx = ToolCallContext(tool_name="get_status", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.decision == PolicyAction.ALLOW


class TestPriorityOrdering:
    def test_higher_priority_wins(self) -> None:
        evaluator = PolicyEvaluator()
        # Add a low-priority ALLOW for deploy_to_production
        evaluator.add_rule(
            PolicyRule(
                name="allow-deploy",
                condition=PolicyCondition(tool_name_pattern="deploy_to_production"),
                action=PolicyAction.ALLOW,
                priority=5,  # higher priority (lower number) than default REVIEW (10)
                org_id="org-1",
            )
        )
        ctx = ToolCallContext(tool_name="deploy_to_production", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.decision == PolicyAction.ALLOW

    def test_org_rule_overrides_default(self) -> None:
        evaluator = PolicyEvaluator()
        # Org rule with same priority as default but appears first in merge
        evaluator.add_rule(
            PolicyRule(
                name="org-allow-create-user",
                condition=PolicyCondition(tool_name_pattern="create_user"),
                action=PolicyAction.ALLOW,
                priority=10,  # same as default REVIEW priority
                org_id="org-1",
            )
        )
        ctx = ToolCallContext(tool_name="create_user", org_id="org-1")
        result = evaluator.evaluate(ctx)
        # Org rules are merged and sorted; on equal priority org-specific should
        # appear first due to stable sort and insertion order
        assert result.decision == PolicyAction.ALLOW


class TestGlobPatternMatching:
    def test_wildcard_match(self) -> None:
        evaluator = PolicyEvaluator()
        evaluator.add_rule(
            PolicyRule(
                name="deny-all-delete",
                condition=PolicyCondition(tool_name_pattern="delete_*"),
                action=PolicyAction.DENY,
                priority=0,
                org_id="org-1",
            )
        )
        ctx = ToolCallContext(tool_name="delete_user", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.decision == PolicyAction.DENY

    def test_no_match_falls_through(self) -> None:
        evaluator = PolicyEvaluator()
        ctx = ToolCallContext(tool_name="some_custom_action", org_id="org-1")
        result = evaluator.evaluate(ctx)
        # No rule matches -> default allow
        assert result.decision == PolicyAction.ALLOW
        assert len(result.matching_rules) == 0


class TestConditionMatching:
    def test_caller_identity_filter(self) -> None:
        evaluator = PolicyEvaluator()
        evaluator.add_rule(
            PolicyRule(
                name="deny-specific-caller",
                condition=PolicyCondition(
                    tool_name_pattern="*",
                    caller_identity="bad-agent",
                ),
                action=PolicyAction.DENY,
                priority=0,
                org_id="org-1",
            )
        )
        # Bad caller -> denied
        ctx = ToolCallContext(tool_name="read_logs", caller_identity="bad-agent", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.decision == PolicyAction.DENY

        # Good caller -> allowed (falls through to default allow for read_*)
        ctx2 = ToolCallContext(tool_name="read_logs", caller_identity="good-agent", org_id="org-1")
        result2 = evaluator.evaluate(ctx2)
        assert result2.decision == PolicyAction.ALLOW

    def test_risk_score_range_filter(self) -> None:
        evaluator = PolicyEvaluator()
        evaluator.add_rule(
            PolicyRule(
                name="review-high-risk",
                condition=PolicyCondition(
                    tool_name_pattern="*",
                    min_risk_score=0.7,
                ),
                action=PolicyAction.REVIEW,
                priority=5,
                org_id="org-1",
            )
        )
        # delete_database has risk ~0.95 -> should match the review rule
        ctx = ToolCallContext(tool_name="delete_database", org_id="org-1")
        result = evaluator.evaluate(ctx)
        # But default deny for delete_database is priority 0, wins over priority 5
        assert result.decision == PolicyAction.DENY

    def test_argument_pattern_filter(self) -> None:
        evaluator = PolicyEvaluator()
        evaluator.add_rule(
            PolicyRule(
                name="deny-prod-deploy",
                condition=PolicyCondition(
                    tool_name_pattern="deploy_*",
                    argument_patterns={"environment": "prod*"},
                ),
                action=PolicyAction.DENY,
                priority=0,
                org_id="org-1",
            )
        )
        # Deploy to production env
        ctx = ToolCallContext(
            tool_name="deploy_service",
            arguments={"environment": "production"},
            org_id="org-1",
        )
        result = evaluator.evaluate(ctx)
        assert result.decision == PolicyAction.DENY

        # Deploy to staging -> should not match org rule
        ctx2 = ToolCallContext(
            tool_name="deploy_service",
            arguments={"environment": "staging"},
            org_id="org-1",
        )
        result2 = evaluator.evaluate(ctx2)
        assert result2.decision != PolicyAction.DENY


class TestTenantIsolation:
    def test_org_rules_only_apply_to_own_org(self) -> None:
        evaluator = PolicyEvaluator()
        evaluator.add_rule(
            PolicyRule(
                name="org1-deny-all",
                condition=PolicyCondition(tool_name_pattern="custom_tool"),
                action=PolicyAction.DENY,
                priority=0,
                org_id="org-1",
            )
        )
        # org-1 should be denied
        ctx1 = ToolCallContext(tool_name="custom_tool", org_id="org-1")
        assert evaluator.evaluate(ctx1).decision == PolicyAction.DENY

        # org-2 should be allowed (falls through to default)
        ctx2 = ToolCallContext(tool_name="custom_tool", org_id="org-2")
        assert evaluator.evaluate(ctx2).decision == PolicyAction.ALLOW

    def test_list_rules_scoped_to_org(self) -> None:
        evaluator = PolicyEvaluator()
        evaluator.add_rule(PolicyRule(name="org1-rule", org_id="org-1", action=PolicyAction.DENY))
        evaluator.add_rule(PolicyRule(name="org2-rule", org_id="org-2", action=PolicyAction.DENY))
        assert len(evaluator.list_rules("org-1")) == 1
        assert len(evaluator.list_rules("org-2")) == 1
        assert evaluator.list_rules("org-1")[0].name == "org1-rule"


class TestRuleCRUD:
    def test_add_and_get(self) -> None:
        evaluator = PolicyEvaluator()
        rule = PolicyRule(id="r1", name="test", org_id="org-1")
        evaluator.add_rule(rule)
        found = evaluator.get_rule("r1", "org-1")
        assert found is not None
        assert found.name == "test"

    def test_remove(self) -> None:
        evaluator = PolicyEvaluator()
        rule = PolicyRule(id="r1", name="test", org_id="org-1")
        evaluator.add_rule(rule)
        assert evaluator.remove_rule("r1", "org-1") is True
        assert evaluator.get_rule("r1", "org-1") is None

    def test_remove_nonexistent(self) -> None:
        evaluator = PolicyEvaluator()
        assert evaluator.remove_rule("nope", "org-1") is False

    def test_update(self) -> None:
        evaluator = PolicyEvaluator()
        rule = PolicyRule(id="r1", name="test", priority=50, org_id="org-1")
        evaluator.add_rule(rule)
        updated = evaluator.update_rule("r1", "org-1", {"name": "updated", "priority": 10})
        assert updated is not None
        assert updated.name == "updated"
        assert updated.priority == 10

    def test_update_nonexistent(self) -> None:
        evaluator = PolicyEvaluator()
        assert evaluator.update_rule("nope", "org-1", {"name": "x"}) is None


class TestEvaluationMetadata:
    def test_evaluation_includes_risk_score(self) -> None:
        evaluator = PolicyEvaluator()
        ctx = ToolCallContext(tool_name="delete_database", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.risk_score > 0.0

    def test_evaluation_includes_latency(self) -> None:
        evaluator = PolicyEvaluator()
        ctx = ToolCallContext(tool_name="read_logs", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.evaluation_ms >= 0.0

    def test_evaluation_includes_explanation(self) -> None:
        evaluator = PolicyEvaluator()
        ctx = ToolCallContext(tool_name="delete_database", org_id="org-1")
        result = evaluator.evaluate(ctx)
        assert result.explanation != ""

    def test_disabled_rules_skipped(self) -> None:
        evaluator = PolicyEvaluator()
        evaluator.add_rule(
            PolicyRule(
                name="disabled-deny",
                condition=PolicyCondition(tool_name_pattern="custom_tool"),
                action=PolicyAction.DENY,
                priority=0,
                org_id="org-1",
                enabled=False,
            )
        )
        ctx = ToolCallContext(tool_name="custom_tool", org_id="org-1")
        result = evaluator.evaluate(ctx)
        # Disabled rule should not fire -> falls to default allow
        assert result.decision == PolicyAction.ALLOW
