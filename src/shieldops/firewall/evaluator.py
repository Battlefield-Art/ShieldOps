"""Policy evaluation engine for the Agent Firewall.

Matches intercepted tool calls against org-scoped policy rules,
computes a risk score, and returns a decision (ALLOW / DENY / REVIEW).
"""

from __future__ import annotations

import time
from fnmatch import fnmatch
from typing import Any

import structlog

from shieldops.firewall.models import (
    PolicyAction,
    PolicyCondition,
    PolicyEvaluation,
    PolicyRule,
    ToolCallContext,
)
from shieldops.firewall.risk_scorer import RiskScorer

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Default (built-in) policies applied to ALL organisations
# ---------------------------------------------------------------------------

_DEFAULT_POLICIES: list[PolicyRule] = [
    # --- DENY: catastrophically destructive ---
    PolicyRule(
        id="default-deny-delete-database",
        name="Block delete_database",
        description="Prevent any agent from deleting databases.",
        condition=PolicyCondition(tool_name_pattern="delete_database"),
        action=PolicyAction.DENY,
        priority=0,
        org_id="__default__",
    ),
    PolicyRule(
        id="default-deny-drop-table",
        name="Block drop_table",
        description="Prevent any agent from dropping tables.",
        condition=PolicyCondition(tool_name_pattern="drop_table"),
        action=PolicyAction.DENY,
        priority=0,
        org_id="__default__",
    ),
    PolicyRule(
        id="default-deny-modify-iam-root",
        name="Block modify_iam_root",
        description="Prevent modifications to IAM root policies.",
        condition=PolicyCondition(tool_name_pattern="modify_iam_root"),
        action=PolicyAction.DENY,
        priority=0,
        org_id="__default__",
    ),
    PolicyRule(
        id="default-deny-format-disk",
        name="Block format_disk",
        description="Prevent disk formatting.",
        condition=PolicyCondition(tool_name_pattern="format_disk"),
        action=PolicyAction.DENY,
        priority=0,
        org_id="__default__",
    ),
    # --- REVIEW: sensitive but sometimes necessary ---
    PolicyRule(
        id="default-review-create-user",
        name="Review create_user",
        description="User creation requires human review.",
        condition=PolicyCondition(tool_name_pattern="create_user"),
        action=PolicyAction.REVIEW,
        priority=10,
        org_id="__default__",
    ),
    PolicyRule(
        id="default-review-modify-security-group",
        name="Review modify_security_group",
        description="Security group changes require human review.",
        condition=PolicyCondition(tool_name_pattern="modify_security_group"),
        action=PolicyAction.REVIEW,
        priority=10,
        org_id="__default__",
    ),
    PolicyRule(
        id="default-review-deploy-to-production",
        name="Review deploy_to_production",
        description="Production deployments require human review.",
        condition=PolicyCondition(tool_name_pattern="deploy_to_production"),
        action=PolicyAction.REVIEW,
        priority=10,
        org_id="__default__",
    ),
    # --- ALLOW: read-only operations ---
    PolicyRule(
        id="default-allow-read",
        name="Allow read_*",
        description="Read operations are safe by default.",
        condition=PolicyCondition(tool_name_pattern="read_*"),
        action=PolicyAction.ALLOW,
        priority=50,
        org_id="__default__",
    ),
    PolicyRule(
        id="default-allow-list",
        name="Allow list_*",
        description="List operations are safe by default.",
        condition=PolicyCondition(tool_name_pattern="list_*"),
        action=PolicyAction.ALLOW,
        priority=50,
        org_id="__default__",
    ),
    PolicyRule(
        id="default-allow-describe",
        name="Allow describe_*",
        description="Describe operations are safe by default.",
        condition=PolicyCondition(tool_name_pattern="describe_*"),
        action=PolicyAction.ALLOW,
        priority=50,
        org_id="__default__",
    ),
    PolicyRule(
        id="default-allow-get",
        name="Allow get_*",
        description="Get operations are safe by default.",
        condition=PolicyCondition(tool_name_pattern="get_*"),
        action=PolicyAction.ALLOW,
        priority=50,
        org_id="__default__",
    ),
]


def get_default_policies() -> list[PolicyRule]:
    """Return a copy of the built-in default policies."""
    return list(_DEFAULT_POLICIES)


class PolicyEvaluator:
    """Evaluate tool calls against org-scoped policy rules.

    Rules are matched in priority order (lower number = higher priority).
    First matching rule wins. Default policies are always appended with
    lowest priority so org-specific rules can override them.

    Args:
        risk_scorer: Optional ``RiskScorer`` instance. A default is created
            if not supplied.
    """

    def __init__(self, risk_scorer: RiskScorer | None = None) -> None:
        self._risk_scorer = risk_scorer or RiskScorer()
        # org_id -> list[PolicyRule] (kept sorted by priority)
        self._rules: dict[str, list[PolicyRule]] = {}

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a rule and keep the list sorted by priority."""
        org_rules = self._rules.setdefault(rule.org_id, [])
        org_rules.append(rule)
        org_rules.sort(key=lambda r: r.priority)

    def remove_rule(self, rule_id: str, org_id: str) -> bool:
        """Remove a rule by id. Returns True if found and removed."""
        org_rules = self._rules.get(org_id, [])
        for idx, rule in enumerate(org_rules):
            if rule.id == rule_id:
                org_rules.pop(idx)
                return True
        return False

    def get_rule(self, rule_id: str, org_id: str) -> PolicyRule | None:
        """Look up a single rule by id within an org."""
        for rule in self._rules.get(org_id, []):
            if rule.id == rule_id:
                return rule
        return None

    def list_rules(self, org_id: str) -> list[PolicyRule]:
        """Return all rules for an org (sorted by priority)."""
        return list(self._rules.get(org_id, []))

    def update_rule(self, rule_id: str, org_id: str, updates: dict[str, Any]) -> PolicyRule | None:
        """Update fields on a rule. Returns updated rule or None."""
        org_rules = self._rules.get(org_id, [])
        for idx, rule in enumerate(org_rules):
            if rule.id == rule_id:
                data = rule.model_dump()
                data.update(updates)
                updated = PolicyRule(**data)
                org_rules[idx] = updated
                org_rules.sort(key=lambda r: r.priority)
                return updated
        return None

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, tool_call: ToolCallContext) -> PolicyEvaluation:
        """Evaluate a tool call and return the policy decision.

        Steps:
            1. Compute risk score via the risk scorer.
            2. Collect applicable rules (org-specific + defaults).
            3. Walk rules in priority order; first match wins.
            4. If no rule matches, allow with the computed risk score.
            5. Log an audit trail entry.
        """
        start = time.perf_counter()

        risk_score = self._risk_scorer.score(
            tool_name=tool_call.tool_name,
            arguments=tool_call.arguments,
            caller_identity=tool_call.caller_identity,
            timestamp=tool_call.timestamp,
        )

        # Merge org rules + defaults (org rules first so they win on equal priority)
        org_rules = self._rules.get(tool_call.org_id, [])
        all_rules = sorted(
            [r for r in org_rules if r.enabled] + [r for r in _DEFAULT_POLICIES if r.enabled],
            key=lambda r: r.priority,
        )

        matching_rules: list[PolicyRule] = []
        decision = PolicyAction.ALLOW
        explanation = "No matching rule — allowed by default."

        for rule in all_rules:
            if self._matches(rule.condition, tool_call, risk_score):
                matching_rules.append(rule)
                decision = rule.action
                explanation = (
                    f"Matched rule '{rule.name}' (id={rule.id}, "
                    f"priority={rule.priority}): {rule.description}"
                )
                break  # first match wins

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        evaluation = PolicyEvaluation(
            decision=decision,
            risk_score=risk_score,
            matching_rules=matching_rules,
            explanation=explanation,
            evaluation_ms=round(elapsed_ms, 3),
        )

        # Audit trail
        logger.info(
            "firewall_evaluation",
            tool_name=tool_call.tool_name,
            org_id=tool_call.org_id,
            caller=tool_call.caller_identity,
            decision=decision.value,
            risk_score=risk_score,
            matched_rule=matching_rules[0].id if matching_rules else None,
            evaluation_ms=evaluation.evaluation_ms,
        )

        return evaluation

    # ------------------------------------------------------------------
    # Condition matching
    # ------------------------------------------------------------------

    @staticmethod
    def _matches(
        condition: PolicyCondition,
        tool_call: ToolCallContext,
        risk_score: float,
    ) -> bool:
        """Return True if all specified condition fields match the tool call."""
        # Tool name (glob)
        if not fnmatch(tool_call.tool_name, condition.tool_name_pattern):
            return False

        # Caller identity (exact match if specified)
        if condition.caller_identity is not None:
            if tool_call.caller_identity != condition.caller_identity:
                return False

        # Risk score range
        if condition.min_risk_score is not None and risk_score < condition.min_risk_score:
            return False
        if condition.max_risk_score is not None and risk_score > condition.max_risk_score:
            return False

        # Argument patterns (glob per key)
        if condition.argument_patterns:
            for key, pattern in condition.argument_patterns.items():
                arg_value = str(tool_call.arguments.get(key, ""))
                if not fnmatch(arg_value, pattern):
                    return False

        return True
