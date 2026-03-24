"""LLM Firewall — evaluate and enforce security rules on LLM requests and responses."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class FirewallAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    TRANSFORM = "transform"
    RATE_LIMIT = "rate_limit"
    ESCALATE = "escalate"


class RuleScope(StrEnum):
    PROMPT_INPUT = "prompt_input"
    MODEL_OUTPUT = "model_output"
    TOOL_CALL = "tool_call"
    SYSTEM_PROMPT = "system_prompt"
    ALL = "all"


class ThreatCategory(StrEnum):
    INJECTION = "injection"
    EXFILTRATION = "exfiltration"
    ABUSE = "abuse"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY = "anomaly"


# --- Models ---


class FirewallRuleRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    action: FirewallAction = FirewallAction.BLOCK
    scope: RuleScope = RuleScope.ALL
    threat_category: ThreatCategory = ThreatCategory.INJECTION
    pattern: str = ""
    priority: int = 0
    enabled: bool = True
    match_count: int = 0
    false_positive_count: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class FirewallEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    action: FirewallAction = FirewallAction.BLOCK
    threat_category: ThreatCategory = ThreatCategory.INJECTION
    scope: RuleScope = RuleScope.ALL
    content_hash: str = ""
    app_id: str = ""
    user_id: str = ""
    matched: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class FirewallReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_rules: int = 0
    total_events: int = 0
    blocked_count: int = 0
    allowed_count: int = 0
    avg_rules_per_request: float = 0.0
    by_action: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_scope: dict[str, int] = Field(default_factory=dict)
    top_triggered_rules: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class LLMFirewall:
    """Evaluate and enforce security rules on LLM requests and responses."""

    def __init__(
        self,
        max_records: int = 200000,
        default_action: FirewallAction = FirewallAction.ALLOW,
    ) -> None:
        self._max_records = max_records
        self._default_action = default_action
        self._rules: list[FirewallRuleRecord] = []
        self._events: list[FirewallEvent] = []
        logger.info(
            "llm_firewall.initialized",
            max_records=max_records,
            default_action=default_action.value,
        )

    # -- rule management -------------------------------------------------------

    def add_rule(
        self,
        name: str,
        action: FirewallAction = FirewallAction.BLOCK,
        scope: RuleScope = RuleScope.ALL,
        threat_category: ThreatCategory = ThreatCategory.INJECTION,
        pattern: str = "",
        priority: int = 0,
        enabled: bool = True,
        description: str = "",
    ) -> FirewallRuleRecord:
        rule = FirewallRuleRecord(
            name=name,
            action=action,
            scope=scope,
            threat_category=threat_category,
            pattern=pattern,
            priority=priority,
            enabled=enabled,
            description=description,
        )
        self._rules.append(rule)
        logger.info(
            "llm_firewall.rule_added",
            rule_id=rule.id,
            name=name,
            action=action.value,
            scope=scope.value,
        )
        return rule

    def record_event(
        self,
        rule_id: str = "",
        action: FirewallAction = FirewallAction.BLOCK,
        threat_category: ThreatCategory = ThreatCategory.INJECTION,
        scope: RuleScope = RuleScope.ALL,
        content_hash: str = "",
        app_id: str = "",
        user_id: str = "",
        matched: bool = False,
        description: str = "",
    ) -> FirewallEvent:
        event = FirewallEvent(
            rule_id=rule_id,
            action=action,
            threat_category=threat_category,
            scope=scope,
            content_hash=content_hash,
            app_id=app_id,
            user_id=user_id,
            matched=matched,
            description=description,
        )
        self._events.append(event)
        if len(self._events) > self._max_records:
            self._events = self._events[-self._max_records :]
        logger.info(
            "llm_firewall.event_recorded",
            event_id=event.id,
            rule_id=rule_id,
            action=action.value,
            matched=matched,
        )
        return event

    # -- domain operations -----------------------------------------------------

    def evaluate_request(self, content: str, app_id: str = "", user_id: str = "") -> dict[str, Any]:
        """Evaluate an incoming LLM request against firewall rules."""
        content_lower = content.lower()
        matched_rules: list[dict[str, Any]] = []
        final_action = self._default_action

        # Sort by priority (higher priority = checked first)
        sorted_rules = sorted(
            [r for r in self._rules if r.enabled],
            key=lambda r: r.priority,
            reverse=True,
        )

        for rule in sorted_rules:
            if rule.scope not in (RuleScope.PROMPT_INPUT, RuleScope.SYSTEM_PROMPT, RuleScope.ALL):
                continue
            if rule.pattern and rule.pattern.lower() in content_lower:
                rule.match_count += 1
                matched_rules.append(
                    {
                        "rule_id": rule.id,
                        "name": rule.name,
                        "action": rule.action.value,
                        "threat_category": rule.threat_category.value,
                    }
                )
                # Highest priority match wins
                if not matched_rules or rule.priority >= sorted_rules[0].priority:
                    final_action = rule.action

        return {
            "action": final_action.value,
            "matched_rules": matched_rules,
            "match_count": len(matched_rules),
            "app_id": app_id,
            "user_id": user_id,
        }

    def evaluate_response(
        self, content: str, app_id: str = "", user_id: str = ""
    ) -> dict[str, Any]:
        """Evaluate an LLM response against output filtering rules."""
        content_lower = content.lower()
        matched_rules: list[dict[str, Any]] = []
        final_action = self._default_action

        sorted_rules = sorted(
            [r for r in self._rules if r.enabled],
            key=lambda r: r.priority,
            reverse=True,
        )

        for rule in sorted_rules:
            if rule.scope not in (RuleScope.MODEL_OUTPUT, RuleScope.ALL):
                continue
            if rule.pattern and rule.pattern.lower() in content_lower:
                rule.match_count += 1
                matched_rules.append(
                    {
                        "rule_id": rule.id,
                        "name": rule.name,
                        "action": rule.action.value,
                        "threat_category": rule.threat_category.value,
                    }
                )
                if not matched_rules or rule.priority >= sorted_rules[0].priority:
                    final_action = rule.action

        return {
            "action": final_action.value,
            "matched_rules": matched_rules,
            "match_count": len(matched_rules),
            "app_id": app_id,
            "user_id": user_id,
        }

    def adjust_rules_from_feedback(self) -> dict[str, Any]:
        """Adjust rule thresholds based on false positive feedback."""
        adjusted: list[str] = []
        for rule in self._rules:
            if rule.match_count > 0 and rule.false_positive_count > 0:
                fp_rate = rule.false_positive_count / rule.match_count
                if fp_rate > 0.5 and rule.enabled:
                    rule.enabled = False
                    adjusted.append(rule.id)
                    logger.info(
                        "llm_firewall.rule_disabled",
                        rule_id=rule.id,
                        fp_rate=round(fp_rate, 2),
                    )
        return {
            "rules_adjusted": len(adjusted),
            "disabled_rule_ids": adjusted,
        }

    # -- report / stats --------------------------------------------------------

    def generate_report(self) -> FirewallReport:
        by_action: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_scope: dict[str, int] = {}
        for e in self._events:
            by_action[e.action.value] = by_action.get(e.action.value, 0) + 1
            by_category[e.threat_category.value] = by_category.get(e.threat_category.value, 0) + 1
            by_scope[e.scope.value] = by_scope.get(e.scope.value, 0) + 1

        blocked = sum(1 for e in self._events if e.action == FirewallAction.BLOCK)
        allowed = sum(1 for e in self._events if e.action == FirewallAction.ALLOW)

        top_rules = sorted(self._rules, key=lambda r: r.match_count, reverse=True)[:5]
        top_triggered = [f"{r.name} ({r.match_count} matches)" for r in top_rules]

        recs: list[str] = []
        if blocked > 0:
            recs.append(f"{blocked} request(s) blocked — review firewall event logs")
        high_fp_rules = [r for r in self._rules if r.false_positive_count > 5]
        if high_fp_rules:
            recs.append(f"{len(high_fp_rules)} rule(s) with high false positives — tune patterns")
        if not recs:
            recs.append("LLM firewall operating within normal parameters")

        return FirewallReport(
            total_rules=len(self._rules),
            total_events=len(self._events),
            blocked_count=blocked,
            allowed_count=allowed,
            by_action=by_action,
            by_category=by_category,
            by_scope=by_scope,
            top_triggered_rules=top_triggered,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        action_dist: dict[str, int] = {}
        for e in self._events:
            key = e.action.value
            action_dist[key] = action_dist.get(key, 0) + 1
        return {
            "total_rules": len(self._rules),
            "total_events": len(self._events),
            "enabled_rules": sum(1 for r in self._rules if r.enabled),
            "default_action": self._default_action.value,
            "action_distribution": action_dist,
            "unique_apps": len({e.app_id for e in self._events}),
        }

    def clear_data(self) -> dict[str, str]:
        self._rules.clear()
        self._events.clear()
        logger.info("llm_firewall.cleared")
        return {"status": "cleared"}
