"""LLMFirewallEngine — Evaluate and enforce rules on LLM request/response traffic."""

from __future__ import annotations

import re
import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RuleAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    LOG = "log"


class RequestVerdict(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    LOGGED = "logged"


class RuleSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --- Models ---


class FirewallRule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    pattern: str = ""
    action: RuleAction = RuleAction.BLOCK
    severity: RuleSeverity = RuleSeverity.HIGH
    description: str = ""
    enabled: bool = True
    created_at: float = Field(default_factory=time.time)


class FirewallEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    request_text: str = ""
    verdict: RequestVerdict = RequestVerdict.ALLOWED
    matched_rule_id: str = ""
    severity: RuleSeverity = RuleSeverity.LOW
    score: float = 0.0
    source_app: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class FirewallReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_rules: int = 0
    total_events: int = 0
    blocked_count: int = 0
    allowed_count: int = 0
    avg_score: float = 0.0
    by_action: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_verdict: dict[str, int] = Field(default_factory=dict)
    top_blocked_patterns: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class LLMFirewallEngine:
    """Evaluate and enforce rules on LLM request/response traffic."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._rules: list[FirewallRule] = []
        self._events: list[FirewallEvent] = []
        logger.info(
            "llm_firewall_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- rule management ----------------------------------------------------

    def add_rule(
        self,
        name: str,
        pattern: str,
        action: RuleAction = RuleAction.BLOCK,
        severity: RuleSeverity = RuleSeverity.HIGH,
        description: str = "",
        enabled: bool = True,
    ) -> FirewallRule:
        rule = FirewallRule(
            name=name,
            pattern=pattern,
            action=action,
            severity=severity,
            description=description,
            enabled=enabled,
        )
        self._rules.append(rule)
        logger.info(
            "llm_firewall_engine.rule_added",
            rule_id=rule.id,
            name=name,
            action=action.value,
        )
        return rule

    def get_rule(self, rule_id: str) -> FirewallRule | None:
        for r in self._rules:
            if r.id == rule_id:
                return r
        return None

    def list_rules(self, enabled: bool | None = None) -> list[FirewallRule]:
        results = list(self._rules)
        if enabled is not None:
            results = [r for r in results if r.enabled == enabled]
        return results

    # -- evaluation ---------------------------------------------------------

    def evaluate_request(self, request_text: str) -> dict[str, Any]:
        """Evaluate a request against all enabled rules. Returns verdict."""
        for rule in self._rules:
            if not rule.enabled:
                continue
            try:
                if re.search(rule.pattern, request_text, re.IGNORECASE):
                    verdict = (
                        RequestVerdict.BLOCKED
                        if rule.action == RuleAction.BLOCK
                        else RequestVerdict.LOGGED
                        if rule.action == RuleAction.LOG
                        else RequestVerdict.ALLOWED
                    )
                    return {
                        "verdict": verdict.value,
                        "matched_rule_id": rule.id,
                        "matched_rule_name": rule.name,
                        "action": rule.action.value,
                        "severity": rule.severity.value,
                    }
            except re.error:
                continue
        return {
            "verdict": RequestVerdict.ALLOWED.value,
            "matched_rule_id": "",
            "matched_rule_name": "",
            "action": "allow",
            "severity": "low",
        }

    # -- event recording ----------------------------------------------------

    def record_event(
        self,
        name: str,
        request_text: str = "",
        verdict: RequestVerdict = RequestVerdict.ALLOWED,
        matched_rule_id: str = "",
        severity: RuleSeverity = RuleSeverity.LOW,
        score: float = 0.0,
        source_app: str = "",
        team: str = "",
    ) -> FirewallEvent:
        event = FirewallEvent(
            name=name,
            request_text=request_text,
            verdict=verdict,
            matched_rule_id=matched_rule_id,
            severity=severity,
            score=score,
            source_app=source_app,
            team=team,
        )
        self._events.append(event)
        if len(self._events) > self._max_records:
            self._events = self._events[-self._max_records :]
        logger.info(
            "llm_firewall_engine.event_recorded",
            event_id=event.id,
            verdict=verdict.value,
        )
        return event

    # -- standard methods ---------------------------------------------------

    def process(self, key: str) -> dict[str, Any]:
        matched = [e for e in self._events if e.name == key or e.source_app == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [e.score for e in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    def generate_report(self) -> FirewallReport:
        by_action: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_verdict: dict[str, int] = {}
        for e in self._events:
            by_verdict[e.verdict.value] = by_verdict.get(e.verdict.value, 0) + 1
            by_severity[e.severity.value] = by_severity.get(e.severity.value, 0) + 1
        for r in self._rules:
            by_action[r.action.value] = by_action.get(r.action.value, 0) + 1
        blocked = sum(1 for e in self._events if e.verdict == RequestVerdict.BLOCKED)
        allowed = sum(1 for e in self._events if e.verdict == RequestVerdict.ALLOWED)
        scores = [e.score for e in self._events]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        blocked_rules = [
            e.matched_rule_id for e in self._events if e.verdict == RequestVerdict.BLOCKED
        ]
        top_blocked = list(dict.fromkeys(blocked_rules))[:5]
        recs: list[str] = []
        if blocked > 0:
            recs.append(f"{blocked} request(s) blocked by firewall rules")
        if not recs:
            recs.append("LLM Firewall Engine is healthy")
        return FirewallReport(
            total_rules=len(self._rules),
            total_events=len(self._events),
            blocked_count=blocked,
            allowed_count=allowed,
            avg_score=avg_score,
            by_action=by_action,
            by_severity=by_severity,
            by_verdict=by_verdict,
            top_blocked_patterns=top_blocked,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._rules.clear()
        self._events.clear()
        logger.info("llm_firewall_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        verdict_dist: dict[str, int] = {}
        for e in self._events:
            verdict_dist[e.verdict.value] = verdict_dist.get(e.verdict.value, 0) + 1
        return {
            "total_rules": len(self._rules),
            "total_events": len(self._events),
            "threshold": self._threshold,
            "verdict_distribution": verdict_dist,
            "unique_teams": len({e.team for e in self._events}),
            "unique_source_apps": len({e.source_app for e in self._events}),
        }
