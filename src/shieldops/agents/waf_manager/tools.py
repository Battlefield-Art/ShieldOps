"""WAF Manager — Tool functions for WAF rule management."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .models import (
    AttackCategory,
    AttackEvent,
    CoverageGap,
    RuleAction,
    WAFRule,
)

logger = structlog.get_logger()

# OWASP Top 10 2021 mapping
_OWASP_TOP_10: list[dict[str, str]] = [
    {"id": "A01", "name": "Broken Access Control"},
    {"id": "A02", "name": "Cryptographic Failures"},
    {"id": "A03", "name": "Injection"},
    {"id": "A04", "name": "Insecure Design"},
    {"id": "A05", "name": "Security Misconfiguration"},
    {"id": "A06", "name": "Vulnerable Components"},
    {"id": "A07", "name": "Auth Failures"},
    {"id": "A08", "name": "Data Integrity Failures"},
    {"id": "A09", "name": "Logging Failures"},
    {"id": "A10", "name": "SSRF"},
]

_OWASP_CATEGORY_MAP: dict[str, list[AttackCategory]] = {
    "A01": [AttackCategory.PATH_TRAVERSAL, AttackCategory.CSRF],
    "A02": [AttackCategory.SENSITIVE_DATA],
    "A03": [
        AttackCategory.SQL_INJECTION,
        AttackCategory.XSS,
        AttackCategory.COMMAND_INJECTION,
        AttackCategory.XXE,
    ],
    "A04": [AttackCategory.INSECURE_DESERIALIZATION],
    "A05": [AttackCategory.SECURITY_MISCONFIGURATION],
    "A06": [],
    "A07": [AttackCategory.BROKEN_AUTH],
    "A08": [AttackCategory.INSECURE_DESERIALIZATION],
    "A09": [],
    "A10": [AttackCategory.SSRF],
}

_AUTO_BLOCK_THRESHOLD = 10  # events before auto-block
_FP_RATE_THRESHOLD = 0.15  # 15% FP rate triggers review


class WAFManagerToolkit:
    """Tools for WAF rule management and attack analysis."""

    def __init__(
        self,
        waf_client: Any | None = None,
        log_store: Any | None = None,
        alert_sink: Any | None = None,
    ) -> None:
        self._waf_client = waf_client
        self._log_store = log_store
        self._alert_sink = alert_sink
        self._rules: dict[str, WAFRule] = {}
        self._events: list[AttackEvent] = []
        self._blocked_ips: set[str] = set()

    async def ingest_waf_logs(
        self,
        time_window_hours: int = 24,
    ) -> list[AttackEvent]:
        """Ingest WAF log events for analysis."""
        logger.info(
            "waf_manager.ingest_logs",
            window_hours=time_window_hours,
        )
        if self._log_store:
            raw = await self._log_store.query(
                window_hours=time_window_hours,
            )
            events = [AttackEvent(**e) for e in (raw or [])]
        else:
            events = list(self._events)

        return events

    async def load_active_rules(self) -> list[WAFRule]:
        """Load current active WAF rules."""
        logger.info("waf_manager.load_rules")
        if self._waf_client:
            raw = await self._waf_client.list_rules()
            return [WAFRule(**r) for r in (raw or [])]
        return list(self._rules.values())

    async def analyze_attack_patterns(
        self,
        events: list[AttackEvent],
    ) -> dict[str, Any]:
        """Analyze attack events for patterns and trends."""
        logger.info(
            "waf_manager.analyze_patterns",
            event_count=len(events),
        )
        category_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for ev in events:
            cat = ev.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1
            source_counts[ev.source_ip] = source_counts.get(ev.source_ip, 0) + 1
            sev = ev.severity
            if sev in severity_counts:
                severity_counts[sev] += 1

        top_sources = sorted(
            source_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        return {
            "total_events": len(events),
            "category_distribution": category_counts,
            "severity_distribution": severity_counts,
            "top_sources": [{"ip": ip, "count": c} for ip, c in top_sources],
            "unique_sources": len(source_counts),
            "timestamp": time.time(),
        }

    async def evaluate_owasp_coverage(
        self,
        rules: list[WAFRule],
    ) -> list[CoverageGap]:
        """Evaluate WAF rule coverage against OWASP Top 10."""
        logger.info(
            "waf_manager.evaluate_coverage",
            rule_count=len(rules),
        )
        rule_categories = {r.category for r in rules if r.enabled}
        gaps: list[CoverageGap] = []

        for owasp in _OWASP_TOP_10:
            mapped = _OWASP_CATEGORY_MAP.get(owasp["id"], [])
            covered_cats = [c for c in mapped if c in rule_categories]
            rule_count = sum(1 for r in rules if r.enabled and r.category in mapped)
            is_covered = len(covered_cats) > 0 or len(mapped) == 0

            if not is_covered:
                gaps.append(
                    CoverageGap(
                        owasp_id=owasp["id"],
                        owasp_name=owasp["name"],
                        covered=False,
                        rule_count=rule_count,
                        gap_description=(f"No active rules for {owasp['name']}"),
                        recommended_rules=[f"Add {c.value} detection rule" for c in mapped],
                        severity="high",
                    )
                )
            else:
                gaps.append(
                    CoverageGap(
                        owasp_id=owasp["id"],
                        owasp_name=owasp["name"],
                        covered=True,
                        rule_count=rule_count,
                        gap_description="",
                        severity="low",
                    )
                )

        return gaps

    async def detect_false_positives(
        self,
        events: list[AttackEvent],
        rules: list[WAFRule],
    ) -> list[AttackEvent]:
        """Identify likely false positive events."""
        logger.info("waf_manager.detect_fps", event_count=len(events))
        fps: list[AttackEvent] = []
        rule_map = {r.rule_id: r for r in rules}

        for ev in events:
            rule = rule_map.get(ev.matched_rule_id)
            is_fp = (rule and rule.false_positive_rate > _FP_RATE_THRESHOLD) or (
                ev.risk_score < 0.2 and ev.action_taken == RuleAction.BLOCK
            )
            if is_fp:
                fp_event = ev.model_copy()
                fp_event.is_false_positive = True
                fps.append(fp_event)

        return fps

    async def propose_rule_tuning(
        self,
        rules: list[WAFRule],
        attack_summary: dict[str, Any],
        false_positives: list[AttackEvent],
    ) -> list[dict[str, Any]]:
        """Propose rule tuning based on analysis."""
        logger.info("waf_manager.propose_tuning")
        proposals: list[dict[str, Any]] = []

        for rule in rules:
            if rule.false_positive_rate > _FP_RATE_THRESHOLD:
                proposals.append(
                    {
                        "rule_id": rule.rule_id,
                        "action": "relax",
                        "reason": (f"FP rate {rule.false_positive_rate:.1%} exceeds threshold"),
                        "suggestion": "Add path/user-agent exclusions",
                    }
                )
            elif rule.hit_count == 0 and rule.enabled:
                proposals.append(
                    {
                        "rule_id": rule.rule_id,
                        "action": "review",
                        "reason": "No hits — verify rule is effective",
                        "suggestion": "Check pattern matches traffic",
                    }
                )

        cat_dist = attack_summary.get("category_distribution", {})
        for cat, count in cat_dist.items():
            matching = [r for r in rules if r.category.value == cat and r.enabled]
            if count > 50 and len(matching) < 2:
                proposals.append(
                    {
                        "rule_id": "new",
                        "action": "create",
                        "reason": (
                            f"High {cat} volume ({count}) with only {len(matching)} rule(s)"
                        ),
                        "suggestion": f"Add additional {cat} rules",
                    }
                )

        return proposals

    async def auto_block_sources(
        self,
        attack_summary: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Auto-block IPs exceeding attack thresholds."""
        logger.info("waf_manager.auto_block")
        blocked: list[dict[str, Any]] = []
        top_sources = attack_summary.get("top_sources", [])

        for src in top_sources:
            ip = src.get("ip", "")
            count = src.get("count", 0)
            if count >= _AUTO_BLOCK_THRESHOLD and ip not in self._blocked_ips:
                self._blocked_ips.add(ip)
                blocked.append(
                    {
                        "ip": ip,
                        "event_count": count,
                        "action": RuleAction.BLOCK.value,
                        "reason": (
                            f"Exceeded threshold: {count} attacks (limit {_AUTO_BLOCK_THRESHOLD})"
                        ),
                        "timestamp": time.time(),
                    }
                )
                if self._waf_client:
                    await self._waf_client.block_ip(ip)

        return blocked

    def add_event(self, event: AttackEvent) -> None:
        """Add an attack event for analysis (testing helper)."""
        self._events.append(event)
        if len(self._events) > 50000:
            self._events = self._events[-50000:]

    def add_rule(self, rule: WAFRule) -> None:
        """Add a WAF rule (testing helper)."""
        self._rules[rule.rule_id] = rule
