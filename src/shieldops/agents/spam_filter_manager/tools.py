"""Spam Filter Manager Agent — Tool functions."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .models import (
    ClassificationResult,
    FilterAction,
    SpamCategory,
    SpamRule,
)

logger = structlog.get_logger()

# Spam scoring keywords
SPAM_KEYWORDS: dict[str, float] = {
    "viagra": 8.0,
    "lottery": 7.0,
    "winner": 6.0,
    "free money": 7.5,
    "click here": 3.0,
    "unsubscribe": 1.0,
    "limited offer": 4.0,
    "act now": 4.5,
    "guaranteed": 3.5,
    "no obligation": 4.0,
    "risk free": 3.5,
    "buy now": 3.0,
    "special promotion": 3.5,
    "congratulations": 4.0,
    "dear friend": 5.0,
    "wire transfer": 6.0,
    "nigerian prince": 9.0,
    "inheritance": 5.5,
}

# Legitimate sender patterns
LEGITIMATE_PATTERNS = [
    "noreply@",
    "notifications@",
    "updates@",
    "billing@",
    "support@",
    "team@",
    "admin@",
]


def _gen_id() -> str:
    return str(uuid.uuid4())[:12]


class SpamFilterManagerToolkit:
    """Tools for spam filter management."""

    def __init__(
        self,
        filter_client: Any | None = None,
        quarantine_client: Any | None = None,
    ) -> None:
        self._filter = filter_client
        self._quarantine = quarantine_client

    async def collect_rules(
        self,
        tenant_id: str,
    ) -> list[SpamRule]:
        """Collect current spam filter rules."""
        logger.info(
            "spam_filter.collect_rules",
            tenant_id=tenant_id,
        )
        if self._filter:
            try:
                raw = await self._filter.get_rules(tenant_id)
                return [SpamRule(**r) for r in raw]
            except Exception:
                logger.debug("spam_filter.rules_fallback")

        # Simulated rules
        rules = [
            SpamRule(
                id=_gen_id(),
                name="keyword_viagra",
                pattern="viagra|cialis|pharmacy",
                category=SpamCategory.SCAM,
                action=FilterAction.REJECT,
                score_threshold=7.0,
                hit_count=1234,
                false_positive_rate=0.01,
            ),
            SpamRule(
                id=_gen_id(),
                name="bulk_marketing",
                pattern="unsubscribe.*click here",
                category=SpamCategory.MARKETING,
                action=FilterAction.TAG,
                score_threshold=4.0,
                hit_count=5678,
                false_positive_rate=0.08,
            ),
            SpamRule(
                id=_gen_id(),
                name="lottery_scam",
                pattern="lottery|winner|prize",
                category=SpamCategory.SCAM,
                action=FilterAction.QUARANTINE,
                score_threshold=6.0,
                hit_count=890,
                false_positive_rate=0.02,
            ),
            SpamRule(
                id=_gen_id(),
                name="newsletter_filter",
                pattern="newsletter|weekly digest",
                category=SpamCategory.NEWSLETTER,
                action=FilterAction.TAG,
                score_threshold=3.0,
                hit_count=3456,
                false_positive_rate=0.12,
            ),
            SpamRule(
                id=_gen_id(),
                name="phishing_pattern",
                pattern="verify.*account|confirm.*identity",
                category=SpamCategory.PHISHING,
                action=FilterAction.QUARANTINE,
                score_threshold=5.5,
                hit_count=456,
                false_positive_rate=0.03,
            ),
        ]
        return rules

    async def classify_messages(
        self,
        rules: list[SpamRule],
        messages: list[dict[str, Any]] | None = None,
    ) -> tuple[list[ClassificationResult], int]:
        """Classify messages using rules."""
        logger.info(
            "spam_filter.classify_messages",
            rule_count=len(rules),
        )
        messages = messages or self._sample_messages()
        results: list[ClassificationResult] = []
        spam_count = 0

        for msg in messages:
            text = (f"{msg.get('subject', '')} {msg.get('body', '')}").lower()
            sender = msg.get("from", "").lower()

            score = 0.0
            matched: list[str] = []
            category = SpamCategory.LEGITIMATE

            # Keyword scoring
            for kw, pts in SPAM_KEYWORDS.items():
                if kw in text:
                    score += pts
                    matched.append(f"keyword:{kw}")

            # Rule matching (simplified)
            for rule in rules:
                if not rule.enabled:
                    continue
                pattern_parts = rule.pattern.split("|")
                if any(p.lower() in text for p in pattern_parts):
                    matched.append(rule.name)
                    if rule.category != SpamCategory.LEGITIMATE:
                        category = rule.category
                    score += rule.score_threshold * 0.5

            # Legitimate sender check
            is_legit = any(pat in sender for pat in LEGITIMATE_PATTERNS)
            if is_legit and score < 8:
                score *= 0.5

            # Determine action
            if score >= 8.0:
                action = FilterAction.REJECT
            elif score >= 5.0:
                action = FilterAction.QUARANTINE
            elif score >= 3.0:
                action = FilterAction.TAG
            else:
                action = FilterAction.ALLOW
                category = SpamCategory.LEGITIMATE

            confidence = min(score / 10.0, 1.0)

            result = ClassificationResult(
                message_id=msg.get("id", _gen_id()),
                sender=msg.get("from", ""),
                subject=msg.get("subject", ""),
                category=category,
                spam_score=round(score, 2),
                action_taken=action,
                matched_rules=matched,
                confidence=round(confidence, 4),
            )
            results.append(result)
            if category != SpamCategory.LEGITIMATE:
                spam_count += 1

        return results, spam_count

    async def tune_filters(
        self,
        rules: list[SpamRule],
        classifications: list[ClassificationResult],
    ) -> list[dict[str, Any]]:
        """Generate filter tuning suggestions."""
        logger.info(
            "spam_filter.tune_filters",
            rule_count=len(rules),
        )
        suggestions: list[dict[str, Any]] = []

        for rule in rules:
            if rule.false_positive_rate > 0.05:
                suggestions.append(
                    {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "type": "raise_threshold",
                        "current": rule.score_threshold,
                        "recommended": round(rule.score_threshold + 1.5, 1),
                        "reason": (f"FP rate {rule.false_positive_rate:.1%} exceeds 5% threshold"),
                    }
                )

            if rule.hit_count == 0 and rule.enabled:
                suggestions.append(
                    {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "type": "review_disable",
                        "reason": "No hits; consider disabling",
                    }
                )

        # Check for missed spam
        missed = [
            c
            for c in classifications
            if c.spam_score > 3 and c.spam_score < 5 and c.action_taken == FilterAction.ALLOW
        ]
        if missed:
            suggestions.append(
                {
                    "rule_id": "new",
                    "rule_name": "borderline_spam",
                    "type": "new_rule",
                    "reason": (f"{len(missed)} borderline messages may need stricter rules"),
                }
            )

        return suggestions

    async def analyze_false_positives(
        self,
        classifications: list[ClassificationResult],
    ) -> tuple[list[dict[str, Any]], float]:
        """Analyze false positive patterns."""
        logger.info("spam_filter.analyze_fps")
        fps: list[dict[str, Any]] = []

        # Simulated FP detection
        for cls in classifications:
            is_fp = False
            sender = cls.sender.lower()

            is_fp_candidate = cls.action_taken != FilterAction.ALLOW and (
                any(p in sender for p in LEGITIMATE_PATTERNS)
                or (cls.spam_score < 6 and cls.confidence < 0.5)
            )
            if is_fp_candidate:
                is_fp = True

            if is_fp:
                fps.append(
                    {
                        "message_id": cls.message_id,
                        "sender": cls.sender,
                        "subject": cls.subject,
                        "action": cls.action_taken.value,
                        "score": cls.spam_score,
                        "matched_rules": cls.matched_rules,
                    }
                )
                cls.is_false_positive = True

        total = max(len(classifications), 1)
        fp_rate = round(len(fps) / total, 4)
        return fps, fp_rate

    async def manage_quarantine(
        self,
        classifications: list[ClassificationResult],
    ) -> tuple[list[dict[str, Any]], int]:
        """Manage quarantined messages."""
        logger.info("spam_filter.manage_quarantine")
        quarantined: list[dict[str, Any]] = []

        for cls in classifications:
            if cls.action_taken == FilterAction.QUARANTINE:
                quarantined.append(
                    {
                        "message_id": cls.message_id,
                        "sender": cls.sender,
                        "subject": cls.subject,
                        "category": cls.category.value,
                        "score": cls.spam_score,
                        "quarantined_at": time.time(),
                        "auto_release": cls.is_false_positive,
                    }
                )

        return quarantined, len(quarantined)

    @staticmethod
    def _sample_messages() -> list[dict[str, Any]]:
        return [
            {
                "id": "msg-001",
                "from": "prince@nigeria.ng",
                "subject": "You are a lottery winner!",
                "body": "Dear friend, congratulations on winning.",
            },
            {
                "id": "msg-002",
                "from": "noreply@company.com",
                "subject": "Your monthly invoice",
                "body": "Please find attached invoice.",
            },
            {
                "id": "msg-003",
                "from": "deals@marketing.com",
                "subject": "Limited offer - buy now!",
                "body": ("Special promotion, act now. Click here to unsubscribe."),
            },
            {
                "id": "msg-004",
                "from": "support@bank.com",
                "subject": "Verify your account",
                "body": ("Please confirm your identity to avoid suspension."),
            },
        ]
