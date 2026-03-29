"""Tests for spam_filter_manager."""

from __future__ import annotations

from shieldops.agents.spam_filter_manager.models import (
    FilterAction,
    SpamCategory,
    SpamFilterManagerState,
    SpamStage,
)


class TestEnums:
    def test_filteraction(self) -> None:
        assert FilterAction.ALLOW == "allow"
        assert len(FilterAction) >= 3

    def test_spamcategory(self) -> None:
        assert SpamCategory.MARKETING == "marketing"
        assert len(SpamCategory) >= 3

    def test_spamstage(self) -> None:
        assert SpamStage.COLLECT_RULES == "collect_rules"
        assert len(SpamStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SpamFilterManagerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SpamFilterManagerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
