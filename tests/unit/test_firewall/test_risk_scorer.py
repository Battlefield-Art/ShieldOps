"""Tests for the firewall risk scorer."""

from __future__ import annotations

from datetime import UTC, datetime

from shieldops.firewall.risk_scorer import RiskScorer


class TestBuiltInProfiles:
    def setup_method(self) -> None:
        self.scorer = RiskScorer()

    def test_destructive_db_ops_high_risk(self) -> None:
        assert self.scorer.score("delete_database") >= 0.90
        assert self.scorer.score("drop_table") >= 0.90
        assert self.scorer.score("format_disk") >= 0.90

    def test_iam_modifications_high_risk(self) -> None:
        assert self.scorer.score("modify_iam_root") >= 0.85
        assert self.scorer.score("delete_iam_policy") >= 0.85

    def test_network_changes_medium_high_risk(self) -> None:
        score = self.scorer.score("modify_security_group")
        assert 0.70 <= score <= 0.95

    def test_read_only_low_risk(self) -> None:
        assert self.scorer.score("read_logs") <= 0.20
        assert self.scorer.score("list_buckets") <= 0.20
        assert self.scorer.score("describe_instances") <= 0.20
        assert self.scorer.score("get_config") <= 0.20

    def test_unknown_tool_moderate_risk(self) -> None:
        score = self.scorer.score("some_unknown_tool")
        assert 0.30 <= score <= 0.50


class TestArgumentSensitivity:
    def setup_method(self) -> None:
        self.scorer = RiskScorer()

    def test_sensitive_key_bumps_risk(self) -> None:
        base = self.scorer.score("read_config")
        bumped = self.scorer.score("read_config", arguments={"password": "hunter2"})
        assert bumped > base

    def test_sensitive_value_bumps_risk(self) -> None:
        base = self.scorer.score("read_config")
        bumped = self.scorer.score(
            "read_config",
            arguments={"data": "contains private_key material here"},
        )
        assert bumped > base

    def test_bump_capped(self) -> None:
        """Argument sensitivity bump should be capped at 0.30."""
        score = self.scorer.score(
            "read_config",
            arguments={
                "password": "x",
                "secret": "y",
                "token": "z",
                "api_key": "w",
            },
        )
        # base ~0.10 + cap 0.30 = 0.40 max
        assert score <= 0.50


class TestCustomProfiles:
    def test_custom_overrides_builtin(self) -> None:
        scorer = RiskScorer(custom_profiles={"read_*": 0.80})
        # Custom profile should override the built-in low-risk read_* profile
        assert scorer.score("read_logs") >= 0.70

    def test_custom_new_tool(self) -> None:
        scorer = RiskScorer(custom_profiles={"my_special_tool": 0.55})
        assert abs(scorer.score("my_special_tool") - 0.55) < 0.1


class TestCallerReputation:
    def test_trusted_caller_lowers_risk(self) -> None:
        scorer = RiskScorer(caller_reputations={"trusted-agent": -0.15})
        base = scorer.score("some_unknown_tool")
        adjusted = scorer.score("some_unknown_tool", caller_identity="trusted-agent")
        assert adjusted < base

    def test_risky_caller_raises_risk(self) -> None:
        scorer = RiskScorer(caller_reputations={"suspicious-agent": 0.20})
        base = scorer.score("read_logs")
        adjusted = scorer.score("read_logs", caller_identity="suspicious-agent")
        assert adjusted > base


class TestTimeAdjustment:
    def test_off_hours_boosts_risk(self) -> None:
        scorer = RiskScorer(off_hours_boost=0.10)
        weekday_noon = datetime(2026, 4, 7, 12, 0, tzinfo=UTC)  # Monday noon
        weekend = datetime(2026, 4, 5, 12, 0, tzinfo=UTC)  # Saturday noon
        score_weekday = scorer.score("read_logs", timestamp=weekday_noon)
        score_weekend = scorer.score("read_logs", timestamp=weekend)
        assert score_weekend > score_weekday

    def test_late_night_boosts_risk(self) -> None:
        scorer = RiskScorer(off_hours_boost=0.10)
        noon = datetime(2026, 4, 7, 12, 0, tzinfo=UTC)
        midnight = datetime(2026, 4, 7, 2, 0, tzinfo=UTC)
        assert scorer.score("read_logs", timestamp=midnight) > scorer.score(
            "read_logs", timestamp=noon
        )
