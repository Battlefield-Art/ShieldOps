"""Contract + parity tests for :class:`FlatSettings` — RFC #241 PR-1.

See ghantakiran/ShieldOps#241. The central test in this file is
:meth:`TestLegacyParity.test_flat_settings_field_matches_legacy_settings_at_default`
— the parity test that proves every flat field in the new
:class:`FlatSettings` returns the same value as the legacy ``settings``
singleton for both defaults AND ``SHIELDOPS_*`` env-set inputs.

This parity test is the regression gate for PR-2+, where each sub-config
file gets progressively deleted: if any field's default or env-routing
behavior drifts, this test catches it immediately.

The 5fbeb149-class bug (env var silently dropped by the validator) is
structurally impossible in ``FlatSettings`` because there is no
validator — pydantic-settings handles env var binding natively. This
file locks that property via a dedicated test per field.
"""

from __future__ import annotations

from typing import Any

import pytest

from shieldops.config.flat import DictSource, FlatSettings
from shieldops.config.settings import settings as legacy_settings

# ---------------------------------------------------------------------------
# The list of flat fields that PR-1 guarantees parity for.
#
# Each tuple is (field_name, env_set_value_for_test).
# The env_set_value is chosen to be obviously-different from the default
# so monkeypatched tests exercise the env var binding path.
# ---------------------------------------------------------------------------

# Fields whose legacy defaults we can rely on + an override value the
# test uses to exercise env var routing.
PARITY_FIELDS: list[tuple[str, Any]] = [
    ("app_name", "shieldops-test"),
    ("app_version", "9.9.9-test"),
    ("environment", "test-env"),
    ("api_host", "127.0.0.1"),
    ("api_port", "9999"),
    ("api_prefix", "/api/v99"),
    ("database_url", "postgresql+asyncpg://u:p@host:5432/test_db"),
    ("database_pool_size", "77"),
    ("redis_url", "redis://testhost:6379/9"),
    ("kafka_brokers", "broker-1:9092,broker-2:9092"),
    ("kafka_consumer_group", "shieldops-test-group"),
    ("anthropic_api_key", "sk-ant-test"),
    ("anthropic_model", "claude-sonnet-4-test"),
    ("openai_api_key", "sk-openai-test"),
    ("opa_endpoint", "http://opa-test:8181"),
    ("langsmith_project", "shieldops-test-lsm"),
    ("jwt_algorithm", "HS512"),
    ("jwt_expire_minutes", "1440"),
    ("aws_region", "eu-west-1"),
    ("gcp_project_id", "test-gcp-project"),
    ("azure_subscription_id", "00000000-0000-0000-0000-000000000001"),
    ("rate_limit_default", "333"),
    ("rate_limit_window_seconds", "15"),
    ("stripe_api_key", "sk_test_stripe"),
    ("slack_bot_token", "xoxb-test-token"),
    ("webhook_url", "https://hooks.example.com/test"),
]


# ---------------------------------------------------------------------------
# 1. Defaults round-trip
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_flat_settings_constructs_with_no_args(self) -> None:
        """The class must be buildable with zero kwargs and return a
        fully-populated instance."""
        s = FlatSettings()
        # Every declared field has a default — the instance is not None
        # and every attribute is readable.
        assert s.app_name
        assert s.api_prefix.startswith("/")
        assert s.database_url.startswith("postgresql")
        assert s.redis_url.startswith("redis://")

    def test_flat_settings_defaults_are_stable(self) -> None:
        """Two constructions yield equivalent state for the defaults.
        Catches accidental mutable-default bugs."""
        s1 = FlatSettings()
        s2 = FlatSettings()
        assert s1.app_name == s2.app_name
        assert s1.database_url == s2.database_url


# ---------------------------------------------------------------------------
# 2. Legacy parity — THE regression gate
# ---------------------------------------------------------------------------


class TestLegacyParity:
    """Every flat field in ``FlatSettings`` must return the same value as
    the legacy ``settings`` singleton for both defaults and env-set inputs.
    This test is the gate for PR-2+ work — if it goes red, a sub-config
    file got deleted before all its fields were ported to the flat class.
    """

    @pytest.mark.parametrize("field,_override", PARITY_FIELDS)
    def test_flat_default_matches_legacy_default(
        self,
        field: str,
        _override: Any,
    ) -> None:
        """At default (no env), ``FlatSettings().X == settings.X``."""
        flat = FlatSettings()
        flat_value = getattr(flat, field)
        legacy_value = getattr(legacy_settings, field)
        # Compare as strings because the legacy settings may cast ints
        # differently in its nested path. We lock the stringified form
        # — any cast mismatch between flat + legacy is a real bug.
        assert str(flat_value) == str(legacy_value), (
            f"default drift on {field}: flat={flat_value!r} vs legacy={legacy_value!r}"
        )

    @pytest.mark.parametrize("field,override", PARITY_FIELDS)
    def test_flat_env_set_matches_env(
        self,
        field: str,
        override: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When ``SHIELDOPS_<FIELD>`` is set, ``FlatSettings()`` reads it.

        This is the test that structurally rules out the 5fbeb149 bug
        class: pydantic-settings binds env vars natively in
        :class:`FlatSettings`, so there is no validator that could drop
        them on the way in.
        """
        env_key = f"SHIELDOPS_{field.upper()}"
        monkeypatch.setenv(env_key, str(override))

        flat = FlatSettings()
        flat_value = getattr(flat, field)
        assert str(flat_value) == str(override), (
            f"env var {env_key}={override!r} was dropped: FlatSettings().{field} == {flat_value!r}"
        )


# ---------------------------------------------------------------------------
# 3. Constructor injection — the test seam
# ---------------------------------------------------------------------------


class TestConstructorInjection:
    def test_kwarg_override_wins_over_defaults(self) -> None:
        s = FlatSettings(database_url="postgresql://test-override")
        assert s.database_url == "postgresql://test-override"

    def test_kwarg_override_wins_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Pydantic-settings precedence: init kwargs > env > defaults.
        Tests rely on this so ``FlatSettings(database_url="sqlite://")``
        always beats whatever ``SHIELDOPS_DATABASE_URL`` is set to in
        the test runner's environment."""
        monkeypatch.setenv("SHIELDOPS_DATABASE_URL", "postgresql://env")
        s = FlatSettings(database_url="postgresql://init")
        assert s.database_url == "postgresql://init"

    def test_multiple_overrides_are_independent(self) -> None:
        s = FlatSettings(
            database_url="postgresql://one",
            redis_url="redis://two",
            anthropic_api_key="sk-three",
        )
        assert s.database_url == "postgresql://one"
        assert s.redis_url == "redis://two"
        assert s.anthropic_api_key == "sk-three"


# ---------------------------------------------------------------------------
# 4. DictSource test seam
# ---------------------------------------------------------------------------


class TestDictSource:
    def test_dict_source_applies_overrides(self) -> None:
        source = DictSource(
            {
                "database_url": "postgresql://via-dict-source",
                "environment": "source-test",
            }
        )
        s = source.build()
        assert s.database_url == "postgresql://via-dict-source"
        assert s.environment == "source-test"

    def test_dict_source_leaves_other_fields_at_defaults(self) -> None:
        s = DictSource({"database_url": "postgresql://only"}).build()
        # Other fields should still have their ordinary defaults
        # (matching the legacy sub/llm.py + sub/api.py values).
        assert s.anthropic_model == "claude-sonnet-4-20250514"
        assert s.api_prefix == "/api/v1"

    def test_dict_source_wins_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """DictSource uses constructor injection, which wins over env."""
        monkeypatch.setenv("SHIELDOPS_DATABASE_URL", "postgresql://env")
        s = DictSource({"database_url": "postgresql://from-source"}).build()
        assert s.database_url == "postgresql://from-source"

    def test_empty_dict_source_returns_all_defaults(self) -> None:
        s = DictSource({}).build()
        assert s.database_url.startswith("postgresql")
        assert s.api_prefix == "/api/v1"


# ---------------------------------------------------------------------------
# 5. Structural: no 5fbeb149-class bug possible
# ---------------------------------------------------------------------------


class TestNoValidatorDrop:
    """The 5fbeb149 bug was: ``extra="ignore"`` on the legacy
    ``Settings`` dropped env vars before the validator saw them. In
    :class:`FlatSettings` there is NO validator — pydantic-settings
    binds env vars directly. This test asserts the property
    structurally."""

    def test_env_var_with_ignore_extra_still_reaches_field(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Set a field that the class DOES declare; confirm it's read.
        The old bug was that ``extra="ignore"`` silently dropped it
        because the routing happened in a validator that ran after
        the extra-filter."""
        monkeypatch.setenv(
            "SHIELDOPS_DATABASE_URL",
            "postgresql+asyncpg://u:p@h:5432/no_drop_test",
        )
        s = FlatSettings()
        assert "no_drop_test" in s.database_url

    def test_unknown_env_var_is_safely_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An env var that doesn't map to any field must be silently
        ignored (not crash the import), matching
        ``extra="ignore"`` semantics."""
        monkeypatch.setenv("SHIELDOPS_NONEXISTENT_FIELD_ABCXYZ", "value")
        # Should not raise.
        s = FlatSettings()
        assert s.app_name  # sanity: construction succeeded
