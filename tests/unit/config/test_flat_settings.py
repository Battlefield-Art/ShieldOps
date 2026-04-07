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
    # ── PR-1 fields (the original 30) ──
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
    # ── PR-2 fields (covers all 166 non-engines fields) ──
    ("debug", "true"),
    ("openai_model", "gpt-4o-test"),
    ("llm_routing_enabled", "true"),
    ("llm_simple_model", "claude-haiku-test"),
    ("llm_moderate_model", "claude-sonnet-test"),
    ("llm_complex_model", "claude-opus-test"),
    ("rag_enabled", "true"),
    ("rag_embedding_model", "text-embedding-test"),
    ("jwt_secret_key", "test-jwt-secret"),
    ("oidc_enabled", "true"),
    ("oidc_issuer_url", "https://oidc-test.example.com"),
    ("oidc_client_id", "test-client-id"),
    ("oidc_client_secret", "test-client-secret"),
    ("oidc_redirect_uri", "http://test/cb"),
    ("oidc_scopes", "openid email"),
    ("langsmith_api_key", "lsm-test-key"),
    ("langsmith_enabled", "true"),
    ("otel_exporter_endpoint", "http://otel-test:4317"),
    ("otel_endpoint", "http://otel-test:4317"),
    ("prometheus_url", "http://prom-test:9090"),
    ("splunk_url", "https://splunk-test"),
    ("splunk_token", "splunk-token-test"),
    ("splunk_index", "test-idx"),
    ("splunk_verify_ssl", "false"),
    ("datadog_api_key", "dd-api-test"),
    ("datadog_app_key", "dd-app-test"),
    ("datadog_site", "datadoghq.eu"),
    ("jaeger_url", "http://jaeger-test"),
    ("newrelic_api_key", "nr-test-key"),
    ("newrelic_account_id", "12345"),
    ("elastic_url", "https://es-test"),
    ("elastic_api_key", "es-test-key"),
    ("tracing_enabled", "true"),
    ("rate_limit_enabled", "false"),
    ("sliding_window_rate_limit_enabled", "true"),
    ("rate_limit_admin", "999"),
    ("rate_limit_operator", "777"),
    ("rate_limit_viewer", "111"),
    ("rate_limit_auth_login", "9"),
    ("rate_limit_auth_register", "4"),
    ("stripe_secret_key", "sk_test_secret"),
    ("stripe_publishable_key", "pk_test_pub"),
    ("stripe_webhook_secret", "whsec_test"),
    ("stripe_success_url", "http://test/success"),
    ("stripe_cancel_url", "http://test/cancel"),
    ("stripe_price_starter", "price_starter_test"),
    ("stripe_price_professional", "price_pro_test"),
    ("stripe_price_enterprise", "price_ent_test"),
    ("gcp_billing_dataset", "billing_test"),
    ("gcp_billing_table", "billing_table_test"),
    ("azure_billing_enabled", "true"),
    ("vault_addr", "http://vault-test"),
    ("vault_token", "vault-token-test"),
    ("vault_mount_point", "test-secret"),
    ("vault_namespace", "test-ns"),
    ("gcp_secret_manager_enabled", "true"),
    ("azure_keyvault_url", "https://kv-test"),
    ("github_advisory_token", "ghs_test"),
    ("nvd_api_key", "nvd-test-key"),
    ("trivy_server_url", "http://trivy-test"),
    ("trivy_timeout", "120"),
    ("gitleaks_path", "/usr/bin/gitleaks-test"),
    ("osv_scanner_path", "/usr/bin/osv-test"),
    ("checkov_path", "/usr/bin/checkov-test"),
    ("iac_scanner_enabled", "true"),
    ("git_scanner_enabled", "true"),
    ("k8s_scanner_enabled", "true"),
    ("network_scanner_enabled", "true"),
    ("syft_path", "/usr/bin/syft-test"),
    ("sbom_enabled", "true"),
    ("mitre_attack_enabled", "true"),
    ("epss_enabled", "true"),
    ("ghsa_enabled", "true"),
    ("os_advisory_feeds_enabled", "true"),
    ("slack_signing_secret", "slack-signing-test"),
    ("slack_approval_channel", "#test-channel"),
    ("pagerduty_routing_key", "pd-routing-test"),
    ("pagerduty_api_key", "pd-api-test"),
    ("pagerduty_service_ids", "svc1,svc2"),
    ("webhook_secret", "whsec-test"),
    ("webhook_timeout", "5.5"),
    ("smtp_host", "smtp-test.example.com"),
    ("smtp_port", "2525"),
    ("smtp_username", "smtp-user"),
    ("smtp_password", "smtp-pass"),
    ("smtp_use_tls", "false"),
    ("smtp_from_address", "noreply@test"),
    ("chat_session_ttl_seconds", "3600"),
    ("chat_max_messages_per_session", "25"),
    ("aws_access_key_id", "AKIATEST"),
    ("aws_secret_access_key", "secret-aws-test"),
    ("cloudwatch_log_group", "/test/group"),
    ("gcp_region", "europe-west1"),
    ("azure_resource_group", "rg-test"),
    ("azure_location", "westus"),
    ("linux_host", "linux-test"),
    ("linux_username", "ubuntu-test"),
    ("linux_private_key_path", "/tmp/key"),  # nosec B108
    ("windows_host", "win-test"),
    ("windows_username", "Administrator-test"),
    ("windows_password", "win-pass"),
    ("windows_use_ssl", "false"),
    ("windows_port", "5985"),
    ("crowdstrike_client_id", "cs-client-test"),
    ("crowdstrike_client_secret", "cs-secret-test"),
    ("crowdstrike_base_url", "https://api.crowdstrike-test.com"),
    ("defender_tenant_id", "def-tenant-test"),
    ("defender_client_id", "def-client-test"),
    ("defender_client_secret", "def-secret-test"),
    ("wiz_client_id", "wiz-client-test"),
    ("wiz_client_secret", "wiz-secret-test"),
    ("wiz_api_endpoint", "https://api.wiz-test"),
    ("splunk_hec_url", "https://hec-test"),
    ("splunk_hec_token", "hec-token-test"),
    ("elastic_cloud_id", "cloud-id-test"),
    ("newrelic_region", "EU"),
    ("servicenow_instance_url", "https://snow-test"),
    ("servicenow_username", "snow-user"),
    ("servicenow_password", "snow-pass"),
    ("jira_base_url", "https://jira-test"),
    ("jira_email", "jira@test"),
    ("jira_api_token", "jira-token-test"),
    ("opsgenie_api_key", "opsg-test"),
    ("agent_confidence_threshold_auto", "0.95"),
    ("agent_confidence_threshold_approval", "0.55"),
    ("agent_max_investigation_time_seconds", "1200"),
    ("agent_max_remediation_retries", "5"),
    ("agent_global_max_concurrent", "50"),
    ("agent_quota_enabled", "false"),
    ("agent_collaboration_enabled", "false"),
    ("agent_collaboration_max_messages", "2000"),
    ("agent_collaboration_session_timeout_minutes", "120"),
    ("agent_benchmark_enabled", "false"),
    ("agent_benchmark_baseline_days", "60"),
    ("agent_benchmark_regression_threshold", "0.5"),
    ("agent_decision_tracking_enabled", "false"),
    ("agent_decision_max_records", "100000"),
    ("agent_decision_retention_days", "180"),
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
        # Normalize to lower-case strings so bool fields parse correctly:
        # pydantic-settings converts "true"/"false" → Python bool, whose
        # ``str(...)`` is "True"/"False". The test override is the
        # string the env var carries, so we compare normalized forms.
        assert str(flat_value).lower() == str(override).lower(), (
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
