"""FlatSettings — RFC #241 PR-2 expansion.

See ghantakiran/ShieldOps#241. PR-1 introduced this module with ~30 of
the most-used fields proven against a parity test. PR-2 expands the field
set to cover **all 166 non-engines fields** declared in the legacy
``_FLAT_TO_NESTED`` registry, so the 15 non-engines sub-config files can
be deleted in PR-3 once their callers (if any) have been migrated.

The 1,820-LOC ``sub/engines.py`` is intentionally **not** migrated here
— it is Phase 3 of the RFC and gets its own incremental decomposition
into a ``views/engines/`` package over multiple small follow-up PRs.

Why this matters:
- The existing ``Settings`` class has a 1,979-entry hand-maintained
  ``_FLAT_TO_NESTED`` dict that routes env vars into 16 plain
  ``BaseModel`` sub-configs. We had a real production bug (commit
  ``5fbeb149``) because ``extra="ignore"`` was silently dropping env
  vars before the validator saw them.
- ``FlatSettings`` stops fighting pydantic-settings and uses it
  natively. Each field declares its own ``SHIELDOPS_*`` env alias; env
  var routing is handled by pydantic-settings itself — there is no
  validator, no registry, and no "which file drops the env var"
  footgun.

PR-3+ work:
- Delete the 15 non-engines sub-config files in ``sub/`` once the
  parity test for every field is green.
- Migrate ``alembic/env.py`` + any remaining direct readers off the
  legacy singleton.
- Begin Phase 3 ``engines.py`` decomposition.

**Zero caller changes in PR-2.** Every consumer still goes through the
existing ``settings`` singleton. This module remains additive until
PR-3 swaps the import in ``config/__init__.py``.
"""

from __future__ import annotations

from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict


class FlatSettings(BaseSettings):
    """Flat pydantic-settings class — one field per line, alphabetized.

    Every field reads from its corresponding ``SHIELDOPS_<UPPER_NAME>``
    environment variable natively via pydantic-settings. No validator
    injection, no registry, no dual-path import dance.

    NOTE: every default here MUST match the corresponding legacy
    sub-config field. The parity test in
    ``tests/unit/config/test_flat_settings.py`` is the regression gate
    — drift here is a bug that will block PR-3.
    """

    model_config = SettingsConfigDict(
        env_prefix="SHIELDOPS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ────────────────────────────────────────────────────────────
    app_name: str = "ShieldOps"
    app_version: str = "0.1.0"
    debug: bool = False
    environment: str = "development"

    # ── API ────────────────────────────────────────────────────────────
    api_host: str = "0.0.0.0"  # noqa: S104  # nosec B104 — matches legacy sub/api.py
    api_port: int = 8000
    api_prefix: str = "/api/v1"
    cors_origins: list[str] = ["http://localhost:3000"]

    # ── Database ───────────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://shieldops:shieldops@localhost:5432/shieldops"
    database_pool_size: int = 20

    # ── Redis ──────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Kafka ──────────────────────────────────────────────────────────
    kafka_brokers: str = "localhost:9092"
    kafka_consumer_group: str = "shieldops-agents"

    # ── LLM ────────────────────────────────────────────────────────────
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-20250514"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    llm_routing_enabled: bool = False
    llm_simple_model: str = "claude-haiku-4-5-20251001"
    llm_moderate_model: str = "claude-sonnet-4-20250514"
    llm_complex_model: str = "claude-opus-4-20250514"
    rag_enabled: bool = False
    rag_embedding_model: str = "text-embedding-3-small"

    # ── Auth ───────────────────────────────────────────────────────────
    jwt_secret_key: str = "change-me-in-production"  # noqa: S105 — dev default
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    oidc_enabled: bool = False
    oidc_issuer_url: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = "http://localhost:8000/api/v1/auth/oidc/callback"
    oidc_scopes: str = "openid email profile"

    # ── Observability ──────────────────────────────────────────────────
    langsmith_api_key: str = ""
    langsmith_project: str = "shieldops"
    langsmith_enabled: bool = False
    otel_exporter_endpoint: str = "http://localhost:4317"
    otel_endpoint: str = "http://localhost:4317"
    prometheus_url: str = "http://localhost:9090"
    splunk_url: str = ""
    splunk_token: str = ""  # noqa: S105 — empty dev default
    splunk_index: str = "main"
    splunk_verify_ssl: bool = True
    datadog_api_key: str = ""
    datadog_app_key: str = ""
    datadog_site: str = "datadoghq.com"
    jaeger_url: str = ""
    newrelic_api_key: str = ""
    newrelic_account_id: str = ""
    elastic_url: str = ""
    elastic_api_key: str = ""
    tracing_enabled: bool = False

    # ── Rate limiting ──────────────────────────────────────────────────
    rate_limit_enabled: bool = True
    rate_limit_window_seconds: int = 60
    sliding_window_rate_limit_enabled: bool = False
    rate_limit_admin: int = 300
    rate_limit_operator: int = 120
    rate_limit_viewer: int = 60
    rate_limit_default: int = 60
    rate_limit_auth_login: int = 10
    rate_limit_auth_register: int = 5
    # RFC #243 PR-3: flip PolicyMiddleware from shadow to enforce mode.
    # Default False — shadow mode is the safe rollout posture.
    policy_enforce: bool = False

    # ── Billing (Stripe + cloud) ───────────────────────────────────────
    stripe_secret_key: str = ""
    stripe_publishable_key: str = ""
    stripe_webhook_secret: str = ""  # noqa: S105 — empty dev default
    stripe_api_key: str = ""
    stripe_success_url: str = "http://localhost:5173/settings?billing=success"
    stripe_cancel_url: str = "http://localhost:5173/settings?billing=cancel"
    stripe_price_starter: str = ""
    stripe_price_professional: str = ""
    stripe_price_enterprise: str = ""
    gcp_billing_dataset: str = "billing_export"
    gcp_billing_table: str = "gcp_billing_export_v1"
    azure_billing_enabled: bool = False

    # ── Security / secret management ───────────────────────────────────
    vault_addr: str = ""
    vault_token: str = ""  # noqa: S105 — empty dev default
    vault_mount_point: str = "secret"  # noqa: S105
    vault_namespace: str = ""
    gcp_secret_manager_enabled: bool = False
    azure_keyvault_url: str = ""
    github_advisory_token: str = ""  # noqa: S105

    # ── Scanners ───────────────────────────────────────────────────────
    nvd_api_key: str = ""
    trivy_server_url: str = ""
    trivy_timeout: int = 300
    gitleaks_path: str = "gitleaks"
    osv_scanner_path: str = "osv-scanner"
    checkov_path: str = "checkov"
    iac_scanner_enabled: bool = False
    git_scanner_enabled: bool = False
    k8s_scanner_enabled: bool = False
    network_scanner_enabled: bool = False
    syft_path: str = "syft"
    sbom_enabled: bool = False
    mitre_attack_enabled: bool = False
    epss_enabled: bool = False
    ghsa_enabled: bool = False
    os_advisory_feeds_enabled: bool = False

    # ── Notifications ──────────────────────────────────────────────────
    slack_bot_token: str = ""  # noqa: S105
    slack_signing_secret: str = ""  # noqa: S105
    slack_approval_channel: str = "#shieldops-approvals"
    pagerduty_routing_key: str = ""
    pagerduty_api_key: str = ""  # noqa: S105
    pagerduty_service_ids: str = ""
    webhook_url: str = ""
    webhook_secret: str = ""  # noqa: S105
    webhook_timeout: float = 10.0
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""  # noqa: S105
    smtp_use_tls: bool = True
    smtp_from_address: str = "shieldops@localhost"
    smtp_to_addresses: list[str] = []
    chat_session_ttl_seconds: int = 86400
    chat_max_messages_per_session: int = 50

    # ── Connectors: AWS ────────────────────────────────────────────────
    aws_region: str = ""
    aws_access_key_id: str = ""  # noqa: S105
    aws_secret_access_key: str = ""  # noqa: S105
    cloudwatch_log_group: str = ""

    # ── Connectors: GCP ────────────────────────────────────────────────
    gcp_project_id: str = ""
    gcp_region: str = "us-central1"

    # ── Connectors: Azure ──────────────────────────────────────────────
    azure_subscription_id: str = ""
    azure_resource_group: str = ""
    azure_location: str = "eastus"

    # ── Connectors: OPA ────────────────────────────────────────────────
    opa_endpoint: str = "http://localhost:8181"

    # ── Connectors: Linux SSH ──────────────────────────────────────────
    linux_host: str = ""
    linux_username: str = ""
    linux_private_key_path: str = ""

    # ── Connectors: Windows WinRM ──────────────────────────────────────
    windows_host: str = ""
    windows_username: str = ""
    windows_password: str = ""  # noqa: S105
    windows_use_ssl: bool = True
    windows_port: int = 5986

    # ── Connectors: CrowdStrike ────────────────────────────────────────
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: str = ""  # noqa: S105
    crowdstrike_base_url: str = "https://api.crowdstrike.com"

    # ── Connectors: Microsoft Defender ─────────────────────────────────
    defender_tenant_id: str = ""
    defender_client_id: str = ""
    defender_client_secret: str = ""  # noqa: S105

    # ── Connectors: Wiz ────────────────────────────────────────────────
    wiz_client_id: str = ""
    wiz_client_secret: str = ""  # noqa: S105
    wiz_api_endpoint: str = "https://api.us1.app.wiz.io/graphql"

    # ── Connectors: Splunk HEC + Elastic + New Relic regional ──────────
    splunk_hec_url: str = ""
    splunk_hec_token: str = ""  # noqa: S105
    elastic_cloud_id: str = ""
    newrelic_region: str = "US"

    # ── Connectors: ServiceNow ─────────────────────────────────────────
    servicenow_instance_url: str = ""
    servicenow_username: str = ""
    servicenow_password: str = ""  # noqa: S105

    # ── Connectors: Jira ───────────────────────────────────────────────
    jira_base_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""  # noqa: S105

    # ── Connectors: OpsGenie ───────────────────────────────────────────
    opsgenie_api_key: str = ""  # noqa: S105

    # ── Agent orchestration ────────────────────────────────────────────
    agent_confidence_threshold_auto: float = 0.85
    agent_confidence_threshold_approval: float = 0.50
    agent_max_investigation_time_seconds: int = 600
    agent_max_remediation_retries: int = 3
    agent_global_max_concurrent: int = 20
    agent_quota_enabled: bool = True
    agent_collaboration_enabled: bool = True
    agent_collaboration_max_messages: int = 1000
    agent_collaboration_session_timeout_minutes: int = 60
    agent_benchmark_enabled: bool = True
    agent_benchmark_baseline_days: int = 30
    agent_benchmark_regression_threshold: float = 0.2
    agent_decision_tracking_enabled: bool = True
    agent_decision_max_records: int = 50000
    agent_decision_retention_days: int = 90


# ---------------------------------------------------------------------------
# DictSource — the test seam borrowed from Design B of RFC #241
# ---------------------------------------------------------------------------


class DictSource:
    """Build a :class:`FlatSettings` from an in-memory dict.

    PR-1 provides this as the test-seam substitute for
    ``monkeypatch.setenv`` ceremony. Tests that want to exercise a
    specific field override pass a dict and get a fully-constructed
    :class:`FlatSettings` instance back, with no environment mutation.

    Usage::

        s = DictSource({"database_url": "postgresql://test"}).build()
        assert s.database_url == "postgresql://test"

    PR-3 may promote this to a more flexible source-stack abstraction
    if multi-source (env + file + vault) support becomes a real
    requirement. For PR-1+PR-2, the simple dict-override form is
    enough to prove the test seam.
    """

    def __init__(self, overrides: dict[str, Any]) -> None:
        self._overrides = dict(overrides)

    def build(self) -> FlatSettings:
        """Construct a FlatSettings with the overrides applied.

        Caller-supplied overrides win over both defaults and env vars,
        matching pydantic-settings's "init > env > defaults" precedence.
        """
        return FlatSettings(**self._overrides)
