"""FlatSettings — PR-1 of RFC #241.

See ghantakiran/ShieldOps#241. This module introduces a **flat**
``pydantic_settings.BaseSettings`` class alongside the existing
2,926-LOC ``settings.py`` without deleting anything. The goal is to
prove the pattern in PR-1 and let the parity test lock it in; PR-2+
progressively expands the field set and eventually deletes the
``_FLAT_TO_NESTED`` registry.

Why this matters:
- The existing ``Settings`` class has a 1,979-entry hand-maintained
  ``_FLAT_TO_NESTED`` dict that routes env vars into 16 plain
  ``BaseModel`` sub-configs. We recently had a real bug (commit
  ``5fbeb149``) because ``extra="ignore"`` was silently dropping env
  vars before the validator saw them.
- ``FlatSettings`` stops fighting pydantic-settings and uses it natively.
  Each field declares its own ``SHIELDOPS_*`` env alias; env var routing
  is handled by pydantic-settings itself — there is no validator, no
  registry, and no "which file drops the env var" footgun.
- The 30 fields chosen for PR-1 are the most-used ones across the
  codebase (see ``grep -rho 'settings\\.\\w\\+' src/shieldops`` — the
  top results are `api_prefix`, `redis_url`, `environment`,
  `database_url`, `opa_endpoint`, `app_version`, `jwt_expire_minutes`,
  and the cloud identifiers).

PR-2+ work:
- Expand the field set to cover all 1,979 entries in ``_FLAT_TO_NESTED``
  (mechanical via a one-shot script).
- Add grouped views (``DatabaseView``, etc.) that forward to the flat
  fields, so code written against ``settings.database.database_url``
  keeps working.
- Delete ``_FLAT_TO_NESTED`` + the validator + the sub-config files.
- Migrate ``alembic/env.py`` + any remaining direct readers.

**Zero caller changes in PR-1.** Every consumer still goes through the
existing ``settings`` singleton. This module is additive.
"""

from __future__ import annotations

from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict


class FlatSettings(BaseSettings):
    """Flat pydantic-settings class — one field per line, alphabetized.

    Every field reads from its corresponding ``SHIELDOPS_<UPPER_NAME>``
    environment variable natively via pydantic-settings. No validator
    injection, no registry, no dual-path import dance.
    """

    model_config = SettingsConfigDict(
        env_prefix="SHIELDOPS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ────────────────────────────────────────────────────────────
    # NOTE: every default here MUST match the corresponding legacy sub-config
    # field. The parity test in tests/unit/config/test_flat_settings.py is
    # the regression gate — drift here is a bug that will block PR-2.
    app_name: str = "ShieldOps"
    app_version: str = "0.1.0"
    debug: bool = False
    environment: str = "development"

    # ── API ────────────────────────────────────────────────────────────
    api_host: str = "0.0.0.0"  # noqa: S104  # nosec B104 — matches legacy sub/api.py
    api_port: int = 8000
    api_prefix: str = "/api/v1"

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

    # ── Policy + Observability ────────────────────────────────────────
    opa_endpoint: str = "http://localhost:8181"
    langsmith_api_key: str = ""
    langsmith_project: str = "shieldops"

    # ── Auth ───────────────────────────────────────────────────────────
    jwt_secret_key: str = "change-me-in-production"  # noqa: S105 — dev default
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # ── Cloud identifiers (commonly referenced) ───────────────────────
    aws_region: str = ""
    gcp_project_id: str = ""
    azure_subscription_id: str = ""

    # ── Rate limiting (the most-used knobs) ───────────────────────────
    rate_limit_enabled: bool = True
    rate_limit_default: int = 60
    rate_limit_window_seconds: int = 60

    # ── Billing ────────────────────────────────────────────────────────
    stripe_api_key: str = ""
    stripe_webhook_secret: str = ""  # noqa: S105 — empty dev default

    # ── Notifications ──────────────────────────────────────────────────
    slack_bot_token: str = ""
    webhook_url: str = ""


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

    PR-2 may promote this to a more flexible source-stack abstraction
    if multi-source (env + file + vault) support becomes a real
    requirement. For PR-1, the simple dict-override form is enough to
    prove the test seam.
    """

    def __init__(self, overrides: dict[str, Any]) -> None:
        self._overrides = dict(overrides)

    def build(self) -> FlatSettings:
        """Construct a FlatSettings with the overrides applied.

        Caller-supplied overrides win over both defaults and env vars,
        matching pydantic-settings's "init > env > defaults" precedence.
        """
        return FlatSettings(**self._overrides)
