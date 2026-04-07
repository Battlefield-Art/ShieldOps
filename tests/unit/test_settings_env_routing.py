"""Regression test: flat env vars must reach nested sub-configs.

Sub-configs (DatabaseConfig, RedisConfig, etc.) are plain ``BaseModel``,
not ``BaseSettings``, so without the explicit routing in
``Settings._route_flat_to_nested`` the ``SHIELDOPS_DATABASE_URL`` env var
is dropped and alembic falls back to the hard-coded default. CI test job
failed with ``database "shieldops" does not exist`` until this was fixed.
"""

from __future__ import annotations

import pytest

from shieldops.config.settings import Settings


class TestSettingsEnvRouting:
    def test_database_url_routed_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "SHIELDOPS_DATABASE_URL",
            "postgresql+asyncpg://u:p@h:5432/shieldops_test",
        )
        s = Settings()
        assert s.database.database_url == ("postgresql+asyncpg://u:p@h:5432/shieldops_test")

    def test_redis_url_routed_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SHIELDOPS_REDIS_URL", "redis://host:6379/7")
        s = Settings()
        assert s.redis.redis_url == "redis://host:6379/7"

    def test_unset_env_keeps_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SHIELDOPS_DATABASE_URL", raising=False)
        s = Settings()
        assert "shieldops" in s.database.database_url

    def test_flat_access_matches_nested(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "SHIELDOPS_DATABASE_URL",
            "postgresql+asyncpg://u:p@h:5432/flat_test",
        )
        s = Settings()
        # Backward-compat flat access path.
        assert s.database_url == s.database.database_url
        assert "flat_test" in s.database_url
