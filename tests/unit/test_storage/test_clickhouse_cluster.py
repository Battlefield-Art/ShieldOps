"""Unit tests for the ClickHouse HA cluster behavior of ``ClickHouseEventStore``.

Covers:
    * round-robin failover when the first host refuses connections
    * reconnection after ``_invalidate_client``
    * distributed table DDL generation (no live cluster required)
    * ``create_distributed_table`` requires a cluster name
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from shieldops.storage.clickhouse_backend import ClickHouseEventStore


class _FakeClient:
    """Minimal stand-in for ``clickhouse_connect`` client."""

    def __init__(self, host: str) -> None:
        self.host = host
        self.commands: list[str] = []
        self.closed = False

    def command(self, sql: str, parameters: Any = None) -> None:  # noqa: ARG002
        self.commands.append(sql)

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def patched_clickhouse_connect():
    """Patch ``clickhouse_connect`` with a controllable ``get_client`` factory."""
    with patch("shieldops.storage.clickhouse_backend.clickhouse_connect") as mock_module:
        yield mock_module


class TestClusterFailover:
    def test_round_robin_skips_failing_host(self, patched_clickhouse_connect):
        """First host raises ConnectionError → backend falls through to second host."""
        failing_host = "clickhouse-1.shieldops.internal"
        good_host = "clickhouse-2.shieldops.internal"

        def get_client_side_effect(**kwargs: Any) -> _FakeClient:
            if kwargs["host"] == failing_host:
                raise ConnectionError("connection refused")
            return _FakeClient(kwargs["host"])

        patched_clickhouse_connect.get_client.side_effect = get_client_side_effect

        store = ClickHouseEventStore(
            host=[failing_host, good_host, "clickhouse-3.shieldops.internal"],
            cluster_name="shieldops_cluster",
            skip_schema_init=True,
        )

        client = store._get_client()
        assert isinstance(client, _FakeClient)
        assert client.host == good_host

    def test_all_hosts_down_raises(self, patched_clickhouse_connect):
        """When every host refuses, _get_client raises RuntimeError."""
        patched_clickhouse_connect.get_client.side_effect = ConnectionError("nope")

        store = ClickHouseEventStore(
            host=["a", "b", "c"],
            cluster_name="shieldops_cluster",
            skip_schema_init=True,
        )

        with pytest.raises(RuntimeError, match="Failed to connect"):
            store._get_client()

    def test_invalidate_client_reconnects(self, patched_clickhouse_connect):
        """After _invalidate_client, a fresh client is created on next access."""
        patched_clickhouse_connect.get_client.side_effect = lambda **kw: _FakeClient(kw["host"])
        store = ClickHouseEventStore(
            host=["clickhouse-1", "clickhouse-2"],
            cluster_name="shieldops_cluster",
            skip_schema_init=True,
        )
        first = store._get_client()
        store._invalidate_client()
        assert first.closed is True

        second = store._get_client()
        assert second is not first

    def test_single_host_string_still_works(self, patched_clickhouse_connect):
        """Back-compat: passing host as a plain string still produces a valid client."""
        patched_clickhouse_connect.get_client.side_effect = lambda **kw: _FakeClient(kw["host"])
        store = ClickHouseEventStore(host="localhost", skip_schema_init=True)
        client = store._get_client()
        assert client.host == "localhost"


class TestDistributedTableSQL:
    def test_ddl_contains_cluster_and_sharding_key(self):
        sql = ClickHouseEventStore.get_distributed_table_ddl(
            cluster_name="shieldops_cluster",
            database="shieldops",
        )
        assert "shieldops_cluster" in sql
        assert "events_local" in sql
        assert "Distributed(shieldops_cluster, shieldops, events_local, rand())" in sql
        assert "ON CLUSTER shieldops_cluster" in sql

    def test_ddl_custom_sharding_key(self):
        sql = ClickHouseEventStore.get_distributed_table_ddl(
            cluster_name="shieldops_cluster",
            database="shieldops",
            sharding_key="cityHash64(org_id)",
        )
        assert "cityHash64(org_id)" in sql

    def test_create_distributed_table_requires_cluster_name(self, patched_clickhouse_connect):
        patched_clickhouse_connect.get_client.side_effect = lambda **kw: _FakeClient(kw["host"])
        store = ClickHouseEventStore(host="localhost", skip_schema_init=True)

        with pytest.raises(RuntimeError, match="cluster_name"):
            store.create_distributed_table()

    def test_create_distributed_table_executes_ddl(self, patched_clickhouse_connect):
        fake = _FakeClient("clickhouse-1")
        patched_clickhouse_connect.get_client.return_value = fake

        store = ClickHouseEventStore(
            host=["clickhouse-1"],
            cluster_name="shieldops_cluster",
            skip_schema_init=True,
        )
        sql = store.create_distributed_table()

        assert "Distributed(shieldops_cluster" in sql
        assert any("Distributed(shieldops_cluster" in cmd for cmd in fake.commands)
