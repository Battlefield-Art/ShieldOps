"""Tests for security_data_lake."""

from __future__ import annotations

from shieldops.agents.security_data_lake.models import SecurityDataLakeState


def test_graph_compiles():
    from shieldops.agents.security_data_lake.graph import create_security_data_lake_graph

    assert create_security_data_lake_graph().compile() is not None


def test_state_defaults():
    s = SecurityDataLakeState(tenant_id="t")
    assert s.error == ""
