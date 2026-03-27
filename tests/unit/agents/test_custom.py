"""Tests for shieldops.agents.custom — utility module."""

from __future__ import annotations


def test_custom_imports():
    from shieldops.agents.custom import builder

    assert builder is not None
