"""Tests for blast-radius enforcement per environment."""

from __future__ import annotations

from shieldops.policy.blast_radius import (
    BLAST_RADIUS_LIMITS,
    check_blast_radius,
)


def _resources(n: int) -> list[str]:
    return [f"resource-{i}" for i in range(n)]


def test_dev_within_limit() -> None:
    result = check_blast_radius("dev", _resources(10))
    assert result.allowed is True
    assert result.limit == 10


def test_dev_over_limit() -> None:
    result = check_blast_radius("dev", _resources(11))
    assert result.allowed is False
    assert result.resource_count == 11


def test_staging_within_limit() -> None:
    result = check_blast_radius("staging", _resources(5))
    assert result.allowed is True
    assert result.limit == 5


def test_staging_over_limit() -> None:
    result = check_blast_radius("staging", _resources(6))
    assert result.allowed is False


def test_prod_within_limit() -> None:
    result = check_blast_radius("prod", _resources(3))
    assert result.allowed is True
    assert result.limit == 3


def test_prod_over_limit() -> None:
    result = check_blast_radius("prod", _resources(4))
    assert result.allowed is False
    assert "4 resources" in result.reason


def test_empty_resources_always_allowed() -> None:
    for env in ("dev", "staging", "prod"):
        result = check_blast_radius(env, [])
        assert result.allowed is True


def test_unknown_environment_uses_strictest_limit() -> None:
    result = check_blast_radius("mystery", _resources(4))
    assert result.allowed is False
    assert result.limit == 3  # DEFAULT_LIMIT


def test_case_insensitive_environment() -> None:
    result = check_blast_radius("PROD", _resources(3))
    assert result.allowed is True


def test_limits_match_constants() -> None:
    assert BLAST_RADIUS_LIMITS == {"dev": 10, "staging": 5, "prod": 3}
