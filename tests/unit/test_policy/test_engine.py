"""Tests for the policy evaluation engine — three-tier decision logic."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from shieldops.policy.blast_radius import BlastRadiusResult
from shieldops.policy.engine import (
    Decision,
    PolicyContext,
    evaluate,
)


def _ctx(risk_score: float = 0.0, **overrides: object) -> PolicyContext:
    """Build a minimal PolicyContext for testing."""
    defaults: dict[str, object] = {
        "agent_name": "test-agent",
        "action_type": "restart_service",
        "target_resources": ["svc-a"],
        "environment": "dev",
        "risk_score": risk_score,
        "org_id": "org-1",
    }
    defaults.update(overrides)
    return PolicyContext(**defaults)  # type: ignore[arg-type]


# A passing blast-radius result used by most tests
_BR_OK = BlastRadiusResult(allowed=True, resource_count=1, limit=10, environment="dev", reason="ok")

# An OPA result that doesn't deny
_OPA_ALLOW: dict[str, object] = {"deny": False, "matched_policies": ["p1"], "reason": ""}


@pytest.fixture(autouse=True)
def _patch_opa_and_br():
    """Patch OPA and blast-radius so unit tests don't need real services."""
    with (
        patch(
            "shieldops.policy.engine.query_opa",
            new_callable=AsyncMock,
            return_value=_OPA_ALLOW,
        ),
        patch(
            "shieldops.policy.engine.check_blast_radius",
            return_value=_BR_OK,
        ),
    ):
        yield


# ---------------------------------------------------------------------------
# Three-tier decision tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auto_approve_low_risk() -> None:
    decision = await evaluate("restart svc-a", _ctx(risk_score=0.2))
    assert decision.allowed is True
    assert decision.decision == Decision.APPROVED


@pytest.mark.asyncio
async def test_auto_approve_at_zero() -> None:
    decision = await evaluate("noop", _ctx(risk_score=0.0))
    assert decision.allowed is True
    assert decision.decision == Decision.APPROVED


@pytest.mark.asyncio
async def test_requires_approval_mid_risk() -> None:
    decision = await evaluate("scale down", _ctx(risk_score=0.6))
    assert decision.allowed is False
    assert decision.decision == Decision.REQUIRES_APPROVAL


@pytest.mark.asyncio
async def test_requires_approval_at_boundary_low() -> None:
    """Exactly 0.5 should require approval (>= 0.5)."""
    decision = await evaluate("scale down", _ctx(risk_score=0.5))
    assert decision.decision == Decision.REQUIRES_APPROVAL


@pytest.mark.asyncio
async def test_requires_approval_at_boundary_high() -> None:
    """Exactly 0.85 should still require approval (<= 0.85)."""
    decision = await evaluate("rotate creds", _ctx(risk_score=0.85))
    assert decision.decision == Decision.REQUIRES_APPROVAL


@pytest.mark.asyncio
async def test_denied_high_risk() -> None:
    decision = await evaluate("delete namespace", _ctx(risk_score=0.95))
    assert decision.allowed is False
    assert decision.decision == Decision.DENIED
    assert "exceeds" in decision.reason.lower()


@pytest.mark.asyncio
async def test_denied_at_risk_above_threshold() -> None:
    decision = await evaluate("drop table", _ctx(risk_score=0.86))
    assert decision.decision == Decision.DENIED


# ---------------------------------------------------------------------------
# Blast-radius denial
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_blast_radius_denial() -> None:
    br_fail = BlastRadiusResult(
        allowed=False,
        resource_count=15,
        limit=10,
        environment="dev",
        reason="Too many resources.",
    )
    with patch("shieldops.policy.engine.check_blast_radius", return_value=br_fail):
        decision = await evaluate("mass restart", _ctx(risk_score=0.1))
    assert decision.allowed is False
    assert decision.decision == Decision.DENIED
    assert decision.blast_radius == 15


# ---------------------------------------------------------------------------
# OPA deny
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_opa_deny_overrides_risk() -> None:
    opa_deny = {"deny": True, "matched_policies": ["no-delete"], "reason": "OPA says no."}
    with patch(
        "shieldops.policy.engine.query_opa",
        new_callable=AsyncMock,
        return_value=opa_deny,
    ):
        decision = await evaluate("delete db", _ctx(risk_score=0.1))
    assert decision.allowed is False
    assert decision.decision == Decision.DENIED
    assert "OPA" in decision.reason


@pytest.mark.asyncio
async def test_opa_unreachable_fail_closed() -> None:
    with patch(
        "shieldops.policy.engine.query_opa",
        new_callable=AsyncMock,
        side_effect=Exception("connection refused"),
    ):
        decision = await evaluate("do thing", _ctx(risk_score=0.1))
    assert decision.allowed is False
    assert decision.decision == Decision.DENIED


# ---------------------------------------------------------------------------
# Matched policies passthrough
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_matched_policies_included() -> None:
    decision = await evaluate("restart svc-a", _ctx(risk_score=0.2))
    assert "p1" in decision.matched_policies
