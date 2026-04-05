"""Tests for the shared OPA policy gate."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from shieldops.agents.policy_gate import check_policy


class TestPolicyAllowed:
    @pytest.mark.asyncio
    async def test_allowed_when_policy_allows(self) -> None:
        engine = AsyncMock()
        engine.evaluate = AsyncMock(return_value=SimpleNamespace(allowed=True, reasons=[]))
        result = await check_policy(engine, "investigation", "query_logs")
        assert result["allowed"] is True
        assert result["reasons"] == []

    @pytest.mark.asyncio
    async def test_denied_when_policy_denies(self) -> None:
        engine = AsyncMock()
        engine.evaluate = AsyncMock(
            return_value=SimpleNamespace(allowed=False, reasons=["blast_radius_exceeded"])
        )
        result = await check_policy(engine, "remediation", "contain", risk_score=0.9)
        assert result["allowed"] is False
        assert "blast_radius_exceeded" in result["reasons"]

    @pytest.mark.asyncio
    async def test_dict_result_from_engine(self) -> None:
        engine = AsyncMock()
        engine.evaluate = AsyncMock(return_value={"allowed": True, "reasons": ["ok"]})
        result = await check_policy(engine, "cost", "analyze")
        assert result["allowed"] is True


class TestNoPolicyEngine:
    @pytest.mark.asyncio
    async def test_none_engine_returns_allowed(self) -> None:
        result = await check_policy(None, "investigation", "query")
        assert result["allowed"] is True
        assert "no_policy_engine" in result["reasons"]
        assert result["approval_required"] is False


class TestApprovalRequired:
    @pytest.mark.asyncio
    async def test_low_risk_no_approval(self) -> None:
        engine = AsyncMock()
        engine.evaluate = AsyncMock(return_value={"allowed": True, "reasons": []})
        result = await check_policy(engine, "investigation", "query", risk_score=0.3)
        assert result["approval_required"] is False

    @pytest.mark.asyncio
    async def test_medium_risk_requires_approval(self) -> None:
        engine = AsyncMock()
        engine.evaluate = AsyncMock(return_value={"allowed": True, "reasons": []})
        result = await check_policy(engine, "remediation", "contain", risk_score=0.7)
        assert result["approval_required"] is True

    @pytest.mark.asyncio
    async def test_high_risk_requires_approval(self) -> None:
        engine = AsyncMock()
        engine.evaluate = AsyncMock(return_value={"allowed": True, "reasons": []})
        result = await check_policy(engine, "remediation", "contain", risk_score=0.85)
        assert result["approval_required"] is True

    @pytest.mark.asyncio
    async def test_above_threshold_no_approval_flag(self) -> None:
        engine = AsyncMock()
        engine.evaluate = AsyncMock(return_value={"allowed": True, "reasons": []})
        result = await check_policy(engine, "remediation", "contain", risk_score=0.9)
        assert result["approval_required"] is False  # > 0.85 = escalate, not approve


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_error_fail_open_for_read(self) -> None:
        engine = AsyncMock()
        engine.evaluate = AsyncMock(side_effect=RuntimeError("OPA down"))
        result = await check_policy(engine, "investigation", "query_logs")
        assert result["allowed"] is True
        assert "policy_error" in result["reasons"][0]

    @pytest.mark.asyncio
    async def test_error_fail_closed_for_write(self) -> None:
        engine = AsyncMock()
        engine.evaluate = AsyncMock(side_effect=RuntimeError("OPA down"))
        result = await check_policy(engine, "remediation", "contain")
        assert result["allowed"] is False
        assert result["approval_required"] is True

    @pytest.mark.asyncio
    async def test_error_fail_closed_for_delete(self) -> None:
        engine = AsyncMock()
        engine.evaluate = AsyncMock(side_effect=RuntimeError("timeout"))
        result = await check_policy(engine, "remediation", "delete")
        assert result["allowed"] is False


class TestMetadata:
    @pytest.mark.asyncio
    async def test_metadata_passed_to_engine(self) -> None:
        engine = AsyncMock()
        engine.evaluate = AsyncMock(return_value={"allowed": True, "reasons": []})
        await check_policy(
            engine,
            "investigation",
            "query",
            metadata={"tenant_id": "org-123", "resource_count": 5},
        )
        call_args = engine.evaluate.call_args[0][0]
        assert call_args["tenant_id"] == "org-123"
        assert call_args["resource_count"] == 5
