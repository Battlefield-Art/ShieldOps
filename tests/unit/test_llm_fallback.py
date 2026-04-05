"""Tests for shared LLM fallback utilities."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import BaseModel, Field


class MockAnalysis(BaseModel):
    summary: str = ""
    confidence: float = 0.0
    findings: list[str] = Field(default_factory=list)


class TestLlmWithFallback:
    @pytest.mark.asyncio
    async def test_returns_llm_result_on_success(self) -> None:
        from shieldops.agents.llm_fallback import llm_with_fallback

        expected = MockAnalysis(summary="test", confidence=0.9)
        with patch("shieldops.utils.llm.llm_structured", new_callable=AsyncMock) as mock:
            mock.return_value = expected
            result = await llm_with_fallback("system", "user", MockAnalysis, agent_name="test")
            assert result == expected

    @pytest.mark.asyncio
    async def test_uses_fallback_fn_on_failure(self) -> None:
        from shieldops.agents.llm_fallback import llm_with_fallback

        with patch("shieldops.utils.llm.llm_structured", new_callable=AsyncMock) as mock:
            mock.side_effect = RuntimeError("LLM down")
            result = await llm_with_fallback(
                "system",
                "user",
                MockAnalysis,
                fallback_fn=lambda: {"summary": "fallback", "confidence": 0.5},
            )
            assert result["summary"] == "fallback"

    @pytest.mark.asyncio
    async def test_uses_fallback_value_on_failure(self) -> None:
        from shieldops.agents.llm_fallback import llm_with_fallback

        with patch("shieldops.utils.llm.llm_structured", new_callable=AsyncMock) as mock:
            mock.side_effect = RuntimeError("LLM down")
            result = await llm_with_fallback(
                "system",
                "user",
                MockAnalysis,
                fallback_value={"summary": "static fallback"},
            )
            assert result["summary"] == "static fallback"

    @pytest.mark.asyncio
    async def test_fallback_fn_takes_priority_over_value(self) -> None:
        from shieldops.agents.llm_fallback import llm_with_fallback

        with patch("shieldops.utils.llm.llm_structured", new_callable=AsyncMock) as mock:
            mock.side_effect = RuntimeError("LLM down")
            result = await llm_with_fallback(
                "system",
                "user",
                MockAnalysis,
                fallback_fn=lambda: {"summary": "from_fn"},
                fallback_value={"summary": "from_value"},
            )
            assert result["summary"] == "from_fn"

    @pytest.mark.asyncio
    async def test_returns_empty_schema_as_last_resort(self) -> None:
        from shieldops.agents.llm_fallback import llm_with_fallback

        with patch("shieldops.utils.llm.llm_structured", new_callable=AsyncMock) as mock:
            mock.side_effect = RuntimeError("LLM down")
            result = await llm_with_fallback("system", "user", MockAnalysis)
            assert isinstance(result, MockAnalysis)
            assert result.summary == ""

    @pytest.mark.asyncio
    async def test_fallback_fn_error_falls_to_value(self) -> None:
        from shieldops.agents.llm_fallback import llm_with_fallback

        with patch("shieldops.utils.llm.llm_structured", new_callable=AsyncMock) as mock:
            mock.side_effect = RuntimeError("LLM down")

            def bad_fallback() -> dict[str, Any]:
                raise ValueError("fallback broken")

            result = await llm_with_fallback(
                "system",
                "user",
                MockAnalysis,
                fallback_fn=bad_fallback,
                fallback_value={"summary": "safe"},
            )
            assert result["summary"] == "safe"


class TestLlmClassify:
    @pytest.mark.asyncio
    async def test_returns_matching_category(self) -> None:
        from shieldops.agents.llm_fallback import llm_classify

        with patch("shieldops.utils.llm.llm_analyze", new_callable=AsyncMock) as mock:
            mock.return_value = {"content": "critical"}
            result = await llm_classify("server down", ["low", "medium", "high", "critical"])
            assert result == "critical"

    @pytest.mark.asyncio
    async def test_keyword_fallback_on_llm_failure(self) -> None:
        from shieldops.agents.llm_fallback import llm_classify

        with patch("shieldops.utils.llm.llm_analyze", new_callable=AsyncMock) as mock:
            mock.side_effect = RuntimeError("LLM down")
            result = await llm_classify(
                "this is a critical security alert",
                ["low", "medium", "high", "critical"],
            )
            assert result == "critical"

    @pytest.mark.asyncio
    async def test_default_category_on_no_match(self) -> None:
        from shieldops.agents.llm_fallback import llm_classify

        with patch("shieldops.utils.llm.llm_analyze", new_callable=AsyncMock) as mock:
            mock.side_effect = RuntimeError("LLM down")
            result = await llm_classify(
                "no keywords here",
                ["alpha", "beta", "gamma"],
                default_category="beta",
            )
            assert result == "beta"

    @pytest.mark.asyncio
    async def test_empty_categories_returns_default(self) -> None:
        from shieldops.agents.llm_fallback import llm_classify

        result = await llm_classify("test", [], default_category="none")
        assert result == "none"
