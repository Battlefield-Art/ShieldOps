"""Typed TokenUsage model — TDD tests (#7)."""

from __future__ import annotations

import pytest

from shieldops.utils.token_usage import TokenUsage


class TestTokenUsageConstruction:
    def test_auto_computes_total(self) -> None:
        tu = TokenUsage(model="claude-sonnet-4-6", prompt_tokens=100, completion_tokens=50)
        assert tu.total_tokens == 150

    def test_explicit_total_overrides_calc(self) -> None:
        # If caller provides a total (e.g. from provider billing), accept it
        tu = TokenUsage(
            model="claude-haiku-4-5",
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=175,  # provider reported a different total
        )
        assert tu.total_tokens == 175

    def test_rejects_negative_tokens(self) -> None:
        with pytest.raises(ValueError):
            TokenUsage(model="claude-sonnet-4-6", prompt_tokens=-1, completion_tokens=0)


class TestTokenUsageCost:
    def test_sonnet_cost(self) -> None:
        """Claude Sonnet: $3/M input, $15/M output."""
        tu = TokenUsage(
            model="claude-sonnet-4-6",
            prompt_tokens=1_000_000,
            completion_tokens=1_000_000,
        )
        # 3 + 15 = 18 USD
        assert tu.estimated_cost_usd == pytest.approx(18.0, rel=1e-3)

    def test_haiku_cheap(self) -> None:
        """Claude Haiku: $1/M input, $5/M output."""
        tu = TokenUsage(
            model="claude-haiku-4-5",
            prompt_tokens=1_000_000,
            completion_tokens=1_000_000,
        )
        assert tu.estimated_cost_usd == pytest.approx(6.0, rel=1e-3)

    def test_unknown_model_zero_cost(self) -> None:
        tu = TokenUsage(
            model="mystery-model",
            prompt_tokens=1000,
            completion_tokens=500,
        )
        assert tu.estimated_cost_usd == 0.0


class TestTokenUsageSerialization:
    def test_dict_round_trip(self) -> None:
        tu = TokenUsage(
            model="claude-sonnet-4-6",
            prompt_tokens=100,
            completion_tokens=50,
        )
        as_dict = tu.model_dump()
        restored = TokenUsage.model_validate(as_dict)
        assert restored == tu

    def test_json_round_trip(self) -> None:
        tu = TokenUsage(
            model="claude-haiku-4-5",
            prompt_tokens=1234,
            completion_tokens=567,
        )
        json_str = tu.model_dump_json()
        restored = TokenUsage.model_validate_json(json_str)
        assert restored.prompt_tokens == 1234
        assert restored.completion_tokens == 567
        assert restored.total_tokens == 1801

    def test_from_raw_dict_with_missing_fields(self) -> None:
        """Backward-compat: old AgentRun.token_usage blobs may lack some keys."""
        raw = {"prompt_tokens": 100}  # no completion or model
        tu = TokenUsage.from_raw(raw)
        assert tu.prompt_tokens == 100
        assert tu.completion_tokens == 0
        assert tu.total_tokens == 100
        assert tu.model == ""
        assert tu.estimated_cost_usd == 0.0
