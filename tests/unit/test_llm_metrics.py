"""Tests for shieldops.utils.llm_metrics — token estimation and LLM call tracking."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from shieldops.utils.llm_metrics import _extract_tokens, estimate_tokens, track_llm_call

# ---------------------------------------------------------------------------
# TestEstimateTokens
# ---------------------------------------------------------------------------


class TestEstimateTokens:
    """Tests for the estimate_tokens() heuristic (4 chars per token, min 1)."""

    def test_empty_string_returns_one(self):
        assert estimate_tokens("") == 1

    def test_short_string_below_four_chars_returns_one(self):
        # "hi" = 2 chars => 2 // 4 = 0 => max(1, 0) = 1
        assert estimate_tokens("hi") == 1

    def test_exactly_four_chars_returns_one(self):
        assert estimate_tokens("abcd") == 1

    def test_five_chars_returns_one(self):
        # 5 // 4 = 1
        assert estimate_tokens("hello") == 1

    def test_eight_chars_returns_two(self):
        assert estimate_tokens("abcdefgh") == 2

    def test_hundred_chars_returns_twenty_five(self):
        text = "a" * 100
        assert estimate_tokens(text) == 25

    def test_large_string(self):
        text = "x" * 4000
        assert estimate_tokens(text) == 1000

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("", 1),
            ("a", 1),
            ("ab", 1),
            ("abc", 1),
            ("abcd", 1),
            ("abcde", 1),
            ("a" * 8, 2),
            ("a" * 12, 3),
            ("a" * 40, 10),
        ],
    )
    def test_parametrized_lengths(self, text: str, expected: int):  # type: ignore[no-untyped-def]
        assert estimate_tokens(text) == expected


# ---------------------------------------------------------------------------
# TestExtractTokens
# ---------------------------------------------------------------------------


class TestExtractTokens:
    """Tests for _extract_tokens() — best-effort token extraction from LLM results."""

    # -- Dict with usage metadata --

    def test_dict_with_usage_returns_actual_counts(self):
        result = {"usage": {"input_tokens": 150, "output_tokens": 80}}
        input_t, output_t = _extract_tokens(result, (), {})
        assert input_t == 150
        assert output_t == 80

    def test_dict_with_partial_usage_output_only(self):
        result = {"usage": {"output_tokens": 50}}
        input_t, output_t = _extract_tokens(result, (), {})
        assert input_t == 0
        assert output_t == 50

    def test_dict_with_usage_zero_output_falls_back_to_content(self):
        # output_tokens=0 triggers content fallback
        result = {
            "usage": {"input_tokens": 100, "output_tokens": 0},
            "content": "a" * 40,  # 40 chars => 10 tokens
        }
        input_t, output_t = _extract_tokens(result, (), {})
        assert input_t == 100
        assert output_t == 10

    # -- Dict without usage --

    def test_dict_without_usage_estimates_from_content(self):
        result = {"content": "a" * 20}  # 20 // 4 = 5
        input_t, output_t = _extract_tokens(result, (), {})
        assert output_t == 5

    def test_dict_without_usage_no_content_returns_zero_output(self):
        result = {"other_key": "value"}
        _, output_t = _extract_tokens(result, (), {})
        assert output_t == 0

    def test_dict_with_empty_content_returns_zero_output(self):
        result = {"content": ""}
        _, output_t = _extract_tokens(result, (), {})
        assert output_t == 0

    def test_dict_with_non_dict_usage_ignores_usage(self):
        # usage is not a dict, should be ignored
        result = {"usage": "not-a-dict", "content": "a" * 16}
        _, output_t = _extract_tokens(result, (), {})
        assert output_t == 4

    # -- Non-dict results --

    def test_non_dict_result_estimates_from_str(self):
        result = "a" * 20  # str(result) = 20 chars => 5 tokens
        _, output_t = _extract_tokens(result, (), {})
        assert output_t == 5

    def test_none_result_returns_zero_output(self):
        _, output_t = _extract_tokens(None, (), {})
        assert output_t == 0

    def test_integer_result_estimates_from_str(self):
        result = 12345  # str(12345) = "12345" => 5 chars => 1 token
        _, output_t = _extract_tokens(result, (), {})
        assert output_t == 1

    # -- Input token estimation from args/kwargs --

    def test_input_tokens_from_positional_string_args(self):
        # Two string args: "a"*20 + "b"*20 = 40 chars => 10 tokens
        input_t, _ = _extract_tokens({}, ("a" * 20, "b" * 20), {})
        assert input_t == 10

    def test_input_tokens_skips_non_string_args(self):
        # Only string args counted; int arg ignored
        input_t, _ = _extract_tokens({}, (42, "a" * 16), {})
        assert input_t == 4

    def test_input_tokens_from_system_prompt_kwarg(self):
        input_t, _ = _extract_tokens({}, (), {"system_prompt": "a" * 20})
        assert input_t == 5

    def test_input_tokens_from_user_prompt_kwarg(self):
        input_t, _ = _extract_tokens({}, (), {"user_prompt": "a" * 40})
        assert input_t == 10

    def test_input_tokens_from_prompt_kwarg(self):
        input_t, _ = _extract_tokens({}, (), {"prompt": "a" * 12})
        assert input_t == 3

    def test_input_tokens_combines_args_and_kwargs(self):
        # positional "a"*20 + kwarg prompt "b"*20 = 40 chars => 10 tokens
        input_t, _ = _extract_tokens({}, ("a" * 20,), {"prompt": "b" * 20})
        assert input_t == 10

    def test_input_tokens_not_estimated_when_usage_provides_them(self):
        result = {"usage": {"input_tokens": 99, "output_tokens": 50}}
        input_t, _ = _extract_tokens(result, ("a" * 400,), {"prompt": "b" * 400})
        # Should use actual usage value, not estimate
        assert input_t == 99

    def test_no_string_args_or_prompt_kwargs_returns_zero_input(self):
        input_t, _ = _extract_tokens({}, (42, 3.14), {"other": "val"})
        assert input_t == 0


# ---------------------------------------------------------------------------
# TestTrackLlmCall
# ---------------------------------------------------------------------------


class TestTrackLlmCall:
    """Tests for the @track_llm_call decorator — async wrapping and metrics recording."""

    @pytest.fixture()
    def mock_metrics(self):
        """Provide a mock AgentMetricsCollector with record_llm_call stub."""
        collector = MagicMock()
        collector.record_llm_call = MagicMock()
        return collector

    # -- Success path --

    @pytest.mark.asyncio
    async def test_returns_decorated_function_result(self, mock_metrics):
        @track_llm_call(agent_type="investigation", model="claude-sonnet")
        async def my_fn(prompt: str) -> dict:
            return {"content": "analysis done"}

        with patch(
            "shieldops.utils.llm_metrics.get_agent_metrics",
            return_value=mock_metrics,
        ):
            result = await my_fn("analyze this")

        assert result == {"content": "analysis done"}

    @pytest.mark.asyncio
    async def test_records_metrics_on_success(self, mock_metrics):
        @track_llm_call(agent_type="remediation", model="claude-opus")
        async def my_fn(prompt: str) -> dict:
            return {"usage": {"input_tokens": 10, "output_tokens": 20}}

        with patch(
            "shieldops.utils.llm_metrics.get_agent_metrics",
            return_value=mock_metrics,
        ):
            await my_fn("fix this")

        mock_metrics.record_llm_call.assert_called_once()
        call_kwargs = mock_metrics.record_llm_call.call_args.kwargs
        assert call_kwargs["agent_type"] == "remediation"
        assert call_kwargs["model"] == "claude-opus"
        assert call_kwargs["input_tokens"] == 10
        assert call_kwargs["output_tokens"] == 20
        assert call_kwargs["latency_seconds"] >= 0

    @pytest.mark.asyncio
    async def test_latency_is_positive(self, mock_metrics):
        @track_llm_call(agent_type="test", model="m")
        async def my_fn() -> str:
            await asyncio.sleep(0.01)
            return "done"

        with patch(
            "shieldops.utils.llm_metrics.get_agent_metrics",
            return_value=mock_metrics,
        ):
            await my_fn()

        latency = mock_metrics.record_llm_call.call_args.kwargs["latency_seconds"]
        assert latency >= 0.01

    # -- Default model --

    @pytest.mark.asyncio
    async def test_default_model_is_unknown(self, mock_metrics):
        @track_llm_call(agent_type="soc")
        async def my_fn() -> str:
            return "ok"

        with patch(
            "shieldops.utils.llm_metrics.get_agent_metrics",
            return_value=mock_metrics,
        ):
            await my_fn()

        assert mock_metrics.record_llm_call.call_args.kwargs["model"] == "unknown"

    # -- Exception path --

    @pytest.mark.asyncio
    async def test_reraises_exception(self, mock_metrics):
        @track_llm_call(agent_type="test", model="m")
        async def my_fn() -> str:
            raise ValueError("boom")

        with (
            patch(
                "shieldops.utils.llm_metrics.get_agent_metrics",
                return_value=mock_metrics,
            ),
            pytest.raises(ValueError, match="boom"),
        ):
            await my_fn()

    @pytest.mark.asyncio
    async def test_records_metrics_on_exception_with_zero_tokens(self, mock_metrics):
        @track_llm_call(agent_type="forensics", model="claude-haiku")
        async def my_fn() -> str:
            raise RuntimeError("API timeout")

        with (
            patch(
                "shieldops.utils.llm_metrics.get_agent_metrics",
                return_value=mock_metrics,
            ),
            pytest.raises(RuntimeError),
        ):
            await my_fn()

        mock_metrics.record_llm_call.assert_called_once()
        call_kwargs = mock_metrics.record_llm_call.call_args.kwargs
        assert call_kwargs["agent_type"] == "forensics"
        assert call_kwargs["model"] == "claude-haiku"
        assert call_kwargs["input_tokens"] == 0
        assert call_kwargs["output_tokens"] == 0
        assert call_kwargs["latency_seconds"] >= 0

    # -- Token extraction through decorator --

    @pytest.mark.asyncio
    async def test_estimates_tokens_from_content_when_no_usage(self, mock_metrics):
        @track_llm_call(agent_type="test", model="m")
        async def my_fn(prompt: str) -> dict:
            return {"content": "a" * 40}  # 40 chars => 10 tokens

        with patch(
            "shieldops.utils.llm_metrics.get_agent_metrics",
            return_value=mock_metrics,
        ):
            await my_fn("a" * 20)

        call_kwargs = mock_metrics.record_llm_call.call_args.kwargs
        assert call_kwargs["output_tokens"] == 10
        # input estimated from positional arg: 20 chars => 5
        assert call_kwargs["input_tokens"] == 5

    @pytest.mark.asyncio
    async def test_estimates_input_from_prompt_kwargs(self, mock_metrics):
        @track_llm_call(agent_type="test", model="m")
        async def my_fn(*, system_prompt: str, user_prompt: str) -> dict:
            return {"content": "ok"}

        with patch(
            "shieldops.utils.llm_metrics.get_agent_metrics",
            return_value=mock_metrics,
        ):
            await my_fn(system_prompt="a" * 20, user_prompt="b" * 20)

        # 40 chars total from kwargs => 10 tokens
        call_kwargs = mock_metrics.record_llm_call.call_args.kwargs
        assert call_kwargs["input_tokens"] == 10

    # -- Preserves function metadata --

    def test_preserves_function_name(self):
        @track_llm_call(agent_type="test")
        async def my_special_fn() -> str:
            return "hi"

        assert my_special_fn.__name__ == "my_special_fn"

    def test_preserves_function_docstring(self):
        @track_llm_call(agent_type="test")
        async def my_fn() -> str:
            """This is a docstring."""
            return "hi"

        assert my_fn.__doc__ == "This is a docstring."

    # -- Metrics recording failure is swallowed on success --

    @pytest.mark.asyncio
    async def test_metrics_recording_failure_does_not_propagate(self, mock_metrics):
        mock_metrics.record_llm_call.side_effect = RuntimeError("metrics down")

        @track_llm_call(agent_type="test", model="m")
        async def my_fn() -> str:
            return "result"

        with patch(
            "shieldops.utils.llm_metrics.get_agent_metrics",
            return_value=mock_metrics,
        ):
            # Should not raise despite metrics failure
            result = await my_fn()

        assert result == "result"

    # -- Metrics recording failure is swallowed on exception path too --

    @pytest.mark.asyncio
    async def test_metrics_failure_on_exception_path_still_reraises_original(self, mock_metrics):
        mock_metrics.record_llm_call.side_effect = RuntimeError("metrics down")

        @track_llm_call(agent_type="test", model="m")
        async def my_fn() -> str:
            raise ValueError("original error")

        with (
            patch(
                "shieldops.utils.llm_metrics.get_agent_metrics",
                return_value=mock_metrics,
            ),
            pytest.raises(ValueError, match="original error"),
        ):
            await my_fn()
