"""Contract tests for the ``llm_structured`` shim (RFC #248 PR-4).

The shim must:

1. Delegate into the installed ``LLMOrchestrator`` when one is
   present (via ``use_test_llm_orchestrator``).
2. Pass through the positional (system_prompt, user_prompt, schema)
   signature without mutation — 1,851 existing callers depend on it.
3. Fall back to the legacy ChatAnthropic path when no orchestrator
   is installed or when delegation raises — so tests that predate
   PR-4 keep working unchanged.

All tests here run against a ``FakeLLMProvider`` so there are zero
network calls and zero dependencies on a real API key.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from pydantic import BaseModel

from shieldops.utils.llm import _LEGACY_SHIM_AGENT_ID, llm_structured
from shieldops.utils.llm_core.adapters import FakeLLMProvider
from shieldops.utils.llm_core.composition import (
    use_test_llm_orchestrator,
)
from shieldops.utils.llm_core.deps import LLMDeps
from shieldops.utils.llm_core.orchestrator import LLMOrchestrator
from shieldops.utils.llm_core.types import Complexity


class _SampleSchema(BaseModel):
    verdict: str
    confidence: float


def _build_orchestrator_with(provider: FakeLLMProvider) -> LLMOrchestrator:
    """Build an orchestrator wired to the given FakeLLMProvider."""
    from shieldops.utils.llm_core.adapters import (
        FixedClassifier,
        InMemoryFitnessRecorder,
        ManualClock,
        NoRetry,
        NullContextRetriever,
        NullLogger,
    )

    deps = LLMDeps(
        provider=provider,
        classifier=FixedClassifier(Complexity.MEDIUM),
        context=NullContextRetriever(),
        fitness=InMemoryFitnessRecorder(),
        retry=NoRetry(),
        clock=ManualClock(),
        log=NullLogger(),
    )
    return LLMOrchestrator(deps)


class TestLLMStructuredDelegation:
    """The shim delegates to the installed orchestrator."""

    @pytest.mark.asyncio
    async def test_delegates_to_installed_orchestrator(self) -> None:
        provider = FakeLLMProvider(
            parsed={"verdict": "safe", "confidence": 0.92},
        )
        orch = _build_orchestrator_with(provider)

        with use_test_llm_orchestrator(orch):
            result = await llm_structured(
                "You are a security analyst.",
                "Is this traffic anomalous? <payload>",
                _SampleSchema,
            )

        # Provider was called exactly once via the shim
        assert len(provider.calls) == 1
        # Return value is the parsed payload from FakeLLMProvider
        assert result == {"verdict": "safe", "confidence": 0.92}

    @pytest.mark.asyncio
    async def test_system_prompt_flows_through_to_provider(self) -> None:
        provider = FakeLLMProvider(parsed={"verdict": "ok", "confidence": 1.0})
        orch = _build_orchestrator_with(provider)

        with use_test_llm_orchestrator(orch):
            await llm_structured(
                "SYSTEM-INSTRUCTIONS",
                "user-data",
                _SampleSchema,
            )

        call = provider.calls[0]
        assert call.system_prompt == "SYSTEM-INSTRUCTIONS"
        assert call.prompt == "user-data"  # user_prompt remains the body
        # The shim sets agent_id to the legacy identifier so fitness
        # metrics bucket shim calls separately from migrated runners.
        assert call.response_model_name == "_SampleSchema"

    @pytest.mark.asyncio
    async def test_agent_id_is_legacy_shim_marker(self) -> None:
        provider = FakeLLMProvider(parsed={"verdict": "x", "confidence": 0.0})
        orch = _build_orchestrator_with(provider)

        # We can't pull agent_id off the FakeLLMProvider call log
        # directly — but we can verify the constant is stable for
        # downstream fitness tooling to key on.
        assert _LEGACY_SHIM_AGENT_ID == "legacy-shim"

        with use_test_llm_orchestrator(orch):
            await llm_structured("s", "u", _SampleSchema)


class TestLLMStructuredFallback:
    """The shim falls back to legacy when orchestrator is absent or raises."""

    @pytest.mark.asyncio
    async def test_falls_back_when_no_orchestrator_installed(self) -> None:
        # With no orchestrator installed, the shim should invoke the
        # legacy ``_llm_structured_legacy`` path. Patch that symbol
        # to an AsyncMock so we don't touch langchain-anthropic.
        from unittest.mock import AsyncMock

        fake_parsed = _SampleSchema(verdict="legacy-path", confidence=0.5)

        # Ensure no orchestrator is installed — use_test_llm_orchestrator
        # with None is not a valid nesting, so just patch the getter.
        with patch(
            "shieldops.utils.llm._llm_structured_legacy",
            new=AsyncMock(return_value=fake_parsed),
        ) as legacy_mock:
            result = await llm_structured("sys", "usr", _SampleSchema)

        legacy_mock.assert_awaited_once_with("sys", "usr", _SampleSchema)
        assert result == fake_parsed

    @pytest.mark.asyncio
    async def test_falls_back_when_orchestrator_raises(self) -> None:
        """A bug in the orchestrator must never crash an agent call."""
        from unittest.mock import AsyncMock

        # Build an orchestrator whose provider raises on every call.
        class _AlwaysFailsProvider:
            name = "always-fails"

            async def complete(self, *args: Any, **kwargs: Any) -> Any:
                raise RuntimeError("synthetic provider failure")

        from shieldops.utils.llm_core.adapters import (
            FixedClassifier,
            InMemoryFitnessRecorder,
            ManualClock,
            NoRetry,
            NullContextRetriever,
            NullLogger,
        )

        deps = LLMDeps(
            provider=_AlwaysFailsProvider(),  # type: ignore[arg-type]
            classifier=FixedClassifier(Complexity.MEDIUM),
            context=NullContextRetriever(),
            fitness=InMemoryFitnessRecorder(),
            retry=NoRetry(),
            clock=ManualClock(),
            log=NullLogger(),
        )
        orch = LLMOrchestrator(deps)

        fake_parsed = _SampleSchema(verdict="fallback", confidence=0.1)
        with (
            use_test_llm_orchestrator(orch),
            patch(
                "shieldops.utils.llm._llm_structured_legacy",
                new=AsyncMock(return_value=fake_parsed),
            ) as legacy_mock,
        ):
            result = await llm_structured("s", "u", _SampleSchema)

        legacy_mock.assert_awaited_once()
        assert result == fake_parsed


class TestLLMStructuredSignatureStability:
    """Signature is frozen — PR-4 must not shift positional args."""

    def test_positional_signature(self) -> None:
        import inspect

        sig = inspect.signature(llm_structured)
        params = list(sig.parameters.values())
        assert len(params) == 3, f"llm_structured must take exactly 3 args, got {len(params)}"
        assert params[0].name == "system_prompt"
        assert params[1].name == "user_prompt"
        assert params[2].name == "schema"
        # All three must accept positional binding (no keyword-only).
        for p in params:
            assert p.kind in (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.POSITIONAL_ONLY,
            ), f"{p.name} must be positional-compatible"
