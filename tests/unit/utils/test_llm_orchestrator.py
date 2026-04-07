"""Contract tests for LLMOrchestrator — RFC #248 PR-1.

See ghantakiran/ShieldOps#248. These tests lock the structural
invariants PR-1 introduces:

1. **Classifier → model routing is wired** — a HIGH-complexity request
   lands on Opus; a LOW-complexity request lands on Haiku. The router
   that has been dead for months is finally load-bearing inside a real
   call path.

2. **Fitness recording closes the loop** — every call, success OR
   failure, records exactly one entry through the
   :class:`FitnessRecorderPort`. This is the cross-subsystem
   integration that RFC #246's EvolutionStore needs from this RFC.

3. **Retry loop honors the injected policy** — scripted retries walk
   through provider failures, sleep for the requested duration on the
   injected :class:`ManualClock`, and succeed when the script returns
   a result.

4. **Fallback replaces try/except blocks** — a caller that passes
   ``fallback=`` gets the fallback back as an :class:`LLMResponse`
   with ``used_fallback=True`` when all retries are exhausted, instead
   of having to wrap the call in their own ``try/except``.

5. **Context retrieval enriches the prompt** — when ``context_query``
   is set, the orchestrator prepends retrieved chunks to the prompt
   before calling the provider.

6. **Hint complexity bypasses the classifier + flags fitness as forced**
   — so a caller that overrides the model doesn't pollute the router's
   training signal.

All tests use in-memory adapters. No real LLM calls. Each runs in <5 ms.
"""

from __future__ import annotations

import pytest

from shieldops.utils.llm_core import (
    Complexity,
    LLMDeps,
    LLMOrchestrator,
    LLMRequest,
    LLMResponse,
    LLMUnavailable,
    ModelTier,
    ProviderResult,
    Sleep,
    Stop,
    TokenUsage,
    build_in_memory_orchestrator,
    get_llm_orchestrator,
    set_llm_orchestrator,
    use_test_llm_orchestrator,
)
from shieldops.utils.llm_core.adapters import (
    FakeLLMProvider,
    FixedClassifier,
    InMemoryFitnessRecorder,
    ManualClock,
    NoRetry,
    NullContextRetriever,
    NullLogger,
    ScriptedLLMProvider,
    ScriptedRetry,
    StaticContextRetriever,
)
from shieldops.utils.llm_core.types import ContextChunk, ProviderName

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _orchestrator(
    *,
    classifier: FixedClassifier | None = None,
    provider: FakeLLMProvider | ScriptedLLMProvider | None = None,
    retry: NoRetry | ScriptedRetry | None = None,
    context: NullContextRetriever | StaticContextRetriever | None = None,
    fitness: InMemoryFitnessRecorder | None = None,
) -> tuple[LLMOrchestrator, LLMDeps, InMemoryFitnessRecorder]:
    fitness = fitness or InMemoryFitnessRecorder()
    deps = LLMDeps(
        provider=provider or FakeLLMProvider(),
        classifier=classifier or FixedClassifier(Complexity.MEDIUM),
        context=context or NullContextRetriever(),
        fitness=fitness,
        retry=retry or NoRetry(),
        clock=ManualClock(start=1000.0),
        log=NullLogger(),
    )
    return LLMOrchestrator(deps), deps, fitness


def _req(
    *,
    agent_id: str = "soc_analyst",
    tenant_id: str | None = None,
    hint: Complexity | None = None,
    context_query: str | None = None,
    fallback: object = None,
) -> LLMRequest:
    return LLMRequest(
        prompt="investigate alert",
        response_model_name="InvestigationResult",
        agent_id=agent_id,
        tenant_id=tenant_id,
        hint_complexity=hint,
        context_query=context_query,
        fallback=fallback,
    )


# ---------------------------------------------------------------------------
# 1. Classifier → model routing
# ---------------------------------------------------------------------------


class TestRouting:
    @pytest.mark.asyncio
    async def test_high_complexity_routes_to_opus(self) -> None:
        provider = FakeLLMProvider()
        orch, _, _ = _orchestrator(classifier=FixedClassifier(Complexity.HIGH), provider=provider)
        resp = await orch.call(_req())
        assert resp.model_used == ModelTier.OPUS
        assert provider.calls[0].model == ModelTier.OPUS

    @pytest.mark.asyncio
    async def test_medium_complexity_routes_to_sonnet(self) -> None:
        provider = FakeLLMProvider()
        orch, _, _ = _orchestrator(classifier=FixedClassifier(Complexity.MEDIUM), provider=provider)
        resp = await orch.call(_req())
        assert resp.model_used == ModelTier.SONNET
        assert provider.calls[0].model == ModelTier.SONNET

    @pytest.mark.asyncio
    async def test_low_complexity_routes_to_haiku(self) -> None:
        provider = FakeLLMProvider()
        orch, _, _ = _orchestrator(classifier=FixedClassifier(Complexity.LOW), provider=provider)
        resp = await orch.call(_req())
        assert resp.model_used == ModelTier.HAIKU
        assert provider.calls[0].model == ModelTier.HAIKU

    @pytest.mark.asyncio
    async def test_hint_complexity_bypasses_classifier(self) -> None:
        """The caller's hint wins over the classifier's choice."""
        provider = FakeLLMProvider()
        orch, _, _ = _orchestrator(classifier=FixedClassifier(Complexity.LOW), provider=provider)
        resp = await orch.call(_req(hint=Complexity.HIGH))
        assert resp.model_used == ModelTier.OPUS
        assert provider.calls[0].model == ModelTier.OPUS


# ---------------------------------------------------------------------------
# 2. Fitness recording closes the loop
# ---------------------------------------------------------------------------


class TestFitnessRecording:
    @pytest.mark.asyncio
    async def test_successful_call_records_fitness(self) -> None:
        orch, _, fitness = _orchestrator()
        await orch.call(_req(agent_id="threat_hunter"))

        records = fitness.for_agent("threat_hunter")
        assert len(records) == 1
        assert records[0].success is True
        assert records[0].tokens > 0
        assert records[0].latency_ms >= 0

    @pytest.mark.asyncio
    async def test_failed_call_still_records_fitness(self) -> None:
        """Even when the provider fails and no fallback is provided,
        fitness is recorded. This is the closing of the feedback loop
        that the router needs to learn."""
        provider = ScriptedLLMProvider(script=[RuntimeError("boom1"), RuntimeError("boom2")])
        orch, _, fitness = _orchestrator(
            provider=provider,
            retry=ScriptedRetry([Sleep(0.0), Stop()]),
        )

        with pytest.raises(LLMUnavailable):
            await orch.call(_req())

        assert len(fitness.records) == 1
        assert fitness.records[0].success is False

    @pytest.mark.asyncio
    async def test_hint_complexity_records_forced_true(self) -> None:
        """Fitness records for forced calls are tagged so the router
        training can exclude them."""
        orch, _, fitness = _orchestrator()
        await orch.call(_req(hint=Complexity.OPUS if False else Complexity.HIGH))
        assert fitness.records[0].forced is True

    @pytest.mark.asyncio
    async def test_classified_call_records_forced_false(self) -> None:
        orch, _, fitness = _orchestrator()
        await orch.call(_req())  # no hint
        assert fitness.records[0].forced is False

    @pytest.mark.asyncio
    async def test_fitness_adapter_exception_does_not_crash_call(self) -> None:
        """A bug in the fitness adapter must NOT propagate to the caller."""

        class BrokenFitness:
            async def record_run(self, **kw):  # noqa: ARG002
                raise RuntimeError("fitness is on fire")

        deps = LLMDeps(
            provider=FakeLLMProvider(),
            classifier=FixedClassifier(Complexity.MEDIUM),
            context=NullContextRetriever(),
            fitness=BrokenFitness(),  # type: ignore[arg-type]
            retry=NoRetry(),
            clock=ManualClock(),
            log=NullLogger(),
        )
        orch = LLMOrchestrator(deps)
        # Must not raise despite the fitness failure.
        resp = await orch.call(_req())
        assert isinstance(resp, LLMResponse)


# ---------------------------------------------------------------------------
# 3. Retry loop
# ---------------------------------------------------------------------------


class TestRetryLoop:
    @pytest.mark.asyncio
    async def test_retry_succeeds_on_third_attempt(self) -> None:
        success = ProviderResult(
            parsed={"ok": True},
            model_used=ModelTier.SONNET,
            provider_used=ProviderName.FAKE,
            tokens=TokenUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            latency_ms=5.0,
        )
        provider = ScriptedLLMProvider(
            script=[RuntimeError("fail1"), RuntimeError("fail2"), success]
        )
        orch, _, fitness = _orchestrator(
            provider=provider,
            retry=ScriptedRetry([Sleep(0.0), Sleep(0.0), Stop()]),
        )

        resp = await orch.call(_req())
        assert resp.attempts == 3
        assert resp.used_fallback is False
        assert fitness.records[0].success is True

    @pytest.mark.asyncio
    async def test_retry_stops_and_falls_back(self) -> None:
        """When retries are exhausted and a fallback is provided, the
        caller gets the fallback back as an LLMResponse — no exception."""
        provider = ScriptedLLMProvider(script=[RuntimeError("always fails")])
        orch, _, _ = _orchestrator(provider=provider, retry=NoRetry())

        fallback = {"default": "canned"}
        resp = await orch.call(_req(fallback=fallback))
        assert resp.used_fallback is True
        assert resp.parsed == fallback
        assert resp.attempts == 1

    @pytest.mark.asyncio
    async def test_retry_sleep_uses_injected_clock_not_real_time(
        self,
    ) -> None:
        """Sleep(5.0) in a retry must advance the ManualClock, not burn
        real seconds."""
        success = ProviderResult(
            parsed={},
            model_used=ModelTier.SONNET,
            provider_used=ProviderName.FAKE,
            tokens=TokenUsage(),
            latency_ms=1.0,
        )
        provider = ScriptedLLMProvider(script=[RuntimeError("fail"), success])
        clock = ManualClock(start=1000.0)
        deps = LLMDeps(
            provider=provider,
            classifier=FixedClassifier(Complexity.MEDIUM),
            context=NullContextRetriever(),
            fitness=InMemoryFitnessRecorder(),
            retry=ScriptedRetry([Sleep(5.0)]),
            clock=clock,
            log=NullLogger(),
        )
        orch = LLMOrchestrator(deps)

        resp = await orch.call(_req())
        assert resp.attempts == 2
        # The Sleep(5.0) in the retry advanced the clock.
        assert clock.now() >= 1005.0


# ---------------------------------------------------------------------------
# 4. Context retrieval enriches the prompt
# ---------------------------------------------------------------------------


class TestContextRetrieval:
    @pytest.mark.asyncio
    async def test_context_query_prepends_chunks_to_prompt(self) -> None:
        chunks = [
            ContextChunk(source="runbook/incident-42", content="saw this before"),
            ContextChunk(source="prior/incident-17", content="related"),
        ]
        provider = FakeLLMProvider()
        orch, _, _ = _orchestrator(provider=provider, context=StaticContextRetriever(chunks))

        resp = await orch.call(_req(context_query="alert-123"))
        assert resp.context_chunks == 2
        # The enriched prompt was what the provider saw.
        sent_prompt = provider.calls[0].prompt
        assert "runbook/incident-42" in sent_prompt
        assert "saw this before" in sent_prompt
        assert "investigate alert" in sent_prompt  # original prompt also present

    @pytest.mark.asyncio
    async def test_no_context_query_skips_retrieval(self) -> None:
        provider = FakeLLMProvider()
        orch, _, _ = _orchestrator(provider=provider)

        resp = await orch.call(_req())
        assert resp.context_chunks == 0
        assert provider.calls[0].prompt == "investigate alert"


# ---------------------------------------------------------------------------
# 5. LLMUnavailable when no fallback
# ---------------------------------------------------------------------------


class TestUnavailable:
    @pytest.mark.asyncio
    async def test_raises_llm_unavailable_when_no_fallback(self) -> None:
        provider = ScriptedLLMProvider(script=[RuntimeError("offline")])
        orch, _, _ = _orchestrator(provider=provider)

        with pytest.raises(LLMUnavailable, match="failed after"):
            await orch.call(_req(fallback=None))


# ---------------------------------------------------------------------------
# 6. Tenant_id threads through the provider call
# ---------------------------------------------------------------------------


class TestTenantPropagation:
    @pytest.mark.asyncio
    async def test_tenant_id_reaches_the_provider(self) -> None:
        provider = FakeLLMProvider()
        orch, _, fitness = _orchestrator(provider=provider)

        await orch.call(_req(tenant_id="acme"))

        assert provider.calls[0].tenant_id == "acme"
        assert fitness.records[0].tenant_id == "acme"


# ---------------------------------------------------------------------------
# 7. Composition root
# ---------------------------------------------------------------------------


class TestComposition:
    def test_get_raises_when_not_installed(self) -> None:
        set_llm_orchestrator(None)
        with pytest.raises(RuntimeError, match="No LLMOrchestrator installed"):
            get_llm_orchestrator()

    def test_use_test_orchestrator_installs_and_restores(self) -> None:
        original, _ = build_in_memory_orchestrator()
        set_llm_orchestrator(original)

        with use_test_llm_orchestrator() as fresh:
            assert get_llm_orchestrator() is fresh
            assert fresh is not original

        assert get_llm_orchestrator() is original
        set_llm_orchestrator(None)

    def test_use_test_orchestrator_restores_on_exception(self) -> None:
        original, _ = build_in_memory_orchestrator()
        set_llm_orchestrator(original)

        with pytest.raises(ValueError, match="test"), use_test_llm_orchestrator():
            raise ValueError("test")

        assert get_llm_orchestrator() is original
        set_llm_orchestrator(None)
