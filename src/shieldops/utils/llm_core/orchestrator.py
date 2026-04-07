"""LLMOrchestrator — the pure sequential LLM call path.

One method, ``call``, that does the fixed sequence:

    1. Classify complexity (or honor ``hint_complexity``)
    2. Resolve model via ``model_for(complexity)``
    3. Optional context retrieval (if ``context_query`` set)
    4. Build the final prompt (context + original prompt)
    5. Retry loop: call provider → check error → retry policy decides
    6. Record fitness (success OR failure path — always)
    7. Return :class:`LLMResponse` or raise :class:`LLMUnavailable`

The whole body is <100 LOC and reads as a recipe. Every decision is
visible in one place. The core has zero imports from any real SDK —
production provider implementations live in the adapters package.
"""

from __future__ import annotations

from shieldops.utils.llm_core.deps import LLMDeps
from shieldops.utils.llm_core.types import (
    LLMRequest,
    LLMResponse,
    LLMUnavailable,
    Sleep,
    Stop,
    TokenUsage,
)


class LLMOrchestrator:
    """Pure-ish orchestrator. All behavior is determined by the
    injected :class:`LLMDeps`."""

    def __init__(self, deps: LLMDeps) -> None:
        self._deps = deps

    async def call(self, req: LLMRequest) -> LLMResponse:
        deps = self._deps
        log = deps.log.bind(agent_id=req.agent_id, tenant_id=req.tenant_id or "")

        # ---- STEP 1: classify (or honor the caller's hint) -----------
        complexity = req.hint_complexity or deps.classifier.classify(req)
        forced = req.hint_complexity is not None
        model = deps.model_for(complexity)

        # ---- STEP 2: optional context retrieval ----------------------
        context_chunks = 0
        enriched_prompt = req.prompt
        if req.context_query:
            chunks = await deps.context.retrieve(
                req.context_query,
                tenant_id=req.tenant_id,
            )
            if chunks:
                context_chunks = len(chunks)
                context_text = "\n\n".join(f"[{c.source}] {c.content}" for c in chunks)
                enriched_prompt = f"Context:\n{context_text}\n\n---\n\n{req.prompt}"

        # ---- STEP 3: retry loop ---------------------------------------
        attempt = 0
        start = deps.clock.now()
        last_error: Exception | None = None
        result = None

        while True:
            attempt += 1
            try:
                result = await deps.provider.complete(
                    model=model,
                    prompt=enriched_prompt,
                    response_model_name=req.response_model_name,
                    tenant_id=req.tenant_id,
                )
                break  # success
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                decision = deps.retry.should_retry(attempt, exc)
                if isinstance(decision, Stop):
                    break
                if isinstance(decision, Sleep):
                    log.warning(
                        "llm.retry",
                        attempt=attempt,
                        sleep_seconds=decision.seconds,
                        error=str(exc),
                    )
                    await deps.clock.sleep(decision.seconds)
                    continue
                # Unknown decision type → treat as stop.
                break

        elapsed_ms = (deps.clock.now() - start) * 1000.0

        # ---- STEP 4: fitness recording (ALWAYS, success or failure) --
        # Wrapped defensively so a bug in the fitness adapter can NEVER
        # crash an agent call.
        fitness_run_id: str | None = None
        try:
            fitness_run_id = await deps.fitness.record_run(
                agent_id=req.agent_id,
                tenant_id=req.tenant_id,
                model_used=model,
                latency_ms=elapsed_ms,
                tokens=result.tokens.total_tokens if result else 0,
                cost_usd=0.0,
                success=result is not None,
                forced=forced,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.fitness.record_failed", error=str(exc))

        # ---- STEP 5: either return success, fall back, or raise ------
        if result is not None:
            log.info(
                "llm.call.success",
                model=model.value,
                provider=result.provider_used.value,
                attempts=attempt,
                latency_ms=elapsed_ms,
            )
            return LLMResponse(
                parsed=result.parsed,
                model_used=model,
                provider_used=result.provider_used,
                complexity=complexity,
                tokens=result.tokens,
                latency_ms=elapsed_ms,
                attempts=attempt,
                context_chunks=context_chunks,
                used_fallback=False,
                fitness_run_id=fitness_run_id,
            )

        if req.fallback is not None:
            log.warning(
                "llm.call.fallback",
                attempts=attempt,
                error=str(last_error) if last_error else "unknown",
            )
            return LLMResponse(
                parsed=req.fallback,
                model_used=model,
                provider_used=ProviderName.FAKE,  # noqa: F821 — late import
                complexity=complexity,
                tokens=TokenUsage(),
                latency_ms=elapsed_ms,
                attempts=attempt,
                context_chunks=context_chunks,
                used_fallback=True,
                fitness_run_id=fitness_run_id,
            )

        log.error(
            "llm.call.unavailable",
            attempts=attempt,
            error=str(last_error) if last_error else "unknown",
        )
        raise LLMUnavailable(
            f"LLM call failed after {attempt} attempts: "
            f"{last_error if last_error else 'unknown error'}"
        )


# Late import to keep the core's import graph clean.
from shieldops.utils.llm_core.types import ProviderName  # noqa: E402
