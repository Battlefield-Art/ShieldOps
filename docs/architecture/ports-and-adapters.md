# Ports & Adapters — the platform testing idiom

**Status:** Active — the standard pattern for new deep modules across
ShieldOps as of RFCs #241–#248 (April 2026).

**TL;DR:** Define a pure-ish core class + `Protocol` ports for every
cross-boundary dependency. Wire real adapters at `app.py` lifespan.
Wire in-memory adapters in tests. The same core class runs identically
in both environments, so tests construct the real code path and assert
on outputs instead of mocking collaborators.

## Why this pattern

ShieldOps has a recurring problem: subsystems get built as collections
of 3–5 small files that "collaborate via module-level globals" (e.g.
`set_toolkit()` in 397 `nodes.py` files, `BillingEnforcementMiddleware._enforcement`
as a class attribute poked by tests, `set_global_tracker()` for the
fitness tracker). The pattern has three predictable failure modes:

1. **Tests mock internal collaborators**, so the assertions don't lock
   the contract — they lock the mocks. Refactoring the implementation
   breaks tests without the behavior actually changing.
2. **Multi-tenant is structurally impossible** because the "global"
   is per-process.
3. **"Built but unwired" subsystems accumulate** — `tenant_rate_limiter.py`,
   `DeepAgentMixin`, `llm_router.py`, both middleware stack builders.
   Each was built in isolation, none was wired into the production path,
   and the test suite never caught it because the tests ran the
   "collaborator" in isolation.

The ports & adapters pattern fixes all three by making the cross-boundary
dependencies explicit at the type level and cheap to swap at construction.

## The shape

A deep module implemented with this pattern has 3 parts:

```
{subsystem}/
├── core/              ── pure logic, zero I/O imports
│   ├── types.py       ── plain dataclasses + Pydantic models
│   ├── ports.py       ── Protocol definitions (one per cross-boundary dep)
│   ├── deps.py        ── frozen dataclass bundling the Protocols into one handle
│   └── {core}.py      ── the deep module itself — sequential logic over the ports
├── adapters/          ── real SDKs + test doubles
│   ├── production/    ── PR-2 lands these (Redis, SqlAlchemy, Anthropic, …)
│   └── in_memory_*.py ── PR-1 ships these (one test double per port)
├── composition.py     ── set/get + use_test_X context manager + build_in_memory_X factory
└── tests/
    └── test_{core}.py ── contract tests using ONLY in-memory adapters
```

## The 8 landed exemplars

Every RFC in the #241–#248 sweep follows this pattern. Use them as
reference when writing a new one.

| # | Package | Core class | Ports | Contract test |
|---|---|---|---|---|
| #242 | `shieldops.api.ws.core` | `Hub` | 6 | `test_publish_disconnect_reconnect_with_since_id` |
| #243 | `shieldops.api.policy` | `RequestPolicyEngine` | 5 | `test_burst_then_refill_then_allow` |
| #244 | `shieldops.licensing` | `LicenseManager` | 0 (self-contained) | `test_exception_during_run_releases_the_slot` |
| #245 | `shieldops.db` | `fetch` + `audit` (stateless) | 0 (takes session) | `test_get_returns_typed_instance` |
| #246 | `shieldops.utils.evolution` | `EvolutionStore` | 0 (self-contained) | `test_record_run_exception_does_not_crash_caller` |
| #247 | `shieldops.agents.runtime` | `AgentRuntime` | 9 | `test_one_run_goes_through_every_lifecycle_step` |
| #248 | `shieldops.utils.llm_core` | `LLMOrchestrator` | 7 | `test_high_complexity_routes_to_opus` |
| #241 | `shieldops.config` | *PR-1 pending* | — | — |

## How to write a new one (30-minute recipe)

Say you're adding a new subsystem `foo_bar`. Follow this checklist:

### 1. Define the core types

Plain dataclasses and Pydantic models. No behavior. No I/O imports.

```python
# shieldops/foo_bar/types.py
from dataclasses import dataclass

@dataclass(frozen=True)
class FooRequest:
    id: str
    payload: dict[str, Any]

@dataclass(frozen=True)
class FooResult:
    id: str
    status: str
```

### 2. Define the ports

One `Protocol` per cross-boundary dependency. **Zero imports from real
SDKs.** Mark them `@runtime_checkable` so `isinstance()` works for tests
that want to assert a given object satisfies the port.

```python
# shieldops/foo_bar/ports.py
from typing import Protocol, runtime_checkable

@runtime_checkable
class FooStore(Protocol):
    async def save(self, req: FooRequest) -> str: ...
    async def get(self, id: str) -> FooResult | None: ...

@runtime_checkable
class Clock(Protocol):
    def now(self) -> float: ...
```

### 3. Bundle the ports into a `FooDeps` frozen dataclass

Single constructor argument for everything the core depends on. Adding
a port is a deliberate schema change, not a silent subsystem import.

```python
# shieldops/foo_bar/deps.py
from dataclasses import dataclass
from shieldops.foo_bar.ports import Clock, FooStore

@dataclass(frozen=True)
class FooDeps:
    store: FooStore
    clock: Clock
```

### 4. Write the core class

Pure sequential logic. Every side effect goes through a port. The body
reads as a recipe.

```python
# shieldops/foo_bar/foo_service.py
from shieldops.foo_bar.deps import FooDeps

class FooService:
    def __init__(self, deps: FooDeps) -> None:
        self._deps = deps

    async def process(self, req: FooRequest) -> FooResult:
        # 1. persist
        id = await self._deps.store.save(req)
        # 2. timestamp
        ts = self._deps.clock.now()
        # 3. return
        return FooResult(id=id, status=f"ok@{ts}")
```

### 5. Write the in-memory adapters

One per port. Production adapters come later.

```python
# shieldops/foo_bar/adapters/in_memory_store.py
class InMemoryFooStore:
    def __init__(self):
        self.saved: dict[str, FooRequest] = {}

    async def save(self, req: FooRequest) -> str:
        self.saved[req.id] = req
        return req.id

    async def get(self, id: str) -> FooResult | None:
        ...
```

```python
# shieldops/foo_bar/adapters/manual_clock.py
class ManualClock:
    def __init__(self, start: float = 0.0):
        self._now = start
    def now(self) -> float:
        return self._now
    def advance(self, seconds: float) -> None:
        self._now += seconds
```

### 6. Write the composition root

Same setter/getter pattern everyone uses. `use_test_foo_service`
context manager restores on exception.

```python
# shieldops/foo_bar/composition.py
import contextlib
from collections.abc import Iterator

_service: FooService | None = None

def set_foo_service(svc: FooService | None) -> None:
    global _service
    _service = svc

def get_foo_service() -> FooService:
    if _service is None:
        raise RuntimeError("No FooService installed. Call set_foo_service(svc).")
    return _service

def build_in_memory_foo_service() -> FooService:
    return FooService(FooDeps(
        store=InMemoryFooStore(),
        clock=ManualClock(),
    ))

@contextlib.contextmanager
def use_test_foo_service(svc: FooService | None = None) -> Iterator[FooService]:
    previous = _service
    fresh = svc or build_in_memory_foo_service()
    try:
        set_foo_service(fresh)
        yield fresh
    finally:
        set_foo_service(previous)
```

### 7. Write the contract tests

Construct the core with in-memory adapters, drive the behavior, assert
on outputs. **Zero mocks.**

```python
# tests/unit/foo_bar/test_foo_service.py
import pytest
from shieldops.foo_bar import FooDeps, FooRequest, FooService
from shieldops.foo_bar.adapters import InMemoryFooStore, ManualClock

class TestFooService:
    @pytest.mark.asyncio
    async def test_process_persists_and_timestamps(self) -> None:
        store = InMemoryFooStore()
        clock = ManualClock(start=1000.0)
        svc = FooService(FooDeps(store=store, clock=clock))

        result = await svc.process(FooRequest(id="a", payload={}))

        assert result.status == "ok@1000.0"
        assert "a" in store.saved
```

## Rules

These rules are non-negotiable and enforced by code review (and by
ruff rule `SHOP-003` in the near future):

1. **The core has zero imports from real SDKs.** If the core needs
   `redis`, `httpx`, `fastapi`, `starlette`, `langchain_anthropic`,
   `boto3`, `google.cloud`, `openai`, `structlog`, or `opentelemetry`
   — it's not a core, it's an adapter. Move it.

2. **Every cross-boundary dependency is a Protocol.** If you find
   yourself importing a concrete class into the core, stop and write
   the port first.

3. **Tests use in-memory adapters, not mocks.** `Mock(spec=...)` is
   a smell. `unittest.mock.patch` on a module-level global is a
   stronger smell — replace it with `use_test_X()`.

4. **Side effects inside the core are wrapped in `contextlib.suppress`
   if they're observability-only.** A bug in a sister RFC's adapter
   must never crash the calling code. See `EvolutionStore.record_run`
   (#246) and `AgentRuntime._execute` (#247) for the pattern.

5. **The composition root has exactly one setter and one getter.**
   `set_X(x)` and `get_X()`. No module-level global access elsewhere.
   `use_test_X()` is the test seam.

6. **Contract tests run in single-digit milliseconds.** If a test
   takes longer than 10ms, it's either doing real I/O (check for a
   missed port) or running against a real fixture (convert it to
   in-memory).

## Migration from the old "module-level globals" pattern

If you're looking at code that uses `set_global_X()` / `_instance` /
`app.state.repository`, you're looking at pre-RFC #242 code. The
mechanical migration is:

1. **Extract the concrete dependency into a Protocol.** Put it in
   `ports.py`.
2. **Replace the global with constructor injection.** The module-level
   `_instance = None; set_global_X(x); get_global_X()` pattern becomes
   a `FooDeps(...)` constructor argument.
3. **Convert the "global setter" calls in tests** to
   `use_test_X()` context managers.
4. **Write one contract test** that exercises the real core with
   in-memory adapters. That test is the regression gate.
5. **Delete the old globals.** With the contract test in place, the
   delete is reversible.

## Related

- **RFC #241** (Settings): pending PR-1. Will use a different shape
  (flat `BaseSettings` + parity test) because pydantic-settings doesn't
  fit the pure-core pattern — but the test seam (`use_test_settings`)
  still follows this idiom.
- **`docs/architecture/overview.md`**: high-level platform architecture.
- **`memory/rfc_implementation_2026_04_07.md`**: per-RFC PR-1 landing
  log including commit SHAs and test counts.

## Landed commit log

```
b1609975 feat(agents): land AgentRuntime + 9 ports + full-lifecycle contract test (RFC #247 PR-1)
6ad16a49 feat(llm): land LLMOrchestrator + 7 ports + classify-route-record contract test (RFC #248 PR-1)
ae571462 feat(policy): land RequestPolicyEngine + 5 ports + burst-refill contract test (RFC #243 PR-1)
9a57ccca feat(db): land fetch helpers + unified audit path (RFC #245 PR-1)
37bfbb2a feat(evolution): land EvolutionStore + RunOutcome + cross-subsystem integration (RFC #246 PR-1)
62e23db5 feat(licensing): land LicenseManager + @enforced + use_test_license (RFC #244 PR-1)
6c044060 feat(ws): land Hub core + in-memory adapters + reconnect-replay contract test (RFC #242 PR-1)
```

**110 contract tests total** across the 7 landed PR-1s. All green. All
running in single-digit milliseconds each. Zero mocks. The test idiom
is proven; the next session can apply it to the PR-2 migrations with
confidence.
