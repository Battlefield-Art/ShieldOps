# Developer Guide — Build Your First ShieldOps Agent

> **Status:** Design (future) — Issue #232
> **See also:** [agent-spec.md](./agent-spec.md), [certification-process.md](./certification-process.md)

This is the outline for the public developer documentation site. It teaches a new
author to build, test, submit, and maintain a marketplace agent. Actual content will
be fleshed out during Phase 2 (MVP).

## Audience

- Python developers comfortable with async, type hints, and Pydantic.
- Security engineers who have built detections or automations before.
- No prior LangGraph experience required (we'll teach the minimum).

## Prerequisites

- Python 3.12+
- A ShieldOps developer account (free)
- `pipx` or a virtualenv manager of choice
- Docker (for running the local sandbox)

---

## Chapter 1 — "Build Your First ShieldOps Agent" (Tutorial)

A 45-minute tutorial that ships a trivial but real agent end-to-end.

### 1.1 What we're building
A `login-anomaly-flagger` agent that:
- Reads recent Okta login events from Splunk.
- Flags logins from impossible-travel patterns.
- Creates a PagerDuty incident when confidence > 0.85.

### 1.2 Concepts in 5 minutes
- LangGraph in one diagram: state, nodes, edges, routing.
- `define_agent()`: the ShieldOps wrapper that handles boilerplate.
- OPA gates: every action passes through policy.
- Fitness tracker: every run is scored.

### 1.3 Install the CLI
```bash
pipx install shieldops-cli
shieldops login
```

### 1.4 Scaffold the agent
```bash
shieldops agent init login-anomaly-flagger
cd login-anomaly-flagger
```
Walk through the generated layout (mirrors `agent-spec.md` §4).

### 1.5 Define the state and models
Write `models.py` with `LoginEvent`, `AnomalyAnalysis`, `FlaggerState` Pydantic
models.

### 1.6 Write the nodes
Three nodes: `fetch_events` → `detect_anomalies` → `create_incident`.
Show the minimal LangGraph state machine.

### 1.7 Wire it with `define_agent()`
```python
from shieldops.agents.framework import define_agent
agent = define_agent(
    name="login-anomaly-flagger",
    state=FlaggerState,
    nodes=[fetch_events, detect_anomalies, create_incident],
    edges=[...],
)
```

### 1.8 Fill in the manifest
Copy the example from [agent-spec.md](./agent-spec.md) and adapt.

### 1.9 Run it locally
```bash
shieldops agent run --input examples/sample.json
```
Show the trace output, OPA decision, fitness score.

### 1.10 Submit it
```bash
shieldops agent validate
shieldops agent publish
```
Explain what happens server-side (cert pipeline kicks off).

### 1.11 Celebrate
Agent is live in the Community tier. Share the URL with friends.

---

## Chapter 2 — Local Development Setup

### 2.1 Supported OSes
macOS (Apple Silicon + Intel), Linux (Debian, Ubuntu, RHEL), Windows via WSL2.

### 2.2 Installing the CLI
- `pipx install shieldops-cli` (recommended)
- Homebrew tap (future)
- Docker-based runner for CI environments

### 2.3 Authenticating
- `shieldops login` → OAuth device flow.
- API tokens for CI.
- Switching between orgs.

### 2.4 Project layout conventions
Repeat the structure from `agent-spec.md` §4, with rationale for each file.

### 2.5 Editor setup
- VS Code extension (future): syntax highlighting for `agent.yaml`, manifest
  validation, inline OPA linting.
- Type stubs for the ShieldOps SDK.

### 2.6 Running the local sandbox
- `shieldops sandbox up` spins up a minimal ShieldOps tenant in Docker.
- Includes fake Splunk, PagerDuty, and Stripe connectors with scripted fixtures.
- Reset with `shieldops sandbox reset`.

### 2.7 Environment variables
- `SHIELDOPS_API_KEY`
- `ANTHROPIC_API_KEY` (or provider of choice)
- `SHIELDOPS_SANDBOX_URL`

---

## Chapter 3 — Testing Locally with the SDK

### 3.1 Unit tests
- pytest conventions mirroring the core ShieldOps repo.
- Testing nodes in isolation with synthetic state.
- Mocking connector calls via the SDK's `FakeConnector` fixtures.

### 3.2 Integration tests
- Running the full graph against the sandbox.
- Snapshot testing for outputs.
- Seed fixtures for common scenarios.

### 3.3 Fitness testing
- Using `shieldops agent fitness --runs 100` to measure baseline fitness.
- Interpreting the fitness breakdown (accuracy, safety, speed, learning, cost).
- Setting a fitness floor before publication.

### 3.4 Adversarial testing
- The ShieldOps prompt-injection corpus (public subset).
- Edge cases: empty inputs, malformed events, connector failures.
- Chaos testing: simulate connector timeouts, rate limits, partial data.

### 3.5 Coverage
- `pytest --cov` with `coverage_threshold` matching the manifest.
- Interpreting the coverage report.

---

## Chapter 4 — Submitting Your First Agent

### 4.1 Pre-submission checklist
- [ ] Manifest complete and validated
- [ ] All examples pass locally
- [ ] Coverage meets threshold
- [ ] README explains what/when/how
- [ ] License chosen (SPDX)
- [ ] Support contact live
- [ ] Icon added

### 4.2 Choosing a certification tier
Decision tree: free hobby project → Community. Commercial product with support
SLA → Verified. Partner with contract → Premier.

### 4.3 Publishing
- `shieldops agent publish` walkthrough.
- What you'll see in the author dashboard.
- Reading automated check results.
- Fixing common rejections (top 10 list).

### 4.4 The review timeline
- Community: minutes.
- Verified: 3-10 business days.
- What reviewers look for (pointer to [certification-process.md](./certification-process.md)).

### 4.5 Getting help
- Developer Slack workspace.
- Office hours with the ShieldOps platform team.
- Escalation path.

---

## Chapter 5 — Best Practices

### 5.1 Idempotency
- Why it matters (retries, replays, sandbox evaluation).
- Patterns: use idempotency keys, upsert semantics, check-before-write.
- Anti-patterns: global counters, timestamp-based IDs, stateful in-memory caches.

### 5.2 Error handling
- Fail closed, not open — if OPA denies, do not proceed.
- Structured errors: use ShieldOps error taxonomy.
- Retries with exponential backoff via the SDK's built-in helpers.
- Never swallow exceptions silently.

### 5.3 Observability
- structlog conventions.
- Adding custom spans via OpenTelemetry.
- What gets auto-traced: node entry/exit, tool calls, LLM calls, connector calls.
- Debugging a failed run via LangSmith traces.

### 5.4 LLM usage
- Choose the cheapest model that works (Haiku → Sonnet → Opus).
- Use `llm_structured()` for all structured outputs.
- Budget tokens explicitly in the manifest.
- Cache aggressively for idempotent prompts.

### 5.5 Security hygiene
- Never log secrets or raw PII.
- Validate all external inputs with Pydantic.
- Assume every input is adversarial (prompt injection is real).
- Use OPA for authorization, not ad-hoc Python checks.
- Sanitize data before passing to the LLM.

### 5.6 Performance
- Declare realistic resource budgets.
- Profile with `shieldops agent profile`.
- Avoid unbounded loops; use `max_iterations` on LangGraph nodes.
- Parallelize connector calls where safe (asyncio.gather).

### 5.7 User experience
- Write clear incident titles and descriptions.
- Include evidence bundles (links, screenshots, query results).
- Respect human approval gates — don't auto-execute high-blast-radius actions.

---

## Chapter 6 — Versioning & Backward Compatibility

### 6.1 SemVer in practice
- Patch: internal fix, prompt tweak. Safe to auto-push.
- Minor: new capability. Must be backward compatible with existing inputs and
  outputs.
- Major: breaking change. Requires customer opt-in, 90-day deprecation of prior
  major version.

### 6.2 Input schema evolution
- Adding optional fields: minor.
- Adding required fields: major.
- Removing fields: major + deprecation notice.
- Renaming fields: don't. Add new, deprecate old.

### 6.3 Output schema evolution
- Downstream consumers rely on output shapes. Treat them as public API.
- Same rules as inputs.

### 6.4 Prompt evolution
- Use the `prompt_evolution.py` subsystem for A/B testing prompt changes without
  bumping the version.
- Champion/challenger workflow explained.

### 6.5 Connector evolution
- Adding a new required connector: major bump.
- Adding an optional connector: minor.
- Removing a connector: major + deprecation.

### 6.6 Deprecation communication
- Use the `deprecated_in` field in the manifest.
- 90-day minimum notice to installed customers.
- In-product banners, email notifications, changelog entries.
- Migration guide is mandatory for major bumps.

### 6.7 Hotfixes
- How to ship a critical security fix in < 24 hours.
- Emergency publication flow (skips normal SLA, goes through on-call reviewer).
- Post-fix communication requirements.

---

## Appendix A — SDK Reference
Pointer to the Python SDK API docs (auto-generated from source).

## Appendix B — CLI Reference
`shieldops agent` command reference.

## Appendix C — Example Gallery
Links to open-source reference agents in the ShieldOps `examples/marketplace/`
directory (to be created).

## Appendix D — FAQ for Authors
- "Can I use non-Anthropic LLMs?" — Yes, via the LLM router.
- "Can I bundle my own OPA policies?" — Yes, under `policies/`.
- "Can I keep my source private?" — Yes for Verified+, no for Community.
- "How do I get promoted from Community to Verified?" — Submit a Verified upgrade
  request from the author dashboard.
- "What happens if ShieldOps rewrites the framework?" — Semver guarantees on
  `define_agent()`; breaking changes get 6 months notice.
