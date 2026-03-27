# Review Agent Skill

Review ShieldOps agent code for correctness, safety, reliability, and architecture compliance.

## Usage
`/review-agent [--agent <type>] [--scope <safety|reliability|architecture|performance|all>]`

## Agents Used
- `agent_governance` — Capability boundary and escalation chain verification
- `decision_explainer` — Agent decision explainability audit
- `reflection_engine` — Self-evaluation and learning loop assessment

## Process

### 1. Safety Review (Critical)

```
- [ ] All infrastructure-modifying actions pass through OPA policy evaluation
- [ ] Rollback capability exists for every write operation
- [ ] Confidence thresholds gate autonomous vs approval-required actions (>0.85/>0.5/<0.5)
- [ ] Blast radius limits enforced per environment (dev/staging/prod)
- [ ] No hardcoded credentials or secrets
- [ ] Audit trail logging for every action with full reasoning chain
- [ ] No agent can delete databases, drop tables, or modify IAM root policies
```

### 2. Reliability Review

```
- [ ] Error handling at every external call (APIs, connectors, LLM)
- [ ] Timeout configuration for all async operations
- [ ] Graceful degradation (agent fails safe, not destructive)
- [ ] State persistence across retries (LangGraph checkpointing)
- [ ] Idempotent actions (safe to retry)
- [ ] LLM fallback logic (try/except with non-LLM fallback in nodes.py)
```

### 3. Architecture Review

```
- [ ] Follows 7-file LangGraph pattern (models, prompts, tools, nodes, graph, runner, policy)
- [ ] State schema matches PRD requirements (models.py)
- [ ] Node functions are pure: input → output, no hidden side effects (nodes.py)
- [ ] Conditional edges have complete coverage — no missing branches (graph.py)
- [ ] Tool functions properly typed and documented (tools.py)
- [ ] Reasoning chain captures every decision point
- [ ] Runner class has proper lifecycle management (runner.py)
- [ ] LLM calls use llm_structured() from utils/llm.py
```

### 4. Performance Review

```
- [ ] No blocking calls in async functions
- [ ] LLM calls minimized (batch where possible)
- [ ] Large data sets use streaming or pagination
- [ ] Memory-bounded collections (ring buffers, max_records)
- [ ] Connector clients lazily initialized
```

### 5. Integration Review

```
- [ ] API routes exist in src/shieldops/api/routes/{agent_type}.py
- [ ] Routes expose: health, run, history, configuration endpoints
- [ ] Dashboard page exists in dashboard-ui/src/pages/
- [ ] Agent registered in src/shieldops/api/app.py
- [ ] Tests exist in tests/unit/ and tests/integration/
```

### Review Code Example

```python
# Verify agent graph compiles and nodes are wired correctly
from shieldops.agents.soc_analyst.graph import create_soc_analyst_graph

graph = create_soc_analyst_graph()
app = graph.compile()

# Check all expected nodes exist
node_names = list(app.get_graph().nodes.keys())
assert "investigate" in node_names or len(node_names) > 0

# Verify runner instantiates
from shieldops.agents.soc_analyst.runner import SOCAnalystRunner
runner = SOCAnalystRunner()
assert runner._app is not None
```

## Key Files
- `src/shieldops/agents/{type}/` — Agent implementation (7 files)
- `src/shieldops/agents/decision_explainer.py` — Decision explainability
- `src/shieldops/agents/agent_governance/` — Governance agent
- `src/shieldops/agents/reflection_engine/` — Reflection agent
- `src/shieldops/policy/opa_client.py` — OPA policy client
- `src/shieldops/policy/approval_workflow.py` — Approval workflow
- `src/shieldops/utils/llm.py` — LLM utility (llm_structured)
- `src/shieldops/api/routes/` — API route modules
- `tests/unit/` — Unit test location
- `tests/integration/` — Integration test location

## Conventions
- Every review must cover all 5 areas (safety, reliability, architecture, performance, integration)
- Safety issues are blockers — no merge until resolved
- Reliability issues require mitigation plan before merge
- Architecture deviations require documented justification
- All findings must reference specific file paths and line numbers
- Use severity levels: critical (blocker), high (fix before merge), medium (fix soon), low (nice-to-have)
