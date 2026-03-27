# Context Hub Skill

Retrieve real documentation and context for ShieldOps agents before they act — inspired by andrewyng/context-hub.

## Usage
`/context-hub <action> [options]`

Actions: `search`, `get`, `annotate`, `feedback`, `stats`

## Agents Used
- `knowledge` — Knowledge base management and retrieval
- `agent_memory_store` — Persistent episodic memory across agents
- `reflection_engine` — Self-evaluation and learning from past actions

## Process

### Search for context
```
/context-hub search "OOMKilled pod remediation"
/context-hub search "HIPAA compliance requirements"
/context-hub search "k8s rollback procedure"
```

Search the ShieldOps knowledge base for runbooks, historical incidents, compliance docs, and playbooks relevant to the query.

### Get specific context
```
/context-hub get runbook-oomkilled
/context-hub get compliance-hipaa-phi
```

Retrieve a specific context entry by ID.

### Annotate context (agent learning)
```
/context-hub annotate runbook-oomkilled "Also check for Redis connection pool leaks"
```

Add a note to a context entry that will be included in future retrievals.

### Provide feedback
```
/context-hub feedback runbook-oomkilled up "This runbook resolved the issue quickly"
/context-hub feedback runbook-oomkilled down "Missing step for multi-container pods"
```

### View stats
```
/context-hub stats
```

Show hub statistics: total entries, by type, annotations, feedback.

## Integration with Agents

The context hub is automatically used by agent nodes that call `fetch_context_for_incident()`, `fetch_context_for_compliance()`, or `fetch_context_for_remediation()` from `shieldops.utils.agent_context_mixin`.

```python
from shieldops.utils.context_hub import ContextHub

hub = ContextHub()
results = hub.search("OOMKilled pod remediation", max_results=5)
entry = hub.get("runbook-oomkilled")
hub.annotate("runbook-oomkilled", "Also check Redis connection pool leaks")
hub.feedback("runbook-oomkilled", "up", "Resolved issue quickly")
stats = hub.stats()
```

Context entries include:
- **Runbooks** — step-by-step procedures for common incidents
- **Incident History** — what worked/failed for similar past incidents
- **Infrastructure Docs** — service configs, dependencies, SLOs
- **Compliance Requirements** — framework-specific controls (HIPAA, SOC 2, PCI-DSS)
- **Playbooks** — automated response procedures

## Key Files
- `src/shieldops/utils/context_hub.py` — Context Hub implementation
- `src/shieldops/utils/agent_context_mixin.py` — Agent integration mixin
- `src/shieldops/agents/knowledge/` — Knowledge management agent
- `src/shieldops/agents/agent_memory_store/` — Episodic memory agent
- `src/shieldops/agents/reflection_engine/` — Reflection and learning agent
- `src/shieldops/knowledge/article_manager.py` — Knowledge base manager
- `src/shieldops/knowledge/knowledge_graph.py` — Knowledge graph

## Conventions
- Agents should fetch real documentation before acting, not rely on training data
- Context entries must have freshness scores; stale entries flagged after 90 days
- Feedback (up/down) is tracked and used to rank search results
- Annotations are immutable and timestamped for audit trail
- All context retrievals logged for usage analytics
