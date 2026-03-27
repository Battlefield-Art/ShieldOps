# agents/ — LangGraph Agent Orchestration

151 autonomous security agents built on LangGraph StateGraph.

## Agent Architecture

Every agent follows this exact 7-file structure:
```
agents/{name}/
├── __init__.py    # Package init, exports create_{name}_graph
├── models.py      # 3 StrEnums + domain models + {Name}State
├── prompts.py     # LLM prompt templates + structured output schemas
├── tools.py       # {Name}Toolkit class with business logic
├── nodes.py       # Async node functions (state, toolkit) → dict
├── graph.py       # build_graph(toolkit) + create_{name}_graph() factory
├── runner.py      # {Name}Runner entry point class
└── policy.py      # (optional) OPA policy integration
```

## Creating a New Agent

### models.py
```python
class Stage(StrEnum):       # 6+ stages matching the workflow
class Severity(StrEnum):    # Domain-specific classification
class Action(StrEnum):      # Actions the agent can take

class DomainModel(BaseModel):  # 3-5 domain models
class {Name}State(BaseModel):  # Full graph state
    request_id: str = ""
    tenant_id: str = ""
    stage: Stage = Stage.FIRST
    # ... pipeline fields as list[dict[str, Any]]
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""            # ALWAYS str = "", never None
```

### nodes.py
```python
async def node_name(state: dict[str, Any], toolkit: Toolkit) -> dict[str, Any]:
    # 1. Extract from state
    # 2. Call toolkit method
    # 3. Try LLM enhancement with llm_structured + try/except
    # 4. Return state updates as dict
```

### graph.py
```python
def build_graph(toolkit: Toolkit) -> StateGraph:
    graph = StateGraph({Name}State)
    graph.add_node("step1", _step1)
    graph.add_node("step2", _step2)
    graph.set_entry_point("step1")
    graph.add_edge("step1", "step2")
    # Use add_conditional_edges for routing decisions
    graph.add_edge("stepN", END)
    return graph

def create_{name}_graph(**clients) -> StateGraph:  # Factory
```

## Key Infrastructure Agents
- `supervisor/` — Dispatches events to appropriate agents
- `agent_memory_store/` — Persistent episodic memory for all agents
- `reflection_engine/` — Self-evaluation and learning loops
- `cross_vendor_correlator/` — OCSF normalization across 8 vendors
- `situation_manager/` — Outcome-centric situation queue

## LLM Integration
- Always use `from shieldops.utils.llm import llm_structured`
- Always wrap in try/except with fallback logic
- LLM Router: Haiku (simple), Sonnet (moderate), Opus (complex)
- Temperature: 0.1 (deterministic reasoning)

## Agent Registry
- `registry.py` — Fleet registration, status tracking, heartbeat
- All agents auto-register on startup via `api/app.py`
- Status: idle, running, disabled
