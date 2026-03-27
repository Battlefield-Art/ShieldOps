# System Design Skill

Design new ShieldOps components, APIs, agent workflows, or engine modules.

## Usage
`/design-system <component> [--depth <shallow|deep>] [--type <agent|api|engine|integration>]`

## Agents Used
- `swarm_coordinator` — Multi-agent coordination and swarm design
- `consensus_engine` — Consensus protocols for multi-agent decisions
- `knowledge_mesh` — Knowledge sharing across agent networks
- `token_optimizer` — LLM token usage optimization
- `routing_optimizer` — Request routing and load distribution

## Process

### 1. Requirements Gathering
- Read relevant PRDs from `docs/prd/`
- Identify stakeholders and constraints
- Map dependencies on existing components
- Review existing patterns in codebase

### 2. Architecture Design
- Define component boundaries and interfaces
- Choose patterns (event-driven, request-response, CQRS)
- Design data models (Pydantic schemas)
- Plan LangGraph workflow (if agent-related)

### 3. API Design (if applicable)
- Define REST endpoints with OpenAPI spec
- Design request/response schemas
- Plan authentication and authorization
- Define rate limits and quotas

### 4. Safety Analysis
- Identify failure modes and blast radius
- Design circuit breakers and fallbacks
- Plan OPA policies needed
- Define rollback procedures

### 5. Impact Assessment
Evaluate design impact across platform domains:

```python
# Check service dependency impact
from shieldops.topology.service_dependency_risk_engine import ServiceDependencyRiskEngine

engine = ServiceDependencyRiskEngine()
engine.record_item(
    service="new-component", dependency="database-primary",
    dependency_type="hard", health_score=0.95, criticality="high",
)
report = engine.generate_report()
```

**Key assessment areas:**
- **Topology**: Service dependencies, cascade failure risk, API contract compatibility
- **SLA**: SLO burn rate impact, error budget consumption, availability targets
- **Security**: Attack surface changes, policy coverage, secrets management
- **Compliance**: Regulatory impact, data handling, audit requirements
- **Cost**: Resource costs, LLM token costs, infrastructure spend
- **Operations**: Runbook needs, on-call impact, monitoring requirements

### 6. Design Document
Output a design doc with:
- Component diagram
- Data flow diagram
- API specification
- State machine (for agents)
- OPA policy requirements
- Test strategy
- Rollout plan

## Agent Design Template

```python
# New agent follows 7-file LangGraph pattern:
# src/shieldops/agents/{name}/
#   __init__.py, models.py, prompts.py, tools.py, nodes.py, graph.py, runner.py

from langgraph.graph import StateGraph
from shieldops.agents.{name}.models import {Name}State
from shieldops.agents.{name}.nodes import investigate, act, validate

def create_{name}_graph(**clients) -> StateGraph:
    graph = StateGraph({Name}State)
    graph.add_node("investigate", investigate)
    graph.add_node("act", act)
    graph.add_node("validate", validate)
    graph.add_edge("investigate", "act")
    graph.add_edge("act", "validate")
    graph.set_entry_point("investigate")
    graph.set_finish_point("validate")
    return graph
```

## Engine Design Template

```python
# New engine follows standard pattern:
# 3 StrEnum + 3 Pydantic models + Engine class

from enum import StrEnum
from pydantic import BaseModel

class {Name}Engine:
    def __init__(self, max_records: int = 10000):
        self._records: list[dict] = []
        self._max_records = max_records

    def add_record(self, **kwargs) -> str: ...
    def process(self, key: str) -> dict: ...
    def generate_report(self) -> dict: ...
    def get_stats(self) -> dict: ...
    def clear_data(self) -> None: ...
```

## Key Files
- `docs/prd/` — Product requirement documents
- `docs/architecture/` — Architecture decision records
- `src/shieldops/agents/` — 179 agents (reference patterns)
- `src/shieldops/connectors/base.py` — Connector protocol (7 methods)
- `src/shieldops/api/` — FastAPI routes (749 endpoints)
- `src/shieldops/policy/opa_client.py` — OPA policy integration
- `src/shieldops/utils/llm.py` — LLM utility (llm_structured)
- `src/shieldops/utils/llm_router.py` — LLM router (Haiku/Sonnet/Opus)

## Conventions
- All new agents follow the 7-file LangGraph pattern
- All new engines follow the StrEnum + Pydantic + Engine class pattern
- Every write operation must have rollback capability
- OPA policies required for all infrastructure-modifying actions
- Pydantic v2 models for all data structures
- async/await for all I/O operations
- structlog for structured logging
- Type hints on all public functions
