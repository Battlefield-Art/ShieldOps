# src/shieldops — Core Package

This is the main Python package for ShieldOps. All business logic lives here.

## Package Architecture

```
shieldops/
├── agents/          # 150 LangGraph agents (see agents/CLAUDE.md)
├── api/             # FastAPI 749 routes + middleware (see api/CLAUDE.md)
├── security/        # 518 security engines (see security/CLAUDE.md)
├── observability/   # 232 OTel/telemetry engines (see observability/CLAUDE.md)
├── analytics/       # 255 analytics engines (see analytics/CLAUDE.md)
├── operations/      # 160 ops engines (see operations/CLAUDE.md)
├── compliance/      # 116 compliance engines (see compliance/CLAUDE.md)
├── connectors/      # 18 vendor connectors (see connectors/CLAUDE.md)
├── sdk/             # Agent Firewall SDK (see sdk/CLAUDE.md)
├── db/              # Database layer (see db/CLAUDE.md)
├── policy/          # OPA policy engine (see policy/CLAUDE.md)
├── utils/           # Shared utilities (see utils/CLAUDE.md)
├── orchestration/   # Supervisor + workflow engine
├── incidents/       # Incident lifecycle engines
├── billing/         # FinOps + cost engines
├── topology/        # Service mesh + dependency mapping
├── sla/             # SLO tracking + error budgets
├── knowledge/       # Knowledge base + onboarding
├── audit/           # Audit trail + evidence
├── changes/         # GitOps + deployment engines
├── config/          # Feature flags + drift analysis
├── integrations/    # External tool integrations
├── events/          # Event bus + messaging
├── cache/           # Redis caching layer
├── messaging/       # Notification channels
└── cli/             # CLI commands
```

## Core Patterns

### Engine Module Pattern
All engine files (security/, analytics/, operations/, etc.) follow this exact pattern:
```python
# 3 StrEnum classes
# 3 Pydantic models: Record, Analysis, Report
# Engine class with:
#   add_record(**kwargs) / record_item(**kwargs)
#   process(key) → Analysis
#   generate_report() → Report
#   get_stats() → dict
#   clear_data() → None
#   3 domain-specific methods
# Ring-buffer storage with max_records eviction
```

### Agent Pattern
All agents in `agents/` follow the LangGraph StateGraph pattern — see `agents/CLAUDE.md`.

### Import Conventions
- `from __future__ import annotations` — always first
- `import structlog` — for structured logging (never `import logging`)
- `from pydantic import BaseModel, Field` — for all data models
- `from shieldops.utils.llm import llm_structured` — for LLM calls

### Code Standards
- Ruff line-length: 100
- Python 3.12+ with full type hints
- Pydantic v2 models (not v1)
- async/await for all I/O
- `add_record(**kwargs)` for: analytics, observability, security, knowledge, sla, billing, incidents, compliance
- `record_item(**kwargs)` for: changes, operations, topology
