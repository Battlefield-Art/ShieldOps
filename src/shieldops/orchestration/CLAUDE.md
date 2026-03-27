# orchestration/ — Multi-Agent Orchestration

Supervisor agent and workflow engine for multi-agent coordination.

## Architecture
- `supervisor.py` — SupervisorAgent: manages up to 10 concurrent agent runs
- `workflow_engine.py` — WorkflowEngine: step-by-step agent sequencing

## Workflow Templates
- `incident_response` — Multi-agent incident handling
- `security_scan` — Coordinated security scanning
- `proactive_check` — Scheduled proactive checks

## Communication Pattern
Agents communicate through:
1. Supervisor dispatch (supervisor calls agents)
2. Workflow step sequencing (engine coordinates chains)
3. Escalation policies (severity-based routing)
4. Structured state objects passed between nodes
